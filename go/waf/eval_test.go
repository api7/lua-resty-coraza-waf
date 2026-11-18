/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package waf

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const testDirectives = `Include @coraza.conf-recommended
SecRequestBodyAccess On
SecRequestBodyLimit 131073
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
SecArgumentsLimit 5
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900001,phase:1,pass,nolog,t:none,setvar:tx.detection_paranoia_level=1"
SecAction "id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=5"
SecRule REQUEST_HEADERS:X-Test "@streq deny" "id:10001,phase:1,deny,status:403,log,msg:'custom deny'"
Include @owasp_crs/*.conf
SecRuleEngine DetectionOnly`

type ruleSet = WAF

func newRuleSet(directives string) (*WAF, error) {
	w, _, err := New(directives)
	return w, err
}

func evaluate(w *WAF, req *Request, out []byte) (*Result, error) {
	return w.Eval(req, out)
}

func newTestRuleSet(t *testing.T) *ruleSet {
	t.Helper()
	rs, err := newRuleSet(testDirectives)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func baseRequest(uri string) *Request {
	return &Request{
		Method: "GET", URI: uri, Protocol: "HTTP/1.1",
		ClientIP: "10.1.2.3", ClientPort: 12345,
		ServerIP: "127.0.0.1", ServerPort: 9080, ServerName: "localhost",
		TxID: "abc",
		Headers: [][2]string{
			{"Host", "localhost"},
			{"User-Agent", "curl/8.0"},
			{"Accept", "*/*"},
		},
	}
}

func run(t *testing.T, rs *ruleSet, req *Request) (*Result, string, []map[string]any) {
	t.Helper()
	out := make([]byte, 16384)
	res, err := evaluate(rs, req, out)
	if err != nil {
		t.Fatal(err)
	}
	ids := string(out[:res.RuleIDsLen])
	var matches []map[string]any
	if res.MatchesLen > 0 {
		if err := json.Unmarshal(out[res.RuleIDsLen:res.RuleIDsLen+res.MatchesLen], &matches); err != nil {
			t.Fatal(err)
		}
	}
	return res, ids, matches
}

func TestCleanRequest(t *testing.T) {
	rs := newTestRuleSet(t)
	res, ids, _ := run(t, rs, baseRequest("/hello?a=1"))
	if res.Matched != 0 || ids != "" || res.MatchesLen != 0 {
		t.Fatalf("unexpected matches: %d %q", res.Matched, ids)
	}
}

func TestSQLiQuery(t *testing.T) {
	rs := newTestRuleSet(t)
	res, ids, matches := run(t, rs, baseRequest("/hello?id=1%27%20OR%20%271%27=%271"))
	if !strings.Contains(ids, "942100") || !strings.Contains(ids, "949110") {
		t.Fatalf("ids = %q", ids)
	}
	if res.AnomalyScore < 5 {
		t.Fatalf("anomaly score = %d", res.AnomalyScore)
	}
	if res.Status == Interrupted {
		t.Fatalf("DetectionOnly must not interrupt")
	}
	if res.WouldInterruptRuleID != 949110 {
		t.Fatalf("would interrupt rule = %d", res.WouldInterruptRuleID)
	}
	for _, m := range matches {
		if _, ok := m["data"]; ok {
			t.Fatalf("data must be omitted")
		}
		if m["id"].(float64) == 942100 && m["severity"] != "critical" {
			t.Fatalf("severity = %v", m["severity"])
		}
	}
}

func TestJSONBodyAndArgsLimit(t *testing.T) {
	rs := newTestRuleSet(t)
	req := baseRequest("/hello?a=1&b=2&c=3&d=4&e=5&f=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	res, ids, matches := run(t, rs, req)
	if !res.ArgsLimitReached {
		t.Fatalf("args limit not reported: %q %d", ids, len(matches))
	}

	req = baseRequest("/hello")
	req.Method = "POST"
	req.LogMatchedData = true
	req.Headers = append(req.Headers, [2]string{"Content-Type", "application/json"})
	req.Body = []byte(`{"q":"1' UNION SELECT password FROM users--"}`)
	res, ids, matches = run(t, rs, req)
	if res.ArgsLimitReached || !strings.Contains(ids, "942") {
		t.Fatalf("ids = %q limit = %v", ids, res.ArgsLimitReached)
	}
	if _, ok := matches[0]["data"]; !ok {
		t.Fatalf("data missing: %v", matches[0])
	}
}

func TestCustomDenyIsNotEnforced(t *testing.T) {
	rs := newTestRuleSet(t)
	req := baseRequest("/hello")
	req.Headers = append(req.Headers, [2]string{"X-Test", "deny"})
	res, ids, _ := run(t, rs, req)
	if ids != "10001" || res.Status == Interrupted {
		t.Fatalf("ids = %q status = %d", ids, res.Status)
	}
}

func TestMatchesTruncated(t *testing.T) {
	rs := newTestRuleSet(t)
	res, ids, matches := run(t, rs, baseRequest("/hello?id=1%27%20OR%20%271%27=%271"))
	out := make([]byte, 200)
	res2, err := evaluate(rs, baseRequest("/hello?id=1%27%20OR%20%271%27=%271"), out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out[res2.RuleIDsLen : res2.RuleIDsLen+res2.MatchesLen])
	if !strings.HasSuffix(s, `{"truncated":true}]`) {
		t.Fatalf("not truncated: %s (full ids %q, %d matches, %d)", s, ids, len(matches), res.Matched)
	}
}

func TestBuildError(t *testing.T) {
	if _, err := newRuleSet("SecRule ARGS \"@rx (\" \"id:1,phase:1,pass\""); err == nil {
		t.Fatal("expected an error")
	}
}

func TestArgsLimitCountsValues(t *testing.T) {
	rs := newTestRuleSet(t)
	// three names, six values: over the limit of 5
	res, _, _ := run(t, rs, baseRequest("/hello?a=1&a=2&a=3&b=1&b=2&evil=1"))
	if !res.ArgsLimitReached {
		t.Fatal("args limit not reported for repeated names")
	}
	res, _, _ = run(t, rs, baseRequest("/hello?a=1&a=2&b=1"))
	if res.ArgsLimitReached {
		t.Fatal("args limit reported under the limit")
	}
}

func TestArgsLimitBody(t *testing.T) {
	rs := newTestRuleSet(t)
	req := baseRequest("/hello")
	req.Method = "POST"
	req.Headers = append(req.Headers, [2]string{"Content-Type", "application/x-www-form-urlencoded"})
	req.Body = []byte("a=1&b=2&c=3&d=4&e=5&f=6")
	res, _, _ := run(t, rs, req)
	if !res.ArgsLimitReached {
		t.Fatal("args limit not reported for a body")
	}
}

func TestArgsLimitQuoted(t *testing.T) {
	rs, err := newRuleSet("SecArgumentsLimit \"2\"\nSecRuleEngine DetectionOnly")
	if err != nil {
		t.Fatal(err)
	}
	res, _, _ := run(t, rs, baseRequest("/hello?a=1&b=2&c=3"))
	if !res.ArgsLimitReached {
		t.Fatal("args limit not reported with a quoted limit")
	}
}

func TestInterruptionWithoutStatus(t *testing.T) {
	rs, err := newRuleSet(`SecRuleEngine On
SecRule ARGS:x "@streq 1" "id:1,phase:1,drop,log"`)
	if err != nil {
		t.Fatal(err)
	}
	res, _, _ := run(t, rs, baseRequest("/hello?x=1"))
	if res.Status != Interrupted || res.InterruptRuleID != 1 || res.WouldInterruptRuleID != 1 {
		t.Fatalf("status = %d rule = %d would = %d",
			res.Status, res.InterruptRuleID, res.WouldInterruptRuleID)
	}
}

func TestDetectionOnlyWouldInterrupt(t *testing.T) {
	rs, err := newRuleSet(`SecRuleEngine DetectionOnly
SecRule ARGS:x "@streq 1" "id:1,phase:1,deny,log"
SecRule ARGS:x "@streq 1" "id:2,phase:1,deny,log"`)
	if err != nil {
		t.Fatal(err)
	}
	res, ids, _ := run(t, rs, baseRequest("/hello?x=1"))
	if res.Status == Interrupted || res.InterruptRuleID != 0 || res.WouldInterruptRuleID != 1 {
		t.Fatalf("status = %d rule = %d would = %d",
			res.Status, res.InterruptRuleID, res.WouldInterruptRuleID)
	}
	if ids != "1,2" {
		t.Fatalf("ids = %q", ids)
	}

	res, _, _ = run(t, rs, baseRequest("/hello?x=2"))
	if res.WouldInterruptRuleID != 0 {
		t.Fatalf("would interrupt rule = %d", res.WouldInterruptRuleID)
	}
}

// GHSA-6gcq-wc29-5xf2: deeply nested JSON took time and memory quadratic in
// its depth before Coraza 3.8.1 (32 KiB: about a minute, 2.7 GB).
func TestDeepJSON(t *testing.T) {
	rs := newTestRuleSet(t)
	depth := 65536
	req := baseRequest("/hello")
	req.Method = "POST"
	req.Headers = append(req.Headers, [2]string{"Content-Type", "application/json"})
	req.Body = []byte(strings.Repeat("[", depth) + strings.Repeat("]", depth))
	start := time.Now()
	run(t, rs, req)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("nested JSON took %v", d)
	}
}

// GHSA-974q-67pr-5pc2: before libinjection-go 0.3.4 @detectSQLi took time
// quadratic in the length of a quote-heavy string literal (1 MiB: about 10s
// for each detectSQLi call).
func TestSQLiStringLiteral(t *testing.T) {
	rs, err := newRuleSet(`SecRequestBodyAccess On
SecRequestBodyLimit 2097152
SecRequestBodyInMemoryLimit 2097152
SecRule ARGS "@detectSQLi" "id:1,phase:2,pass,log"
SecRuleEngine DetectionOnly`)
	if err != nil {
		t.Fatal(err)
	}
	for name, literal := range map[string]string{
		"backslash-escaped quote": strings.Repeat(`\'`, 524288),
		"doubled quote":           strings.Repeat(`''`, 524288),
	} {
		t.Run(name, func(t *testing.T) {
			req := baseRequest("/hello")
			req.Method = "POST"
			req.Headers = append(req.Headers,
				[2]string{"Content-Type", "application/x-www-form-urlencoded"})
			req.Body = []byte("q='" + literal)
			start := time.Now()
			run(t, rs, req)
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("a %d-byte string literal took %v", len(req.Body), d)
			}
		})
	}
}

// GHSA-5gj4-9gm7-2fx2: before Coraza 3.8.1 a dotted property ("a.b")
// overwrote the flattened name of a nested one ({"a":{"b":...}}), hiding
// the nested value from the rules.
func TestJSONKeyCollision(t *testing.T) {
	rs := newTestRuleSet(t)
	post := func(body string) *Result {
		req := baseRequest("/hello")
		req.Method = "POST"
		req.Headers = append(req.Headers, [2]string{"Content-Type", "application/json"})
		req.Body = []byte(body)
		res, _, _ := run(t, rs, req)
		return res
	}

	nested := post(`{"account":{"role":"1' OR '1'='1"}}`)
	decoy := post(`{"account":{"role":"1' OR '1'='1"},"account.role":"safe"}`)
	// -1 means the score was not available
	if nested.AnomalyScore <= 0 {
		t.Fatalf("nested SQL injection not detected: score %d", nested.AnomalyScore)
	}
	if decoy.AnomalyScore < nested.AnomalyScore {
		t.Fatalf("a dotted decoy lowered the score from %d to %d",
			nested.AnomalyScore, decoy.AnomalyScore)
	}
}

func TestArgsLimitRepeatedNamesHideNothing(t *testing.T) {
	rs, err := newRuleSet("SecArgumentsLimit 2\nSecRuleEngine DetectionOnly")
	if err != nil {
		t.Fatal(err)
	}
	// two names, four values before the attack: c is dropped
	res, _, _ := run(t, rs, baseRequest("/hello?a=1&a=2&b=1&b=2&c=attack"))
	if !res.ArgsLimitReached {
		t.Fatal("dropped arguments not reported")
	}
}

func multipart(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--x\r\n" + p + "\r\n")
	}
	b.WriteString("--x--\r\n")
	return b.String()
}

// Bypasses fixed in CRS after v4.25.0, the last release of the legacy
// coraza-coreruleset/v4 module, which detects none of these.
func TestCRSSecurityFixes(t *testing.T) {
	rs := newTestRuleSet(t)
	cases := []struct {
		name, uri, contentType, body string
		ruleID                       string
	}{
		// GHSA-575j-qr6p-9763: command injection in the URL path
		{"rce in path", "/;/bin/sh%20-c%20id", "", "", "932230"},
		// GHSA-89h9-2j8h-9gp2: an upper case charset parameter name
		{"charset name case", "/hello",
			"application/x-www-form-urlencoded; CHARSET=utf-7", "a=b", "920480"},
		// GHSA-qmx4-jfcv-fgww: a second _charset_ shadowing the first
		{"repeated _charset_", "/hello", "multipart/form-data; boundary=x", multipart(
			"Content-Disposition: form-data; name=\"_charset_\"\r\n\r\nutf-8",
			"Content-Disposition: form-data; name=\"_charset_\"\r\n\r\nutf-7"), "922100"},
		// V29-260924: a trailing slash after the upload extension
		{"php upload with trailing slash", "/hello", "multipart/form-data; boundary=x", multipart(
			"Content-Disposition: form-data; name=\"f\"; filename=\"shell.php/\"\r\n\r\nhi"), "933110"},
		{"jsp upload with trailing slash", "/hello", "multipart/form-data; boundary=x", multipart(
			"Content-Disposition: form-data; name=\"f\"; filename=\"shell.jsp/\"\r\n\r\nhi"), "944140"},
		// GHSA-6jp8-c2w2-x7wr: attack in an XML attribute value
		{"xml attribute", "/hello", "text/xml",
			`<a b="1' UNION SELECT password FROM users--"/>`, "942100"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := baseRequest(c.uri)
			if c.body != "" {
				req.Method = "POST"
				req.Headers = append(req.Headers,
					[2]string{"Content-Type", c.contentType},
					[2]string{"Content-Length", strconv.Itoa(len(c.body))})
				req.Body = []byte(c.body)
			}
			_, ids, _ := run(t, rs, req)
			if !strings.Contains(","+ids+",", ","+c.ruleID+",") {
				t.Fatalf("rule %s did not match, matched %q", c.ruleID, ids)
			}
		})
	}
}

// records the calls evaluate makes and can fail Close
type recordingWAF struct {
	coraza.WAF
	calls    *[]string
	closeErr error
}

func (w recordingWAF) NewTransactionWithID(id string) types.Transaction {
	return recordingTx{w.WAF.NewTransactionWithID(id), w.calls, w.closeErr}
}

type recordingTx struct {
	types.Transaction
	calls    *[]string
	closeErr error
}

func (tx recordingTx) ProcessLogging() {
	*tx.calls = append(*tx.calls, "logging")
	tx.Transaction.ProcessLogging()
}

func (tx recordingTx) Close() error {
	*tx.calls = append(*tx.calls, "close")
	if err := tx.Transaction.Close(); err != nil {
		return err
	}
	return tx.closeErr
}

// A body over SecRequestBodyInMemoryLimit is buffered in a temporary file;
// when that file cannot be created the request phases fail, and the logging
// phase must still run and the transaction be closed.
func TestBodyBufferFailureIsLoggedAndClosed(t *testing.T) {
	dir := t.TempDir()
	// Coraza buffers bodies in os.TempDir(), which it checks for writing
	// when the rule set is built
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	auditLog := filepath.Join(dir, "audit.log")
	rs, err := newRuleSet(`SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 1048576
SecRequestBodyInMemoryLimit 1024
SecAuditEngine On
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLogParts ABZ
SecAuditLog ` + auditLog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tmp); err != nil {
		t.Fatal(err)
	}
	var calls []string
	rs.waf = recordingWAF{WAF: rs.waf, calls: &calls}

	req := baseRequest("/hello")
	req.Method = "POST"
	req.TxID = "body-buffer-failure"
	req.Body = []byte(strings.Repeat("a", 4096))
	if _, err := evaluate(rs, req, make([]byte, 1024)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error %v, want the temporary file not created", err)
	}

	if strings.Join(calls, ",") != "logging,close" {
		t.Fatalf("calls %v, want logging then close", calls)
	}
	data, err := os.ReadFile(auditLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), req.TxID) {
		t.Fatalf("transaction missing from the audit log: %q", data)
	}
}

// A failure to close keeps the result and is counted.
func TestCloseErrorKeepsResult(t *testing.T) {
	rs := newTestRuleSet(t)
	var calls []string
	rs.waf = recordingWAF{WAF: rs.waf, calls: &calls, closeErr: errors.New("close failed")}

	before := CloseErrors()
	req := baseRequest("/hello")
	req.Headers = append(req.Headers, [2]string{"X-Test", "deny"})
	_, ids, _ := run(t, rs, req)
	if ids != "10001" {
		t.Fatalf("rule IDs %q, want 10001", ids)
	}
	if n := CloseErrors() - before; n != 1 {
		t.Fatalf("close errors counted %d, want 1", n)
	}
	if strings.Join(calls, ",") != "logging,close" {
		t.Fatalf("calls %v, want logging then close", calls)
	}
}
