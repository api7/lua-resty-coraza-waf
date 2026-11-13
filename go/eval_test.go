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

package main

import (
	"encoding/json"
	"strings"
	"testing"
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

func newTestRuleSet(t *testing.T) *ruleSet {
	t.Helper()
	rs, err := newRuleSet(testDirectives)
	if err != nil {
		t.Fatal(err)
	}
	if rs.argLimit != 5 {
		t.Fatalf("argLimit = %d", rs.argLimit)
	}
	return rs
}

func baseRequest(uri string) *request {
	return &request{
		method: "GET", uri: uri, protocol: "HTTP/1.1",
		clientIP: "10.1.2.3", clientPort: 12345,
		serverIP: "127.0.0.1", serverPort: 9080, serverName: "localhost",
		txID: "abc",
		headers: [][2]string{
			{"Host", "localhost"},
			{"User-Agent", "curl/8.0"},
			{"Accept", "*/*"},
		},
	}
}

func run(t *testing.T, rs *ruleSet, req *request) (*result, string, []map[string]any) {
	t.Helper()
	out := make([]byte, 16384)
	res, err := evaluate(rs, req, out)
	if err != nil {
		t.Fatal(err)
	}
	ids := string(out[:res.ruleIDsLen])
	var matches []map[string]any
	if res.matchesLen > 0 {
		if err := json.Unmarshal(out[res.ruleIDsLen:res.ruleIDsLen+res.matchesLen], &matches); err != nil {
			t.Fatal(err)
		}
	}
	return res, ids, matches
}

func TestCleanRequest(t *testing.T) {
	rs := newTestRuleSet(t)
	res, ids, _ := run(t, rs, baseRequest("/hello?a=1"))
	if res.matched != 0 || ids != "" || res.matchesLen != 0 {
		t.Fatalf("unexpected matches: %d %q", res.matched, ids)
	}
}

func TestSQLiQuery(t *testing.T) {
	rs := newTestRuleSet(t)
	res, ids, matches := run(t, rs, baseRequest("/hello?id=1%27%20OR%20%271%27=%271"))
	if !strings.Contains(ids, "942100") || !strings.Contains(ids, "949110") {
		t.Fatalf("ids = %q", ids)
	}
	if res.anomalyScore < 5 {
		t.Fatalf("anomaly score = %d", res.anomalyScore)
	}
	if res.interrupted != 0 {
		t.Fatalf("DetectionOnly must not interrupt")
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
	// Coraza 3.3.3 applies SecArgumentsLimit to query arguments only
	req := baseRequest("/hello?a=1&b=2&c=3&d=4&e=5&f=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	res, ids, matches := run(t, rs, req)
	if !res.argsLimitReached {
		t.Fatalf("args limit not reported: %q %d", ids, len(matches))
	}

	req = baseRequest("/hello")
	req.method = "POST"
	req.logMatchedData = true
	req.headers = append(req.headers, [2]string{"Content-Type", "application/json"})
	req.body = []byte(`{"q":"1' UNION SELECT password FROM users--"}`)
	res, ids, matches = run(t, rs, req)
	if res.argsLimitReached || !strings.Contains(ids, "942") {
		t.Fatalf("ids = %q limit = %v", ids, res.argsLimitReached)
	}
	if _, ok := matches[0]["data"]; !ok {
		t.Fatalf("data missing: %v", matches[0])
	}
}

func TestCustomDenyIsNotEnforced(t *testing.T) {
	rs := newTestRuleSet(t)
	req := baseRequest("/hello")
	req.headers = append(req.headers, [2]string{"X-Test", "deny"})
	res, ids, _ := run(t, rs, req)
	if ids != "10001" || res.interrupted != 0 {
		t.Fatalf("ids = %q interrupted = %d", ids, res.interrupted)
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
	s := string(out[res2.ruleIDsLen : res2.ruleIDsLen+res2.matchesLen])
	if !strings.HasSuffix(s, `{"truncated":true}]`) {
		t.Fatalf("not truncated: %s (full ids %q, %d matches, %d)", s, ids, len(matches), res.matched)
	}
}

func TestBuildError(t *testing.T) {
	if _, err := newRuleSet("SecRule ARGS \"@rx (\" \"id:1,phase:1,pass\""); err == nil {
		t.Fatal("expected an error")
	}
}
