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
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// probes after every CRS rule: 20001 and 20002 run at the end of the request
// phases, 20005 in the logging phase
const probes = `
SecAction "id:20001,phase:1,pass,log,msg:'end of phase 1'"
SecAction "id:20002,phase:2,pass,log,msg:'end of phase 2'"
SecAction "id:20005,phase:5,pass,log,msg:'logging'"`

func budgetRuleSet(t *testing.T, withCRS bool) *WAF {
	t.Helper()
	d := strings.Replace(testDirectives, "SecArgumentsLimit 5", "SecArgumentsLimit 1000", 1)
	if !withCRS {
		d = strings.Replace(d, crsInclude+"\n", "", 1)
	}
	w, _, err := New(d + probes)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func jsonBody(fields int) []byte {
	parts := make([]string, fields)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"field%d":"value number %d"`, i, i)
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

func ids(t *testing.T, w *WAF, req *Request) (*Result, map[string]bool) {
	t.Helper()
	res, s, _ := run(t, w, req)
	m := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		m[id] = true
	}
	return res, m
}

func TestBudgetUnset(t *testing.T) {
	w := budgetRuleSet(t, true)
	res, got := ids(t, w, baseRequest("/hello?id=1%27%20OR%20%271%27=%271"))
	if res.Status != Done || res.BudgetPhase != 0 {
		t.Fatalf("status %d phase %d", res.Status, res.BudgetPhase)
	}
	for _, id := range []string{"942100", "20001", "20002", "20005"} {
		if !got[id] {
			t.Fatalf("rule %s did not match: %v", id, got)
		}
	}
}

func TestBudgetLasts(t *testing.T) {
	w := budgetRuleSet(t, true)
	req := baseRequest("/hello?id=1%27%20OR%20%271%27=%271")
	req.Budget = time.Hour
	res, got := ids(t, w, req)
	if res.Status != Done || !got["942100"] || !got["20002"] || !got["20005"] {
		t.Fatalf("status %d ids %v", res.Status, got)
	}
}

// Running out in phase 1 skips the rest of phase 1 and the whole of phase 2;
// the logging phase runs.
func TestBudgetPhase1(t *testing.T) {
	w := budgetRuleSet(t, true)
	req := baseRequest("/hello?id=1%27%20OR%20%271%27=%271")
	req.Method = "POST"
	req.Headers = append(req.Headers, [2]string{"Content-Type", "application/json"})
	req.Body = []byte(`{"q":"1' UNION SELECT password FROM users--"}`)
	req.Budget = time.Nanosecond
	res, got := ids(t, w, req)
	if res.Status != BudgetExhausted || res.BudgetPhase != 1 {
		t.Fatalf("status %d phase %d", res.Status, res.BudgetPhase)
	}
	if got["20001"] || got["20002"] || got["942100"] {
		t.Fatalf("rules after the checkpoint ran: %v", got)
	}
	if !got["20005"] {
		t.Fatalf("logging phase did not run: %v", got)
	}
	for id := range got {
		if strings.HasPrefix(id, "21474") {
			t.Fatalf("checkpoint %s reported as a match", id)
		}
	}
}

// Running out while the body rules run keeps the phase 1 matches and skips
// the remaining phase 2 rules.
func TestBudgetPhase2(t *testing.T) {
	w := budgetRuleSet(t, true)
	req := baseRequest("/hello?id=1%27%20OR%20%271%27=%271")
	req.Method = "POST"
	req.Headers = append(req.Headers, [2]string{"Content-Type", "application/json"})
	req.Body = jsonBody(800)

	full, _ := ids(t, w, req)
	req.Budget = full.Elapsed / 4
	if req.Budget < 10*time.Millisecond {
		t.Skipf("inspection too fast to split: %v", full.Elapsed)
	}
	res, got := ids(t, w, req)
	if res.Status != BudgetExhausted || res.BudgetPhase != 2 {
		t.Fatalf("status %d phase %d, elapsed %v of %v", res.Status, res.BudgetPhase, res.Elapsed, full.Elapsed)
	}
	if !got["20001"] || got["20002"] || !got["20005"] {
		t.Fatalf("ids %v", got)
	}
	if res.Elapsed >= full.Elapsed {
		t.Fatalf("elapsed %v, %v without a budget", res.Elapsed, full.Elapsed)
	}
}

// Without checkpoints, a budget gone after phase 1 still skips phase 2.
func TestBudgetWithoutCRS(t *testing.T) {
	w := budgetRuleSet(t, false)
	req := baseRequest("/hello")
	req.Budget = time.Nanosecond
	res, got := ids(t, w, req)
	if res.Status != BudgetExhausted || res.BudgetPhase != 1 {
		t.Fatalf("status %d phase %d", res.Status, res.BudgetPhase)
	}
	if !got["20001"] || got["20002"] || !got["20005"] {
		t.Fatalf("ids %v", got)
	}
}

func TestBudgetCheckpoints(t *testing.T) {
	files, err := fs.Glob(rootFS, "@owasp_crs/*.conf")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	d, err := expand(testDirectives)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(d, "@"+budgetOperator); n != 2*len(files) {
		t.Fatalf("%d checkpoints for %d files", n, len(files))
	}
	if strings.Contains(d, crsInclude) {
		t.Fatal("CRS include left unexpanded")
	}
	if !strings.HasSuffix(d, "SecMarker "+budgetMarker+"\n") {
		t.Fatal("marker is not the last directive")
	}
	if last := BudgetFirstID + 2*len(files) + 1; last > BudgetLastID {
		t.Fatalf("checkpoint id %d out of range", last)
	}
}

func TestBudgetReservedName(t *testing.T) {
	_, _, err := New("SecMarker " + budgetMarker)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("err %v", err)
	}
}

func TestClose(t *testing.T) {
	w, info, err := New(testDirectives)
	if err != nil {
		t.Fatal(err)
	}
	if info.Duration <= 0 || info.Rules == 0 {
		t.Fatalf("build info %+v", info)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
