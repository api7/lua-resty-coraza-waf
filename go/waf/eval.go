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
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	// limits of the matches JSON array
	maxMatches     = 20
	maxMatchesSize = 8192
)

// Request is one HTTP request to inspect. Body is only read during Eval.
type Request struct {
	Method, URI, Protocol string
	ClientIP              string
	ClientPort            int
	ServerIP              string
	ServerPort            int
	ServerName            string
	TxID                  string
	Headers               [][2]string
	Body                  []byte
	LogMatchedData        bool
	// time allowed for the request phases, none when zero
	Budget time.Duration
}

// Status is the outcome of Eval.
type Status int

const (
	// Done: every request phase ran
	Done Status = iota
	// Interrupted: a rule interrupted the request; only with SecRuleEngine On
	Interrupted
	// BudgetExhausted: the budget ran out and the rules after a checkpoint
	// were skipped. The result holds the matches found before.
	BudgetExhausted
)

// Result of Eval. RuleIDsLen bytes of comma separated rule IDs, then
// MatchesLen bytes of the matches JSON array, are written to out.
type Result struct {
	Status          Status
	InterruptRuleID int
	// the rule that interrupts, or would interrupt with SecRuleEngine On
	WouldInterruptRuleID int
	Matched              int
	// -1 when CRS did not compute it
	AnomalyScore     int
	ArgsLimitReached bool
	// phase (1 or 2) whose checkpoint ran out, with BudgetExhausted
	BudgetPhase int
	// time spent in Eval
	Elapsed    time.Duration
	RuleIDsLen int
	MatchesLen int
}

type match struct {
	ID       int      `json:"id"`
	Severity string   `json:"severity"`
	Msg      string   `json:"msg"`
	Tags     []string `json:"tags"`
	Ver      string   `json:"ver"`
	Data     *string  `json:"data,omitempty"`
}

var truncatedMarker = []byte(`{"truncated":true}`)

// Eval runs the request phases of one transaction and writes the rule IDs
// followed by the matches JSON into out. As in Coraza's HTTP middleware, the
// logging phase runs and the transaction is closed on every path, including
// when the request phases fail. A failure to close (removing a temporary
// body file) does not change the result; it is counted in CloseErrors and
// written to the debug log.
//
// With a budget, a phase that runs out skips its remaining rules, and the
// request body phase is skipped when the headers phase ran out. A budget
// that runs out after the last checkpoint does not change the status;
// Elapsed shows it.
func (w *WAF) Eval(req *Request, out []byte) (*Result, error) {
	start := time.Now()
	tx := w.waf.NewTransactionWithID(req.TxID)
	logger := tx.DebugLogger()
	defer func() {
		if err := tx.Close(); err != nil {
			closeErrors.Add(1)
			logger.Error().Err(err).Msg("Failed to close the transaction")
		}
	}()

	var b *budget
	if req.Budget > 0 {
		if st, ok := tx.(plugintypes.TransactionState); ok {
			b = &budget{deadline: start.Add(req.Budget)}
			budgets.Store(tx, b)
			defer budgets.Delete(tx)
			st.Variables().TX().Set(budgetVar, []string{"1"})
		}
	}

	it, err := processRequest(tx, req, b)
	tx.ProcessLogging()
	if err != nil {
		return nil, err
	}

	res := &Result{AnomalyScore: -1}
	defer func() { res.Elapsed = time.Since(start) }()
	if tx.IsRuleEngineOff() {
		return res, nil
	}

	if b != nil && b.phase != 0 {
		res.Status = BudgetExhausted
		res.BudgetPhase = int(b.phase)
	}
	if it != nil {
		// a drop or a deny without status has Status 0
		res.Status = Interrupted
		res.InterruptRuleID = it.RuleID
		res.WouldInterruptRuleID = it.RuleID
	} else if d, ok := tx.(interface {
		DetectionOnlyInterruption() *types.Interruption
	}); ok {
		if di := d.DetectionOnlyInterruption(); di != nil {
			res.WouldInterruptRuleID = di.RuleID
		}
	}

	if st, ok := tx.(plugintypes.TransactionState); ok {
		vars := st.Variables()
		if v := vars.TX().Get("blocking_inbound_anomaly_score"); len(v) > 0 {
			if n, err := strconv.Atoi(v[0]); err == nil {
				res.AnomalyScore = n
			}
		}
		// set by Coraza when it dropped arguments over SecArgumentsLimit,
		// from the query or from a body processor
		res.ArgsLimitReached = vars.ArgumentsLimitReached().Get() == "1"
	}

	writeMatches(tx.MatchedRules(), req.LogMatchedData, res, out)
	return res, nil
}

// processRequest runs phases 1 and 2 and returns the interruption. Phase 2
// is skipped once the budget b has run out.
func processRequest(tx types.Transaction, req *Request, b *budget) (*types.Interruption, error) {
	if tx.IsRuleEngineOff() {
		return nil, nil
	}

	tx.ProcessConnection(req.ClientIP, req.ClientPort, req.ServerIP, req.ServerPort)
	tx.ProcessURI(req.URI, req.Method, req.Protocol)
	for _, h := range req.Headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if req.ServerName != "" {
		tx.SetServerName(req.ServerName)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	if b != nil {
		if b.phase == 0 && !time.Now().Before(b.deadline) {
			b.phase = types.PhaseRequestHeaders
		}
		if b.phase != 0 {
			return nil, nil
		}
	}
	if len(req.Body) > 0 && tx.IsRequestBodyAccessible() {
		it, _, err := tx.WriteRequestBody(req.Body)
		if err != nil || it != nil {
			return it, err
		}
	}
	return tx.ProcessRequestBody()
}

// writeMatches keeps the rules that have logging enabled, the same filter as
// the Coraza error callback.
func writeMatches(rules []types.MatchedRule, withData bool, res *Result, out []byte) {
	matchesCap := maxMatchesSize
	if matchesCap > len(out)/2 {
		matchesCap = len(out) / 2
	}
	idsCap := len(out) - matchesCap

	ids := out[:0:idsCap]
	seen := map[int]struct{}{}
	matches := make([]byte, 0, matchesCap)
	matches = append(matches, '[')
	n, truncated := 0, false

	for _, mr := range rules {
		if l, ok := mr.(interface{ Log() bool }); ok && !l.Log() {
			continue
		}
		res.Matched++
		rule := mr.Rule()
		id := rule.ID()

		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			s := strconv.Itoa(id)
			need := len(s)
			if len(ids) > 0 {
				need++
			}
			if len(ids)+need <= cap(ids) {
				if len(ids) > 0 {
					ids = append(ids, ',')
				}
				ids = append(ids, s...)
			}
		}

		if truncated {
			continue
		}
		if n >= maxMatches {
			truncated = true
			continue
		}
		m := match{
			ID:       id,
			Severity: severity(rule),
			Msg:      mr.Message(),
			Tags:     rule.Tags(),
			Ver:      rule.Version(),
		}
		if m.Tags == nil {
			m.Tags = []string{}
		}
		if withData {
			d := mr.Data()
			m.Data = &d
		}
		b, err := json.Marshal(m)
		if err != nil {
			continue
		}
		// room for the separator, this item, the truncation marker and "]"
		if len(matches)+1+len(b)+1+len(truncatedMarker)+1 > matchesCap {
			truncated = true
			continue
		}
		if n > 0 {
			matches = append(matches, ',')
		}
		matches = append(matches, b...)
		n++
	}

	if truncated {
		if n > 0 {
			matches = append(matches, ',')
		}
		matches = append(matches, truncatedMarker...)
	}
	matches = append(matches, ']')

	res.RuleIDsLen = len(ids)
	if n == 0 && !truncated {
		return
	}
	if len(matches) <= len(out)-len(ids) {
		res.MatchesLen = copy(out[len(ids):], matches)
	}
}

// severity is empty for rules without a severity action; Coraza reports
// those as "emergency", the zero value.
func severity(rule types.RuleMetadata) string {
	if rule.Severity() == types.RuleSeverityEmergency &&
		!strings.Contains(strings.ToLower(rule.Raw()), "severity:") {
		return ""
	}
	return rule.Severity().String()
}
