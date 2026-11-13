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
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	// limits of the matches JSON array
	maxMatches     = 20
	maxMatchesSize = 8192
)

type request struct {
	method, uri, protocol string
	clientIP              string
	clientPort            int
	serverIP              string
	serverPort            int
	serverName            string
	txID                  string
	headers               [][2]string
	body                  []byte
	logMatchedData        bool
}

type result struct {
	interrupted      int
	interruptRuleID  int
	matched          int
	anomalyScore     int
	argsLimitReached bool
	ruleIDsLen       int
	matchesLen       int
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

// evaluate runs the request phases of one transaction and writes the rule IDs
// followed by the matches JSON into out.
func evaluate(rs *ruleSet, req *request, out []byte) (*result, error) {
	tx := rs.waf.NewTransactionWithID(req.txID)
	defer tx.Close()

	res := &result{anomalyScore: -1}
	if tx.IsRuleEngineOff() {
		return res, nil
	}

	tx.ProcessConnection(req.clientIP, req.clientPort, req.serverIP, req.serverPort)
	tx.ProcessURI(req.uri, req.method, req.protocol)
	for _, h := range req.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if req.serverName != "" {
		tx.SetServerName(req.serverName)
	}

	it := tx.ProcessRequestHeaders()
	if it == nil && len(req.body) > 0 && tx.IsRequestBodyAccessible() {
		var err error
		if it, _, err = tx.WriteRequestBody(req.body); err != nil {
			return nil, err
		}
	}
	if it == nil {
		var err error
		if it, err = tx.ProcessRequestBody(); err != nil {
			return nil, err
		}
	}
	tx.ProcessLogging()

	if it != nil {
		// a drop or a deny without status has Status 0
		res.interrupted = 1
		res.interruptRuleID = it.RuleID
	}

	if st, ok := tx.(plugintypes.TransactionState); ok {
		vars := st.Variables()
		if v := vars.TX().Get("blocking_inbound_anomaly_score"); len(v) > 0 {
			if n, err := strconv.Atoi(v[0]); err == nil {
				res.anomalyScore = n
			}
		}
		// set by Coraza when it dropped arguments over SecArgumentsLimit,
		// from the query or from a body processor
		res.argsLimitReached = vars.ArgumentsLimitReached().Get() == "1"
	}

	writeMatches(tx.MatchedRules(), req.logMatchedData, res, out)
	return res, nil
}

// writeMatches keeps the rules that have logging enabled, the same filter as
// the Coraza error callback.
func writeMatches(rules []types.MatchedRule, withData bool, res *result, out []byte) {
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
		res.matched++
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

	res.ruleIDsLen = len(ids)
	if n == 0 && !truncated {
		return
	}
	if len(matches) <= len(out)-len(ids) {
		res.matchesLen = copy(out[len(ids):], matches)
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
