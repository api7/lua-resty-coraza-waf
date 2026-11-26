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

// Evaluation budget.
//
// Coraza runs the rules of a phase in one loop and takes no context. In
// DetectionOnly an interruption does not end that loop, so a checkpoint
// cannot stop it with deny. Instead, before each CRS file, New places one
// checkpoint rule per request phase. Once the deadline has passed, the
// checkpoint matches and skips to a marker after every rule, so the rest of
// the phase, custom rules included, is skipped while the logging phase still
// runs. Eval then skips the request body phase when phase 1 ran out.
//
// The checkpoints target a TX variable that Eval sets only when a budget is
// given; without it they are never evaluated.

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	// directives must not contain this prefix, see expand
	budgetReserved = "CORAZA_WAF_BUDGET"
	budgetMarker   = budgetReserved + "_END"
	budgetVar      = "coraza_waf_budget"
	budgetOperator = "corazaWafBudget"

	// BudgetFirstID and BudgetLastID bound the IDs of the checkpoint rules.
	// Directives must not define or remove rules in this range.
	BudgetFirstID = 2147483000
	BudgetLastID  = 2147483647
)

type budget struct {
	deadline time.Time
	// phase whose checkpoint ran out, 0 while the budget lasts
	phase types.RulePhase
}

// transaction -> *budget, for the transactions evaluated with a budget
var budgets sync.Map

type budgetOp struct {
	phase types.RulePhase
}

func (o budgetOp) Evaluate(tx plugintypes.TransactionState, _ string) bool {
	// with multiphase evaluation a rule also runs in earlier phases
	if tx.LastPhase() != o.phase {
		return false
	}
	v, ok := budgets.Load(tx)
	if !ok {
		return false
	}
	b := v.(*budget)
	if b.phase != 0 {
		return true
	}
	if time.Now().Before(b.deadline) {
		return false
	}
	b.phase = o.phase
	return true
}

func init() {
	plugins.RegisterOperator(budgetOperator, func(opt plugintypes.OperatorOptions) (plugintypes.Operator, error) {
		n, err := strconv.Atoi(opt.Arguments)
		if err != nil || (n != 1 && n != 2) {
			return nil, fmt.Errorf("@%s takes the phase, 1 or 2", budgetOperator)
		}
		return budgetOp{phase: types.RulePhase(n)}, nil
	})
}

func writeCheckpoints(b *strings.Builder, n int) {
	for phase := 1; phase <= 2; phase++ {
		fmt.Fprintf(b, "SecRule TX:%s \"@%s %d\" \"id:%d,phase:%d,pass,nolog,t:none,skipAfter:%s\"\n",
			budgetVar, budgetOperator, phase, BudgetFirstID+2*n+phase-1, phase, budgetMarker)
	}
}
