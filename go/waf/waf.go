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

// Package waf builds Coraza v3 rule sets with the embedded OWASP CRS and
// inspects requests with them. It holds no global handle table and makes no
// cgo calls, so other packages can import it; package main of this module
// exposes it through a C ABI.
package waf

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync/atomic"
	"time"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
)

// @owasp_crs/, @crs-setup.conf.example and @coraza.conf-recommended
var rootFS = mergefs.Merge(crs.FS, corazaconf.FS)

// crsInclude is the directive that loads every CRS rule file. New expands it
// into one Include per file with budget checkpoints in between.
const crsInclude = "Include @owasp_crs/*.conf"

var (
	panics      atomic.Int64
	closeErrors atomic.Int64
)

// Panics returns the number of panics recovered while building rule sets.
func Panics() int64 { return panics.Load() }

// CloseErrors returns the number of transactions that failed to close, see
// WAF.Eval.
func CloseErrors() int64 { return closeErrors.Load() }

// WAF is a compiled rule set. It is safe for concurrent use.
type WAF struct {
	waf coraza.WAF
}

// BuildInfo describes a successful build.
type BuildInfo struct {
	Duration time.Duration
	// number of rules, including the budget checkpoints
	Rules int
}

// New compiles the SecLang directives. Files are read from the embedded CRS
// only. A directive line equal to crsInclude is expanded so that the
// evaluation budget is checked before each CRS file, see budget.go.
func New(directives string) (w *WAF, info BuildInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			panics.Add(1)
			w, err = nil, fmt.Errorf("panic while building rule set: %v", r)
		}
	}()
	start := time.Now()
	expanded, err := expand(directives)
	if err != nil {
		return nil, info, err
	}
	cw, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(rootFS).
		WithDirectives(expanded))
	if err != nil {
		return nil, info, err
	}
	info.Duration = time.Since(start)
	if rc, ok := cw.(interface{ RulesCount() int }); ok {
		info.Rules = rc.RulesCount()
	}
	return &WAF{waf: cw}, info, nil
}

// Close releases the matchers that the rule set shares with other rule sets
// built in this process. The WAF must not be used afterwards.
func (w *WAF) Close() error {
	if c, ok := w.waf.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func expand(directives string) (string, error) {
	if strings.Contains(directives, budgetReserved) {
		return "", fmt.Errorf("directives must not use the reserved name %s", budgetReserved)
	}
	files, err := fs.Glob(rootFS, "@owasp_crs/*.conf")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(len(directives) + len(files)*256)
	cp := 0
	for _, line := range strings.SplitAfter(directives, "\n") {
		if strings.TrimSpace(line) != crsInclude {
			b.WriteString(line)
			continue
		}
		for _, f := range files {
			cp++
			writeCheckpoints(&b, cp)
			b.WriteString("Include ")
			b.WriteString(f)
			b.WriteByte('\n')
		}
	}
	if !strings.HasSuffix(b.String(), "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("SecMarker " + budgetMarker + "\n")
	return b.String(), nil
}
