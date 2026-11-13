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

// Package main exposes Coraza v3 and the embedded OWASP CRS as a C shared
// library, called through LuaJIT FFI by lib/resty/coraza.lua.
//
// Contract with the Lua side:
//   - the library is loaded in HTTP workers only, after fork;
//   - every call is synchronous and Go never calls back into Lua;
//   - every exported function recovers panics and reports them as an error;
//   - one request is one cwaf_eval call: phase 1, phase 2 and logging, after
//     which the transaction is closed. Response phases are never run.
package main

/*
#include <stdint.h>

typedef struct {
    const char  *method;      int method_len;
    const char  *uri;         int uri_len;
    const char  *protocol;    int protocol_len;
    const char  *client_ip;   int client_ip_len;   int client_port;
    const char  *server_ip;   int server_ip_len;   int server_port;
    const char  *server_name; int server_name_len;
    const char  *tx_id;       int tx_id_len;
    const char **header_names;
    int         *header_name_lens;
    const char **header_values;
    int         *header_value_lens;
    int          header_count;
    const char  *body;        int body_len;
    int          log_matched_data;
} cwaf_request_t;

typedef struct {
    int interrupted;
    int interrupt_rule_id;
    int matched;
    int anomaly_score;
    int args_limit_reached;
    int rule_ids_len;
    int matches_len;
} cwaf_result_t;
*/
import "C"

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

var (
	mu       sync.Mutex
	wafs     = map[int64]*ruleSet{}
	jobs     = map[int64]*buildJob{}
	nextID   atomic.Int64
	panics   atomic.Int64
	building atomic.Int64
)

type ruleSet struct {
	waf coraza.WAF
}

type buildJob struct {
	done chan struct{}
	rs   *ruleSet
	err  error
}

func writeErr(buf *C.char, capacity C.int, msg string) {
	if buf == nil || capacity <= 0 {
		return
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(capacity))
	n := copy(b[:len(b)-1], msg)
	b[n] = 0
}

func recoverErr(errbuf *C.char, errcap C.int, rc *C.int) {
	if r := recover(); r != nil {
		panics.Add(1)
		writeErr(errbuf, errcap, fmt.Sprint("panic: ", r))
		*rc = -1
	}
}

func goString(p *C.char, n C.int) string {
	if p == nil || n <= 0 {
		return ""
	}
	return C.GoStringN(p, n)
}

func newRuleSet(directives string) (rs *ruleSet, err error) {
	defer func() {
		if r := recover(); r != nil {
			panics.Add(1)
			err = fmt.Errorf("panic while building rule set: %v", r)
		}
	}()
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives))
	if err != nil {
		return nil, err
	}
	return &ruleSet{waf: w}, nil
}

// cwaf_build_start parses the directives on a goroutine and returns a job id
// (> 0), or -1. The caller polls cwaf_build_poll without blocking its event loop.
//
//export cwaf_build_start
func cwaf_build_start(dirs *C.char, dlen C.int) (id C.int64_t) {
	defer func() {
		if r := recover(); r != nil {
			panics.Add(1)
			id = -1
		}
	}()
	s := goString(dirs, dlen)
	j := &buildJob{done: make(chan struct{})}
	jid := nextID.Add(1)
	mu.Lock()
	jobs[jid] = j
	mu.Unlock()
	building.Add(1)
	go func() {
		defer building.Add(-1)
		j.rs, j.err = newRuleSet(s)
		close(j.done)
	}()
	return C.int64_t(jid)
}

// cwaf_build_poll returns 0 while the job is pending, a rule set handle (> 0)
// once it is built, or -1 with the reason in errbuf. A finished job is
// forgotten after it has been reported once.
//
//export cwaf_build_poll
func cwaf_build_poll(jid C.int64_t, errbuf *C.char, errcap C.int) (h C.int64_t) {
	defer func() {
		if r := recover(); r != nil {
			panics.Add(1)
			writeErr(errbuf, errcap, fmt.Sprint("panic: ", r))
			h = -1
		}
	}()
	mu.Lock()
	j := jobs[int64(jid)]
	mu.Unlock()
	if j == nil {
		writeErr(errbuf, errcap, "unknown build job")
		return -1
	}
	select {
	case <-j.done:
	default:
		return 0
	}
	mu.Lock()
	delete(jobs, int64(jid))
	if j.err == nil {
		wafs[int64(jid)] = j.rs
	}
	mu.Unlock()
	if j.err != nil {
		writeErr(errbuf, errcap, j.err.Error())
		return -1
	}
	return jid
}

// cwaf_free drops a rule set handle; its memory is reclaimed by the Go GC.
//
//export cwaf_free
func cwaf_free(h C.int64_t) {
	defer func() {
		if recover() != nil {
			panics.Add(1)
		}
	}()
	mu.Lock()
	delete(wafs, int64(h))
	mu.Unlock()
}

// cwaf_eval inspects one request with the rule set h. Rule IDs (comma
// separated) and then the JSON array of matches are written to out; their
// lengths are reported in res. Returns 0 on success, -1 on error.
//
//export cwaf_eval
func cwaf_eval(h C.int64_t, req *C.cwaf_request_t, res *C.cwaf_result_t,
	out *C.char, outcap C.int, errbuf *C.char, errcap C.int) (rc C.int) {
	defer recoverErr(errbuf, errcap, &rc)

	mu.Lock()
	rs := wafs[int64(h)]
	mu.Unlock()
	if rs == nil {
		writeErr(errbuf, errcap, "unknown rule set handle")
		return -1
	}

	var buf []byte
	if out != nil && outcap > 0 {
		buf = unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outcap))
	}
	r, err := evaluate(rs, toRequest(req), buf)
	if err != nil {
		writeErr(errbuf, errcap, err.Error())
		return -1
	}
	res.interrupted = C.int(r.interrupted)
	res.interrupt_rule_id = C.int(r.interruptRuleID)
	res.matched = C.int(r.matched)
	res.anomaly_score = C.int(r.anomalyScore)
	res.args_limit_reached = boolInt(r.argsLimitReached)
	res.rule_ids_len = C.int(r.ruleIDsLen)
	res.matches_len = C.int(r.matchesLen)
	return 0
}

func boolInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

func toRequest(req *C.cwaf_request_t) *request {
	r := &request{
		method:         goString(req.method, req.method_len),
		uri:            goString(req.uri, req.uri_len),
		protocol:       goString(req.protocol, req.protocol_len),
		clientIP:       goString(req.client_ip, req.client_ip_len),
		clientPort:     int(req.client_port),
		serverIP:       goString(req.server_ip, req.server_ip_len),
		serverPort:     int(req.server_port),
		serverName:     goString(req.server_name, req.server_name_len),
		txID:           goString(req.tx_id, req.tx_id_len),
		logMatchedData: req.log_matched_data != 0,
	}
	if n := int(req.header_count); n > 0 {
		names := unsafe.Slice(req.header_names, n)
		nameLens := unsafe.Slice(req.header_name_lens, n)
		values := unsafe.Slice(req.header_values, n)
		valueLens := unsafe.Slice(req.header_value_lens, n)
		r.headers = make([][2]string, n)
		for i := 0; i < n; i++ {
			r.headers[i] = [2]string{
				goString(names[i], C.int(nameLens[i])),
				goString(values[i], C.int(valueLens[i])),
			}
		}
	}
	if req.body != nil && req.body_len > 0 {
		// WriteRequestBody copies it, so the Lua string only has to outlive
		// this call
		r.body = unsafe.Slice((*byte)(unsafe.Pointer(req.body)), int(req.body_len))
	}
	return r
}

// cwaf_stats writes the number of live rule sets, rule sets being built and
// recovered panics.
//
//export cwaf_stats
func cwaf_stats(out *C.int64_t) {
	defer func() {
		if recover() != nil {
			panics.Add(1)
		}
	}()
	s := unsafe.Slice(out, 3)
	mu.Lock()
	s[0] = C.int64_t(len(wafs))
	mu.Unlock()
	s[1] = C.int64_t(building.Load())
	s[2] = C.int64_t(panics.Load())
}

func main() {}
