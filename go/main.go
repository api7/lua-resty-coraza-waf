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

// Package main is the C ABI of this module, called through LuaJIT FFI by
// lib/resty/coraza.lua. The work is done by importable packages (waf); this
// package keeps the handle table and turns panics into errors.
//
// Contract with the Lua side:
//   - the library is loaded in HTTP workers only, after fork;
//   - Go never calls back into Lua; pointers passed in are only used during
//     the call;
//   - every exported function recovers panics and reports them as an error;
//   - one request is one waf_eval call: phase 1, phase 2 and logging, after
//     which the transaction is closed, also when a phase fails. Response
//     phases are never run.
package main

/*
#include <stdint.h>

typedef struct {
    int     max_procs;       // > 0 sets GOMAXPROCS
    int     set_gc_percent;  // != 0 sets GOGC to gc_percent, < 0 is off
    int     gc_percent;
    int64_t memory_limit;    // > 0 sets GOMEMLIMIT, in bytes
} rt_config_t;

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
    int64_t      budget_us;   // 0: no budget
} waf_req_t;

typedef struct {
    int     interrupt_rule_id;
    int     would_interrupt_rule_id;
    int     matched;
    int     anomaly_score;
    int     args_limit_reached;
    int     budget_phase;
    int64_t elapsed_us;
    int     rule_ids_len;
    int     matches_len;
} waf_res_t;

typedef struct {
    int64_t duration_us;
    int     rules;
} waf_build_info_t;
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/api7/lua-resty-coraza-waf/go/waf"
)

// abiVersion changes with any change to the exported functions or structs.
const abiVersion = 1

var (
	mu       sync.Mutex
	wafs     = map[int64]*waf.WAF{}
	jobs     = map[int64]*buildJob{}
	nextID   atomic.Int64
	panics   atomic.Int64
	building atomic.Int64
)

type buildJob struct {
	done chan struct{}
	w    *waf.WAF
	info waf.BuildInfo
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

func recoverCount() {
	if recover() != nil {
		panics.Add(1)
	}
}

func goString(p *C.char, n C.int) string {
	if p == nil || n <= 0 {
		return ""
	}
	return C.GoStringN(p, n)
}

//export rt_abi_version
func rt_abi_version() C.int { return abiVersion }

// rt_init applies the runtime settings that are not left unset in cfg.
// Setting max_procs also stops Go from updating GOMAXPROCS on its own.
//
//export rt_init
func rt_init(cfg *C.rt_config_t, errbuf *C.char, errcap C.int) (rc C.int) {
	defer recoverErr(errbuf, errcap, &rc)
	if cfg == nil {
		return 0
	}
	if cfg.max_procs < 0 || cfg.memory_limit < 0 {
		writeErr(errbuf, errcap, "max_procs and memory_limit must not be negative")
		return -1
	}
	if cfg.max_procs > 0 {
		runtime.GOMAXPROCS(int(cfg.max_procs))
	}
	if cfg.set_gc_percent != 0 {
		debug.SetGCPercent(int(cfg.gc_percent))
	}
	if cfg.memory_limit > 0 {
		debug.SetMemoryLimit(int64(cfg.memory_limit))
	}
	return 0
}

func toInfo(info waf.BuildInfo, out *C.waf_build_info_t) {
	if out == nil {
		return
	}
	out.duration_us = C.int64_t(info.Duration.Microseconds())
	out.rules = C.int(info.Rules)
}

func addWAF(w *waf.WAF) int64 {
	h := nextID.Add(1)
	mu.Lock()
	wafs[h] = w
	mu.Unlock()
	return h
}

// waf_new compiles the directives on the calling thread and returns a
// handle (> 0), or -1 with the reason in errbuf.
//
//export waf_new
func waf_new(dirs *C.char, dlen C.int, info *C.waf_build_info_t,
	errbuf *C.char, errcap C.int) (h C.int64_t) {
	defer func() {
		if r := recover(); r != nil {
			panics.Add(1)
			writeErr(errbuf, errcap, fmt.Sprint("panic: ", r))
			h = -1
		}
	}()
	building.Add(1)
	w, bi, err := waf.New(goString(dirs, dlen))
	building.Add(-1)
	if err != nil {
		writeErr(errbuf, errcap, err.Error())
		return -1
	}
	toInfo(bi, info)
	return C.int64_t(addWAF(w))
}

// waf_build_start compiles the directives on a goroutine and returns a job
// id (> 0), or -1. The caller polls waf_build_poll.
//
//export waf_build_start
func waf_build_start(dirs *C.char, dlen C.int) (id C.int64_t) {
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
		j.w, j.info, j.err = waf.New(s)
		close(j.done)
	}()
	return C.int64_t(jid)
}

// waf_build_poll returns 0 while the job is pending, a handle (> 0) once it
// is built, or -1 with the reason in errbuf. A finished job is forgotten
// after it has been reported once.
//
//export waf_build_poll
func waf_build_poll(jid C.int64_t, info *C.waf_build_info_t,
	errbuf *C.char, errcap C.int) (h C.int64_t) {
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
		wafs[int64(jid)] = j.w
	}
	mu.Unlock()
	if j.err != nil {
		writeErr(errbuf, errcap, j.err.Error())
		return -1
	}
	toInfo(j.info, info)
	return jid
}

// waf_free drops a handle and releases the matchers of its rule set. The
// caller must not use the handle afterwards, nor free it during waf_eval.
//
//export waf_free
func waf_free(h C.int64_t) {
	defer recoverCount()
	mu.Lock()
	w := wafs[int64(h)]
	delete(wafs, int64(h))
	mu.Unlock()
	if w != nil {
		w.Close()
	}
}

const (
	evalDone        = 0
	evalInterrupted = 1
	evalBudget      = 2
	evalError       = -1
)

// waf_eval inspects one request with the rule set h. Rule IDs (comma
// separated) and then the JSON array of matches are written to out; their
// lengths are reported in res. Returns 0 when every request phase ran, 1
// when a rule interrupted the request (SecRuleEngine On only), 2 when the
// budget ran out, or -1 with the reason in errbuf.
//
//export waf_eval
func waf_eval(h C.int64_t, req *C.waf_req_t, res *C.waf_res_t,
	out *C.char, outcap C.int, errbuf *C.char, errcap C.int) (rc C.int) {
	defer recoverErr(errbuf, errcap, &rc)

	mu.Lock()
	w := wafs[int64(h)]
	mu.Unlock()
	if w == nil {
		writeErr(errbuf, errcap, "unknown rule set handle")
		return evalError
	}

	var buf []byte
	if out != nil && outcap > 0 {
		buf = unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outcap))
	}
	r, err := w.Eval(toRequest(req), buf)
	if err != nil {
		writeErr(errbuf, errcap, err.Error())
		return evalError
	}
	res.interrupt_rule_id = C.int(r.InterruptRuleID)
	res.would_interrupt_rule_id = C.int(r.WouldInterruptRuleID)
	res.matched = C.int(r.Matched)
	res.anomaly_score = C.int(r.AnomalyScore)
	res.args_limit_reached = boolInt(r.ArgsLimitReached)
	res.budget_phase = C.int(r.BudgetPhase)
	res.elapsed_us = C.int64_t(r.Elapsed.Microseconds())
	res.rule_ids_len = C.int(r.RuleIDsLen)
	res.matches_len = C.int(r.MatchesLen)
	switch r.Status {
	case waf.Interrupted:
		return evalInterrupted
	case waf.BudgetExhausted:
		return evalBudget
	}
	return evalDone
}

func boolInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

func toRequest(req *C.waf_req_t) *waf.Request {
	r := &waf.Request{
		Method:         goString(req.method, req.method_len),
		URI:            goString(req.uri, req.uri_len),
		Protocol:       goString(req.protocol, req.protocol_len),
		ClientIP:       goString(req.client_ip, req.client_ip_len),
		ClientPort:     int(req.client_port),
		ServerIP:       goString(req.server_ip, req.server_ip_len),
		ServerPort:     int(req.server_port),
		ServerName:     goString(req.server_name, req.server_name_len),
		TxID:           goString(req.tx_id, req.tx_id_len),
		LogMatchedData: req.log_matched_data != 0,
		Budget:         time.Duration(req.budget_us) * time.Microsecond,
	}
	if n := int(req.header_count); n > 0 {
		names := unsafe.Slice(req.header_names, n)
		nameLens := unsafe.Slice(req.header_name_lens, n)
		values := unsafe.Slice(req.header_values, n)
		valueLens := unsafe.Slice(req.header_value_lens, n)
		r.Headers = make([][2]string, n)
		for i := 0; i < n; i++ {
			r.Headers[i] = [2]string{
				goString(names[i], C.int(nameLens[i])),
				goString(values[i], C.int(valueLens[i])),
			}
		}
	}
	if req.body != nil && req.body_len > 0 {
		// WriteRequestBody copies it, so the Lua string only has to outlive
		// this call
		r.Body = unsafe.Slice((*byte)(unsafe.Pointer(req.body)), int(req.body_len))
	}
	return r
}

// order of the counters written by rt_stats
var statMetrics = []string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/total:bytes",
	"/gc/cycles/total:gc-cycles",
	"/sched/goroutines:goroutines",
	"/sched/gomaxprocs:threads",
}

// rt_stats writes up to n counters to out, in this order: Go heap objects
// bytes, memory mapped by the Go runtime, GC cycles, goroutines, GOMAXPROCS,
// OS threads of the process, threads whose CPU affinity differs from the
// main thread (-1 when unknown), live rule sets, rule sets being built,
// recovered panics, transactions that failed to close.
//
//export rt_stats
func rt_stats(out *C.int64_t, n C.int) {
	defer recoverCount()
	if out == nil || n <= 0 {
		return
	}
	samples := make([]metrics.Sample, len(statMetrics))
	for i, name := range statMetrics {
		samples[i].Name = name
	}
	metrics.Read(samples)
	vals := make([]int64, 0, 11)
	for _, s := range samples {
		if s.Value.Kind() == metrics.KindUint64 {
			vals = append(vals, int64(s.Value.Uint64()))
		} else {
			vals = append(vals, -1)
		}
	}
	threads, mismatched := threadAffinity()
	mu.Lock()
	live := int64(len(wafs))
	mu.Unlock()
	vals = append(vals, threads, mismatched, live, building.Load(),
		panics.Load()+waf.Panics(), waf.CloseErrors())

	s := unsafe.Slice(out, int(n))
	for i := range s {
		if i < len(vals) {
			s[i] = C.int64_t(vals[i])
		} else {
			s[i] = -1
		}
	}
}

// threadAffinity returns the number of threads of the process and how many
// of them have a CPU affinity other than the main thread's, -1 when unknown.
func threadAffinity() (int64, int64) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return -1, -1
	}
	var main unix.CPUSet
	if err := unix.SchedGetaffinity(os.Getpid(), &main); err != nil {
		return int64(len(entries)), -1
	}
	var mismatched int64
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		var set unix.CPUSet
		if err := unix.SchedGetaffinity(tid, &set); err != nil {
			// the thread exited after ReadDir
			if errors.Is(err, unix.ESRCH) {
				continue
			}
			return int64(len(entries)), -1
		}
		if set != main {
			mismatched++
		}
	}
	return int64(len(entries)), mismatched
}

func main() {}
