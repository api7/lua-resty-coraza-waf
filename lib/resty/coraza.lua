--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

-- LuaJIT FFI binding of coraza_waf.so.
--
-- The Go runtime does not survive fork: load the library after fork, in the
-- processes that use it (for example in init_worker of HTTP workers).
local ffi = require("ffi")
local ngx = ngx
local ffi_string = ffi.string
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local package = package
local tonumber = tonumber
local tostring = tostring
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local next = next
local str_find = string.find
local collectgarbage = collectgarbage

local LIBRARY_NAME = "coraza_waf"
local ABI_VERSION = 1
local ERRCAP = 512
local OUTCAP = 16384
local POLL_INTERVAL = 0.002
local FULL_GC_INTERVAL = 10
-- order of the counters written by rt_stats
local STATS = {
    "heap_bytes", "runtime_bytes", "gc_cycles", "goroutines", "max_procs",
    "threads", "affinity_mismatch", "rule_sets", "building", "panics",
    "close_errors",
}

if not pcall(ffi.typeof, "waf_req_t") then
    ffi.cdef[[
    typedef struct {
        int     max_procs;
        int     set_gc_percent;
        int     gc_percent;
        int64_t memory_limit;
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
        int64_t      budget_us;
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

    int     rt_abi_version(void);
    int     rt_init(const rt_config_t *cfg, char *errbuf, int errcap);
    void    rt_stats(int64_t *out, int n);
    int64_t waf_new(const char *dirs, int dlen, waf_build_info_t *info,
                    char *errbuf, int errcap);
    int64_t waf_build_start(const char *dirs, int dlen);
    int64_t waf_build_poll(int64_t job, waf_build_info_t *info,
                           char *errbuf, int errcap);
    void    waf_free(int64_t h);
    int     waf_eval(int64_t h, const waf_req_t *req, waf_res_t *res,
                     char *out, int outcap, char *errbuf, int errcap);
    ]]
end

local lib
local errbuf = ffi_new("char[?]", ERRCAP)
local outbuf = ffi_new("char[?]", OUTCAP)
local req_t = ffi_new("waf_req_t")
local res_t = ffi_new("waf_res_t")
local info_t = ffi_new("waf_build_info_t")
local headers_cap = 0
local h_names, h_name_lens, h_values, h_value_lens

-- return codes of waf_eval
local STATUS = { [0] = "done", [1] = "interrupted", [2] = "budget" }

-- rule sets of this Lua VM
local state = {
    -- rule sets alive or being built through new()
    count = 0,
    -- directives -> rule set being built on a goroutine
    tasks = {},
    polling = false,
    last_full_gc = 0,
}


local _M = { version = "0.1.0" }


local function log_warn(...)
    if ngx and ngx.log then
        ngx.log(ngx.WARN, ...)
    end
end


-- Applies Go runtime settings: max_procs (GOMAXPROCS; setting it stops Go
-- from adjusting it on its own), gc_percent (GOGC, a number or "off") and
-- memory_limit (GOMEMLIMIT, bytes). Unset fields keep the current value.
function _M.init_runtime(opts)
    local cfg = ffi_new("rt_config_t")
    cfg.max_procs = opts.max_procs or 0
    if opts.gc_percent ~= nil then
        cfg.set_gc_percent = 1
        cfg.gc_percent = opts.gc_percent == "off" and -1 or opts.gc_percent
    end
    cfg.memory_limit = opts.memory_limit or 0
    if lib.rt_init(cfg, errbuf, ERRCAP) ~= 0 then
        return nil, ffi_string(errbuf)
    end
    return true
end


-- Loads the library from path, or from package.cpath when path is nil,
-- checks that it matches this module and waits for the Go runtime to start.
-- runtime, if given, is passed to init_runtime. Loading twice keeps the
-- library loaded first and applies runtime again.
function _M.load(path, runtime)
    if not lib then
        if not path then
            path = package.searchpath(LIBRARY_NAME, package.cpath)
            if not path then
                return nil, LIBRARY_NAME .. " is not found in package.cpath"
            end
            -- ffi.load takes a name without "/" as a library to look up
            if not str_find(path, "/", 1, true) then
                path = "./" .. path
            end
        end

        local ok, l = pcall(ffi.load, path)
        if not ok then
            return nil, "failed to load " .. path .. ": " .. tostring(l)
        end

        -- the first call into the library waits for the Go runtime to
        -- finish initializing (about 0.1s); take that wait here rather than
        -- in the first request
        local found, abi = pcall(function() return l.rt_abi_version() end)
        if not found then
            return nil, path .. " is not a coraza_waf library: " .. tostring(abi)
        end
        if abi ~= ABI_VERSION then
            return nil, path .. " has ABI version " .. tostring(abi)
                        .. ", this module needs " .. ABI_VERSION
        end
        lib = l
    end

    if runtime then
        local ok, err = _M.init_runtime(runtime)
        if not ok then
            return nil, err
        end
    end

    local mismatch = _M.stats().affinity_mismatch
    if mismatch > 0 then
        log_warn(mismatch, " threads of this process have a CPU affinity",
                 " other than its main thread")
    end
    return true
end


function _M.loaded()
    return lib ~= nil
end


local function release()
    state.count = state.count - 1
end


-- Turns waf into a ready rule set with handle h and the build information
-- in info_t. The rule set is freed when waf is collected.
local function wrap(waf, h)
    waf.state = "ready"
    waf.handle = h
    waf.build_time = tonumber(info_t.duration_us) / 1e6
    waf.rules = info_t.rules
    waf.box = ffi_gc(ffi_new("int64_t[1]", h), function(b)
        lib.waf_free(b[0])
        release()
    end)
    return waf
end


-- Low level: starts building on a goroutine and returns the job id.
function _M.build_start(directives)
    local job = lib.waf_build_start(directives, #directives)
    if job <= 0 then
        return nil, "failed to start building the rule set"
    end
    return job
end


-- Low level: returns false while the job runs, the handle once built, or
-- nil and the error. A finished job is reported once.
function _M.build_poll(job)
    local h = lib.waf_build_poll(job, info_t, errbuf, ERRCAP)
    if h == 0 then
        return false
    end
    if h < 0 then
        return nil, ffi_string(errbuf)
    end
    return h
end


local function poll_tasks(premature)
    if premature then
        state.polling = false
        return
    end
    while next(state.tasks) do
        for directives, waf in pairs(state.tasks) do
            local h, err = _M.build_poll(waf.job)
            if h ~= false then
                state.tasks[directives] = nil
                waf.job = nil
                if h then
                    wrap(waf, h)
                else
                    waf.state = "failed"
                    waf.err = err
                    release()
                end
                if waf.waiters > 0 then
                    waf.sema:post(waf.waiters)
                end
            end
        end
        if next(state.tasks) then
            ngx.sleep(POLL_INTERVAL)
        end
    end
    state.polling = false
end


local function start_polling()
    if state.polling then
        return true
    end
    local ok, err = ngx.timer.at(0, poll_tasks)
    if not ok then
        return nil, err
    end
    state.polling = true
    return true
end


local function check_limit(max)
    if not max or state.count < max then
        return true
    end
    -- rule sets that nobody references are only freed once Lua collects
    -- them
    local now = ngx and ngx.now() or 0
    if now - state.last_full_gc >= FULL_GC_INTERVAL then
        state.last_full_gc = now
        collectgarbage("collect")
    end
    return state.count < max
end


local function result_of(waf)
    if waf.state == "ready" then
        return waf
    end
    return nil, "invalid", waf.err
end


-- Waits for a rule set returned by new(directives, { async = true }) to be
-- built. Must be called where the request can yield. Returns the rule set,
-- or nil, a reason ("invalid", "timeout", "error") and a message. A timeout
-- does not cancel the build: the object becomes ready later.
function _M.wait(waf, timeout)
    if waf.state ~= "building" then
        return result_of(waf)
    end
    waf.waiters = waf.waiters + 1
    local ok, err = waf.sema:wait(timeout or 60)
    waf.waiters = waf.waiters - 1
    if not ok and waf.state == "building" then
        if err == "timeout" then
            return nil, "timeout", "timed out waiting for the rule set to build"
        end
        return nil, "error", err
    end
    return result_of(waf)
end


-- Builds a rule set from SecLang directives; see the README for the names
-- and rule IDs they must not use. The rule set is freed when the returned
-- object is garbage collected.
--
-- By default the build runs on the calling thread, which blocks the nginx
-- worker for the build time. opts:
--   async               build on a goroutine: the object is returned in the
--                       "building" state and eval returns "not_ready" until
--                       it is built. Calls with the same directives while it
--                       builds return the same object. Needs ngx timers.
--   wait                with async, wait for the build, see wait()
--   build_wait_timeout  seconds for wait, default 60
--   max_rule_sets       limit of the rule sets alive or being built through
--                       new() in this Lua VM
--
-- On failure returns nil, a reason and a message. Reasons:
--   "invalid"  the directives were rejected
--   "limit"    max_rule_sets rule sets are alive
--   "timeout"  the wait ended before the build
--   "error"    the build could not start
function _M.new(directives, opts)
    local async = opts and opts.async
    local max = opts and opts.max_rule_sets

    if not async then
        if not check_limit(max) then
            return nil, "limit", state.count .. " rule sets are alive"
        end
        local h = lib.waf_new(directives, #directives, info_t, errbuf, ERRCAP)
        if h < 0 then
            return nil, "invalid", ffi_string(errbuf)
        end
        state.count = state.count + 1
        return wrap({}, h)
    end

    local waf = state.tasks[directives]
    if not waf then
        if not check_limit(max) then
            return nil, "limit", state.count .. " rule sets are alive"
        end
        local job, err = _M.build_start(directives)
        if not job then
            return nil, "error", err
        end
        local semaphore = require("ngx.semaphore")
        waf = { state = "building", job = job, waiters = 0,
                sema = semaphore.new() }
        state.tasks[directives] = waf
        state.count = state.count + 1
    end

    local ok, err = start_polling()
    if not ok then
        return nil, "error", "failed to poll the build: " .. tostring(err)
    end

    if opts.wait then
        return _M.wait(waf, opts.build_wait_timeout)
    end
    return waf
end


local function ensure_header_cap(n)
    if n <= headers_cap then
        return
    end
    headers_cap = n
    h_names = ffi_new("const char *[?]", n)
    h_name_lens = ffi_new("int[?]", n)
    h_values = ffi_new("const char *[?]", n)
    h_value_lens = ffi_new("int[?]", n)
    req_t.header_names = h_names
    req_t.header_name_lens = h_name_lens
    req_t.header_values = h_values
    req_t.header_value_lens = h_value_lens
end


-- Inspects one request on the calling thread: phases 1 and 2, then logging.
-- Logging also runs when a phase fails, and then nil and the error are
-- returned. Returns nil and "not_ready" while an async build runs. Nothing
-- is blocked here, the caller acts on the result.
--
-- req fields: method, uri, protocol, client_ip, client_port, server_ip,
-- server_port, server_name, tx_id, headers ({{name, value}, ...}), body,
-- log_matched_data, budget (seconds for the request phases, none when
-- unset; see the README for where the inspection stops).
--
-- result.status is "done", "interrupted" (a rule interrupted the request;
-- SecRuleEngine On only) or "budget" (the budget ran out in
-- result.budget_phase and the remaining rules were skipped).
function _M.eval(waf, req)
    if waf.state ~= "ready" then
        if waf.state == "building" then
            return nil, "not_ready"
        end
        return nil, waf.err
    end

    local headers = req.headers or {}
    local n = #headers
    ensure_header_cap(n)
    for i = 1, n do
        local h = headers[i]
        h_names[i - 1] = h[1]
        h_name_lens[i - 1] = #h[1]
        h_values[i - 1] = h[2]
        h_value_lens[i - 1] = #h[2]
    end
    req_t.header_count = n

    local method = req.method or "GET"
    local uri = req.uri or "/"
    local protocol = req.protocol or "HTTP/1.1"
    local client_ip = req.client_ip or ""
    local server_ip = req.server_ip or ""
    local server_name = req.server_name or ""
    local tx_id = req.tx_id or ""
    local body = req.body or ""
    req_t.method, req_t.method_len = method, #method
    req_t.uri, req_t.uri_len = uri, #uri
    req_t.protocol, req_t.protocol_len = protocol, #protocol
    req_t.client_ip, req_t.client_ip_len = client_ip, #client_ip
    req_t.client_port = req.client_port or 0
    req_t.server_ip, req_t.server_ip_len = server_ip, #server_ip
    req_t.server_port = req.server_port or 0
    req_t.server_name, req_t.server_name_len = server_name, #server_name
    req_t.tx_id, req_t.tx_id_len = tx_id, #tx_id
    req_t.body, req_t.body_len = body, #body
    req_t.log_matched_data = req.log_matched_data and 1 or 0
    local budget = req.budget
    req_t.budget_us = (type(budget) == "number" and budget > 0)
                      and budget * 1e6 or 0

    local rc = lib.waf_eval(waf.handle, req_t, res_t, outbuf, OUTCAP,
                            errbuf, ERRCAP)

    -- do not keep pointers to request strings past this call
    req_t.method, req_t.uri, req_t.protocol = nil, nil, nil
    req_t.client_ip, req_t.server_ip, req_t.server_name = nil, nil, nil
    req_t.tx_id, req_t.body = nil, nil
    for i = 0, n - 1 do
        h_names[i] = nil
        h_values[i] = nil
    end

    local status = STATUS[rc]
    if not status then
        return nil, ffi_string(errbuf)
    end

    local ids_len = res_t.rule_ids_len
    local matches_len = res_t.matches_len
    return {
        status = status,
        interrupted = status == "interrupted",
        interrupt_rule_id = res_t.interrupt_rule_id,
        would_interrupt_rule_id = res_t.would_interrupt_rule_id,
        matched = res_t.matched,
        anomaly_score = res_t.anomaly_score,
        args_limit_reached = res_t.args_limit_reached ~= 0,
        budget_phase = res_t.budget_phase ~= 0 and res_t.budget_phase or nil,
        elapsed = tonumber(res_t.elapsed_us) / 1e6,
        rule_ids = ids_len > 0 and ffi_string(outbuf, ids_len) or nil,
        matches = matches_len > 0 and ffi_string(outbuf + ids_len, matches_len) or nil,
    }
end


-- Process wide counters of the Go runtime and the rule sets, named as in
-- STATS, plus held: the rule sets alive or being built through new() in this
-- Lua VM. threads and affinity_mismatch are -1 when they cannot be read.
function _M.stats()
    local out = ffi_new("int64_t[?]", #STATS)
    lib.rt_stats(out, #STATS)
    local s = { held = state.count }
    for i, name in ipairs(STATS) do
        s[name] = tonumber(out[i - 1])
    end
    return s
end


return _M
