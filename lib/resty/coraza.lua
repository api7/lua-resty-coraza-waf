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
local ffi_string = ffi.string
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local package = package
local io_open = io.open
local tonumber = tonumber
local tostring = tostring
local pcall = pcall
local str_gmatch = string.gmatch
local str_gsub = string.gsub

local LIBRARY_NAME = "coraza_waf"
local ERRCAP = 512
local OUTCAP = 16384

if not pcall(ffi.typeof, "cwaf_request_t") then
    ffi.cdef[[
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

    int64_t cwaf_build_start(const char *dirs, int dlen);
    int64_t cwaf_build_poll(int64_t job, char *errbuf, int errcap);
    void    cwaf_free(int64_t h);
    int     cwaf_eval(int64_t h, cwaf_request_t *req, cwaf_result_t *res,
                      char *out, int outcap, char *errbuf, int errcap);
    void    cwaf_stats(int64_t *out);
    ]]
end

local lib
local errbuf = ffi_new("char[?]", ERRCAP)
local outbuf = ffi_new("char[?]", OUTCAP)
local req_t = ffi_new("cwaf_request_t")
local res_t = ffi_new("cwaf_result_t")
local headers_cap = 0
local h_names, h_name_lens, h_values, h_value_lens


local _M = { version = "0.1.0" }


local function find_library()
    for dir in str_gmatch(package.cpath, "[^;]+") do
        local path = str_gsub(dir, "%?", LIBRARY_NAME, 1)
        local f = io_open(path, "rb")
        if f then
            f:close()
            return path
        end
    end
end


-- Loads the library from path, or from package.cpath when path is nil.
-- Loading twice returns the library loaded first.
function _M.load(path)
    if lib then
        return true
    end

    path = path or find_library()
    if not path then
        return nil, LIBRARY_NAME .. " is not found in package.cpath"
    end

    local ok, l = pcall(ffi.load, path)
    if not ok then
        return nil, "failed to load " .. path .. ": " .. tostring(l)
    end
    lib = l
    return true
end


function _M.loaded()
    return lib ~= nil
end


-- Starts building a rule set from SecLang directives on a Go goroutine.
-- Returns a job id to pass to build_poll.
function _M.build_start(directives)
    local job = lib.cwaf_build_start(directives, #directives)
    if job <= 0 then
        return nil, "failed to start building the rule set"
    end
    return job
end


-- Returns false while the job is running, the rule set when it is built, or
-- nil and the error when the directives are invalid. The rule set is freed
-- when it is garbage collected; on_free, if given, is called at that point.
function _M.build_poll(job, on_free)
    local h = lib.cwaf_build_poll(job, errbuf, ERRCAP)
    if h == 0 then
        return false
    end
    if h < 0 then
        return nil, ffi_string(errbuf)
    end

    local box = ffi_gc(ffi_new("int64_t[1]", h), function(b)
        lib.cwaf_free(b[0])
        if on_free then
            on_free()
        end
    end)
    return { handle = h, box = box }
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


-- Inspects one request: phases 1 and 2 and logging; the rule set is used in
-- DetectionOnly mode, so nothing is blocked here. req fields: method, uri,
-- protocol, client_ip, client_port, server_ip, server_port, server_name,
-- tx_id, headers ({{name, value}, ...}), body, log_matched_data.
function _M.eval(rule_set, req)
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

    local rc = lib.cwaf_eval(rule_set.handle, req_t, res_t, outbuf, OUTCAP,
                             errbuf, ERRCAP)

    -- do not keep pointers to request strings past this call
    req_t.method, req_t.uri, req_t.protocol = nil, nil, nil
    req_t.client_ip, req_t.server_ip, req_t.server_name = nil, nil, nil
    req_t.tx_id, req_t.body = nil, nil
    for i = 0, n - 1 do
        h_names[i] = nil
        h_values[i] = nil
    end

    if rc ~= 0 then
        return nil, ffi_string(errbuf)
    end

    local ids_len = res_t.rule_ids_len
    local matches_len = res_t.matches_len
    return {
        interrupted = res_t.interrupted ~= 0,
        interrupt_rule_id = res_t.interrupt_rule_id,
        matched = res_t.matched,
        anomaly_score = res_t.anomaly_score,
        args_limit_reached = res_t.args_limit_reached ~= 0,
        rule_ids = ids_len > 0 and ffi_string(outbuf, ids_len) or nil,
        matches = matches_len > 0 and ffi_string(outbuf + ids_len, matches_len) or nil,
    }
end


-- Process wide counters of the Go side.
function _M.stats()
    local out = ffi_new("int64_t[3]")
    lib.cwaf_stats(out)
    return {
        rule_sets = tonumber(out[0]),
        building = tonumber(out[1]),
        panics = tonumber(out[2]),
    }
end


return _M
