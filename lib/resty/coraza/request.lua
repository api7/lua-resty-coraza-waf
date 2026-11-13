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

-- Reads the headers and the body of the current nginx request in the form
-- resty.coraza eval takes.
local ngx = ngx
local ngx_var = ngx.var
local req_get_headers = ngx.req.get_headers
local req_read_body = ngx.req.read_body
local req_get_body_data = ngx.req.get_body_data
local req_get_body_file = ngx.req.get_body_file
local ipairs = ipairs
local pairs = pairs
local type = type
local tonumber = tonumber
local io_open = io.open
local str_find = string.find
local str_gsub = string.gsub
local str_lower = string.lower
local str_match = string.match
local str_sub = string.sub

local DEFAULT_MAX_HEADERS = 100

local _M = {}


-- Returns the request headers as { {name, value}, ... }, one entry per value,
-- and whether more than max_headers (default 100) were sent. HTTP/2 carries
-- the host in :authority, so Host is added from $host when it is missing.
function _M.get_headers(max_headers)
    local raw, truncated = req_get_headers(max_headers or DEFAULT_MAX_HEADERS, true)
    local headers = {}
    local has_host = false
    for name, value in pairs(raw) do
        if type(value) == "table" then
            for _, v in ipairs(value) do
                headers[#headers + 1] = { name, v }
            end
        else
            headers[#headers + 1] = { name, value }
        end
        if not has_host and str_lower(name) == "host" then
            has_host = true
        end
    end

    if not has_host and ngx_var.host then
        headers[#headers + 1] = { "Host", ngx_var.host }
    end
    return headers, truncated == "truncated"
end


-- Coraza fails to parse a cut multipart, JSON or XML body, so only the
-- other types can be inspected up to a size limit.
function _M.can_truncate(media_type)
    if str_sub(media_type, 1, 10) == "multipart/" then
        return false
    end
    local subtype = str_match(media_type, "/(.+)$") or ""
    if subtype == "json" or subtype == "xml"
       or str_sub(subtype, -5) == "+json"
       or str_sub(subtype, -4) == "+xml" then
        return false
    end
    return true
end


-- Compiles media type patterns ("application/json", "application/*+json")
-- into a function telling whether a lower case media type matches one.
function _M.media_type_matcher(patterns)
    local exact = {}
    local wildcard = {}
    for _, p in ipairs(patterns) do
        p = str_lower(p)
        if str_find(p, "*", 1, true) then
            local escaped = str_gsub(p, "[%^%$%(%)%%%.%[%]%+%-%?]", "%%%0")
            wildcard[#wildcard + 1] = "^" .. str_gsub(escaped, "%*", "[^/]*") .. "$"
        else
            exact[p] = true
        end
    end

    return function(media_type)
        if exact[media_type] then
            return true
        end
        for _, w in ipairs(wildcard) do
            if str_match(media_type, w) then
                return true
            end
        end
        return false
    end
end


local function read_file_prefix(path, n)
    local f, err = io_open(path, "rb")
    if not f then
        return nil, nil, err
    end
    local size = f:seek("end")
    f:seek("set", 0)
    local data = f:read(n)
    f:close()
    return data or "", size
end


-- Reads the request body to inspect. Returns the body or nil, and the state:
--   "none"              no body
--   "skipped_type"      no media type, or one media_type_allowed rejects
--   "skipped_encoding"  a Content-Encoding other than identity
--   "skipped_oversize"  over max_size and of a type that cannot be cut
--   "inspected"         the whole body is returned
--   "truncated"         the first max_size bytes are returned
--
-- opts:
--   max_size            bytes to inspect at most (required)
--   media_type_allowed  function(media_type) -> boolean, default all types
--
-- A body spooled to a file is read up to max_size + 1 bytes only.
function _M.read_body(opts)
    local max_size = opts.max_size
    local allowed = opts.media_type_allowed

    local len = tonumber(ngx_var.http_content_length)
    if len == 0 then
        return nil, "none"
    end
    local length_known = len ~= nil
    if not length_known and not ngx_var.http_transfer_encoding
       and ngx.req.http_version() < 2 then
        return nil, "none"
    end

    local content_type = ngx_var.http_content_type
    local media_type = content_type
                       and str_lower(str_match(content_type, "^%s*([^;%s]+)") or "")
    if not media_type or media_type == "" then
        -- an HTTP/2 request carries no length up front, so look before
        -- reporting a body that may not exist
        if not length_known then
            req_read_body()
            if not req_get_body_data() and not req_get_body_file() then
                return nil, "none"
            end
        end
        return nil, "skipped_type"
    end

    if allowed and not allowed(media_type) then
        return nil, "skipped_type"
    end

    local encoding = ngx_var.http_content_encoding
    if encoding and str_lower(encoding) ~= "identity" then
        return nil, "skipped_encoding"
    end

    local truncatable = _M.can_truncate(media_type)
    if length_known and len > max_size and not truncatable then
        return nil, "skipped_oversize"
    end

    req_read_body()
    local data = req_get_body_data()
    local size
    if data then
        size = #data
    else
        local file = req_get_body_file()
        if not file then
            return nil, "none"
        end
        local err
        data, size, err = read_file_prefix(file, max_size + 1)
        if not data then
            ngx.log(ngx.ERR, "coraza: failed to read the request body file: ", err)
            return nil, "none"
        end
    end

    if size == 0 then
        return nil, "none"
    end
    if size <= max_size then
        return data, "inspected"
    end
    if truncatable then
        return str_sub(data, 1, max_size), "truncated"
    end
    return nil, "skipped_oversize"
end


return _M
