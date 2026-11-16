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
local str_gmatch = string.gmatch
local str_gsub = string.gsub
local str_lower = string.lower
local str_match = string.match
local str_sub = string.sub

local DEFAULT_MAX_HEADERS = 100
-- type "/" subtype, with the token characters of RFC 9110
local MEDIA_TYPE = "^[a-z0-9!#$%%&'*+.^_`|~-]+/[a-z0-9!#$%%&'*+.^_`|~-]+$"

local _M = {}


-- Returns the request headers as { {name, value}, ... }, one entry per value
-- with the values of a name in arrival order (names are lower case), and
-- whether more than max_headers (default 100) were sent. HTTP/2 and HTTP/3
-- carry the host in :authority, so Host is added from $host when it is
-- missing there; an HTTP/1 request without Host is passed as it came.
function _M.get_headers(max_headers)
    local raw, truncated = req_get_headers(max_headers or DEFAULT_MAX_HEADERS)
    local headers = {}
    for name, value in pairs(raw) do
        if type(value) == "table" then
            for _, v in ipairs(value) do
                headers[#headers + 1] = { name, v }
            end
        else
            headers[#headers + 1] = { name, value }
        end
    end

    if raw.host == nil and ngx.req.http_version() >= 2 and ngx_var.host then
        headers[#headers + 1] = { "host", ngx_var.host }
    end
    return headers, truncated == "truncated"
end


-- Media types Coraza fails to parse cut: multipart, and the types the JSON
-- and XML parsers are picked for, by prefix, in coraza.conf-recommended
-- (rules 200000, 200001 and 200006), or by suffix.
local NOT_TRUNCATABLE = {
    "^multipart/", "^application/json", "^application/xml",
    "^application/soap%+xml", "^text/xml", "^application/[a-z0-9.-]+%+json",
    "/json$", "/xml$", "%+json$", "%+xml$",
}

function _M.can_truncate(media_type)
    for _, p in ipairs(NOT_TRUNCATABLE) do
        if str_find(media_type, p) then
            return false
        end
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


-- codings that turn the body into bytes no rule can match
local COMPRESSED = {
    gzip = true, ["x-gzip"] = true, deflate = true, br = true,
    compress = true, ["x-compress"] = true, zstd = true,
}

local function is_compressed(encoding)
    for coding in str_gmatch(str_lower(encoding), "[^,%s]+") do
        if COMPRESSED[coding] then
            return true
        end
    end
    return false
end


local function read_file_prefix(path, n)
    local f, err = io_open(path, "rb")
    if not f then
        return nil, nil, err
    end
    local size
    size, err = f:seek("end")
    local data
    if size and size > 0 then
        f:seek("set", 0)
        data, err = f:read(n)
    end
    f:close()
    if not size or size > 0 and not data then
        return nil, nil, err or "empty read"
    end
    return data or "", size
end


-- Whether a Content-Type is a media type followed by nothing or by
-- parameters. A comma, which only a quoted parameter value may hold, is taken
-- as repeated headers joined by nginx.
local function well_formed(media_type, params)
    return str_find(media_type, MEDIA_TYPE) ~= nil
           and not str_find(params, ",", 1, true)
           and (str_find(params, "^%s*;") or str_find(params, "^%s*$")) ~= nil
end


-- Reads the request body to inspect. Returns the body or nil, the state and,
-- for "error", the error:
--   "none"              no body
--   "skipped_type"      a media type media_type_allowed rejects
--   "skipped_encoding"  a compressed Content-Encoding (gzip, br, ...)
--   "skipped_oversize"  over max_size and of a type that cannot be cut
--   "inspected"         the whole body is returned
--   "truncated"         the first max_size bytes are returned
--   "error"             the body spooled to a file could not be read
--
-- opts:
--   max_size            bytes to inspect at most (required)
--   media_type_allowed  function(media_type) -> boolean, default all types
--
-- A body without a media type, or with a malformed Content-Type, is
-- inspected whatever media_type_allowed says: CRS parses it as URLENCODED
-- (rule 901340) and many backends parse it as JSON. Repeated Content-Type
-- headers, which nginx joins with commas, are malformed. An unknown
-- Content-Encoding is inspected as it came, as a backend that does not know
-- it is likely to do the same.
--
-- A body without a length (chunked, or HTTP/2 without Content-Length) is
-- read before it is skipped, as only reading tells whether there is one. A
-- body spooled to a file is read up to max_size + 1 bytes only.
function _M.read_body(opts)
    local max_size = opts.max_size
    local allowed = opts.media_type_allowed

    local len = tonumber(ngx_var.http_content_length)
    if len == 0 then
        return nil, "none"
    end
    if not len then
        if not ngx_var.http_transfer_encoding and ngx.req.http_version() < 2 then
            return nil, "none"
        end
        req_read_body()
        if not req_get_body_data() and not req_get_body_file() then
            return nil, "none"
        end
    end

    local media_type, params = "", ""
    local content_type = ngx_var.http_content_type
    if content_type then
        media_type, params = str_match(content_type, "^%s*([^;%s]*)(.*)$")
        media_type = str_lower(media_type)
    end
    local truncatable
    if media_type == "" and params == "" then
        truncatable = true
    elseif not well_formed(media_type, params) then
        -- the parser Coraza picks for it is unknown
        truncatable = false
    else
        if allowed and not allowed(media_type) then
            return nil, "skipped_type"
        end
        truncatable = _M.can_truncate(media_type)
    end

    local encoding = ngx_var.http_content_encoding
    if encoding and is_compressed(encoding) then
        return nil, "skipped_encoding"
    end

    if len and len > max_size and not truncatable then
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
            return nil, "error", "failed to read the request body file: " .. err
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
