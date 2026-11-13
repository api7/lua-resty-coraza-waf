use t::Coraza 'no_plan';

run_tests();

__DATA__

=== TEST 1: headers keep every value, in a list
--- config
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local headers, truncated = request.get_headers()
            local seen = {}
            for _, h in ipairs(headers) do
                if h[1]:lower() == "x-a" then
                    seen[#seen + 1] = h[2]
                end
            end
            table.sort(seen)
            ngx.say("x-a: ", table.concat(seen, ","))
            ngx.say("truncated: ", truncated)
        }
    }
--- more_headers
X-A: 1
X-A: 2
--- response_body
x-a: 1,2
truncated: false



=== TEST 2: headers past max_headers are reported
--- config
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local headers, truncated = request.get_headers(2)
            ngx.say("count: ", #headers, ", truncated: ", truncated)
        }
    }
--- more_headers
X-A: 1
X-B: 2
X-C: 3
--- response_body
count: 2, truncated: true



=== TEST 3: HTTP/2 has no Host header; it is added from $host
--- http2
--- config
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local headers = request.get_headers()
            local hosts = 0
            for _, h in ipairs(headers) do
                if h[1]:lower() == "host" then
                    hosts = hosts + 1
                    ngx.say("host: ", h[2])
                end
            end
            ngx.say("host headers: ", hosts)
        }
    }
--- response_body
host: localhost
host headers: 1



=== TEST 4: body states
--- config
    location /body {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local allowed = request.media_type_matcher({
                "application/json", "application/*+json",
                "application/x-www-form-urlencoded", "multipart/form-data",
            })
            local body, state = request.read_body({
                max_size = 16,
                media_type_allowed = allowed,
            })
            ngx.say(state, " ", body and #body or "-")
        }
    }
    location /t {
        content_by_lua_block {
            local cases = {
                { "GET, no body", "GET", nil, {} },
                { "json", "POST", '{"a":1}',
                  { ["Content-Type"] = "application/json; charset=utf-8" } },
                { "vendor json", "POST", '{"a":1}',
                  { ["Content-Type"] = "application/vnd.api+json" } },
                { "type not allowed", "POST", "<a/>",
                  { ["Content-Type"] = "text/xml" } },
                { "no type", "POST", "abc", {} },
                { "gzip", "POST", "abc",
                  { ["Content-Type"] = "application/json", ["Content-Encoding"] = "gzip" } },
                { "json over max_size", "POST", '{"a":"0123456789abcdef"}',
                  { ["Content-Type"] = "application/json" } },
                { "form over max_size", "POST", "a=0123456789abcdef",
                  { ["Content-Type"] = "application/x-www-form-urlencoded" } },
                { "empty", "POST", "",
                  { ["Content-Type"] = "application/json" } },
            }
            local raw_http = require("raw_http")
            for _, c in ipairs(cases) do
                ngx.print(c[1], ": ", raw_http.request(c[2], "/body", c[4], c[3]))
            end
        }
    }
--- response_body
GET, no body: none -
json: inspected 7
vendor json: inspected 7
type not allowed: skipped_type -
no type: skipped_type -
gzip: skipped_encoding -
json over max_size: skipped_oversize -
form over max_size: truncated 16
empty: none -



=== TEST 5: a body spooled to a file is read up to max_size + 1 bytes
--- config
    client_body_buffer_size 1k;
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local body, state = request.read_body({ max_size = 4096 })
            ngx.say("in file: ", ngx.req.get_body_file() ~= nil)
            ngx.say(state, " ", body and #body or "-")
        }
    }
--- request eval
"POST /t\n" . ("a=" . ("x" x 9000))
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- response_body
in file: true
truncated 4096



=== TEST 6: an HTTP/2 body without Content-Length is read
--- http2
--- config
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local body, state = request.read_body({ max_size = 1024 })
            ngx.say(state, " ", body)
        }
    }
--- request
POST /t
a=1
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- response_body
inspected a=1



=== TEST 7: media types a cut body cannot be parsed for
--- config
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            for _, t in ipairs({
                "multipart/form-data", "multipart/mixed", "application/json",
                "text/json", "application/xml", "text/xml", "application/vnd.api+json",
                "application/atom+xml", "application/x-www-form-urlencoded",
                "text/plain",
            }) do
                ngx.say(t, ": ", request.can_truncate(t))
            end
        }
    }
--- response_body
multipart/form-data: false
multipart/mixed: false
application/json: false
text/json: false
application/xml: false
text/xml: false
application/vnd.api+json: false
application/atom+xml: false
application/x-www-form-urlencoded: true
text/plain: true



=== TEST 8: a request read with resty.coraza.request is inspected
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local request = require("resty.coraza.request")
            local crs = require("crs")

            local rs = assert(coraza.rule_set(crs.directives()))
            local headers = request.get_headers()
            local body, state = request.read_body({ max_size = 1024 })
            local res = assert(coraza.eval(rs, {
                method = ngx.req.get_method(),
                uri = ngx.var.request_uri,
                protocol = ngx.var.server_protocol,
                client_ip = ngx.var.remote_addr,
                client_port = tonumber(ngx.var.remote_port),
                server_name = ngx.var.host,
                headers = headers,
                body = body,
            }))
            ngx.say("body: ", state)
            ngx.say("rule ids: ", res.rule_ids)
        }
    }
--- request
POST /t
id=1' OR '1'='1
--- more_headers
Content-Type: application/x-www-form-urlencoded
User-Agent: curl/8.5.0
Accept: */*
--- response_body
body: inspected
rule ids: 942100,949110
