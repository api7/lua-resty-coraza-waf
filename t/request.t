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
                { "no type over max_size", "POST", '{"a":"0123456789abcdef"}', {} },
                { "gzip", "POST", "abc",
                  { ["Content-Type"] = "application/json", ["Content-Encoding"] = "gzip" } },
                { "gzip in a list", "POST", "abc",
                  { ["Content-Type"] = "application/json",
                    ["Content-Encoding"] = "identity, GZIP" } },
                { "unknown encoding", "POST", "abc",
                  { ["Content-Type"] = "application/json", ["Content-Encoding"] = "foo" } },
                { "identity", "POST", "abc",
                  { ["Content-Type"] = "application/json", ["Content-Encoding"] = "identity" } },
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
no type: inspected 3
no type over max_size: truncated 16
gzip: skipped_encoding -
gzip in a list: skipped_encoding -
unknown encoding: inspected 3
identity: inspected 3
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
            ngx.say("interrupted: ", res.interrupted, ", would interrupt: ",
                    res.would_interrupt_rule_id)
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
interrupted: false, would interrupt: 949110



=== TEST 9: the values of a repeated header keep their arrival order
--- config
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local values = {}
            for _, h in ipairs(request.get_headers()) do
                if h[1] == "content-type" then
                    values[#values + 1] = h[2]
                end
            end
            ngx.say(table.concat(values, " | "))
        }
    }
--- more_headers
Content-Type: application/x-www-form-urlencoded
content-type: text/plain
--- response_body
application/x-www-form-urlencoded | text/plain



=== TEST 10: an HTTP/1.0 request without Host gets none
--- config
    location /t {
        content_by_lua_block {
            local request = require("resty.coraza.request")
            local hosts = 0
            for _, h in ipairs(request.get_headers()) do
                if h[1]:lower() == "host" then
                    hosts = hosts + 1
                end
            end
            ngx.say("host headers: ", hosts)
        }
    }
--- raw_request eval
"GET /t HTTP/1.0\r\n\r\n"
--- response_body
host headers: 0



=== TEST 11: a body without Content-Type is inspected, as CRS parses it as URLENCODED
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local request = require("resty.coraza.request")
            local crs = require("crs")

            local rs = assert(coraza.rule_set(crs.directives()))
            local body, state = request.read_body({
                max_size = 1024,
                media_type_allowed = request.media_type_matcher({ "application/json" }),
            })
            local res = assert(coraza.eval(rs, {
                method = ngx.req.get_method(),
                uri = ngx.var.request_uri,
                protocol = ngx.var.server_protocol,
                client_ip = ngx.var.remote_addr,
                client_port = tonumber(ngx.var.remote_port),
                server_name = ngx.var.host,
                headers = request.get_headers(),
                body = body,
            }))
            ngx.say("body: ", state)
            ngx.say("rule ids: ", res.rule_ids)
        }
    }
--- request
POST /t
{"q": "<script>alert(1)</script>"}
--- more_headers
User-Agent: curl/8.5.0
Accept: */*
--- response_body
body: inspected
rule ids: 920340,941100,941110,941160,941390,949110



=== TEST 12: an HTTP/2 request without Content-Type
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
--- response_body
inspected a=1



=== TEST 13: an HTTP/2 request without Content-Type and body
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
--- response_body
none nil
