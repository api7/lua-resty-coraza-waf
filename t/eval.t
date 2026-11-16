use t::Coraza 'no_plan';

run_tests();

__DATA__

=== TEST 1: a form body is inspected
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local read_request = require("read_request")

            local rs = assert(coraza.rule_set(crs.directives()))
            local res = assert(coraza.eval(rs, read_request()))
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
rule ids: 942100,949110,980170
interrupted: false, would interrupt: 949110



=== TEST 2: CRS parses a body without Content-Type as URLENCODED
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local read_request = require("read_request")

            local rs = assert(coraza.rule_set(crs.directives()))
            local res = assert(coraza.eval(rs, read_request()))
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
rule ids: 920340,920640,941100,941110,941160,941390,949110,980170



=== TEST 3: repeated Content-Type headers are flagged, and the body is inspected
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local read_request = require("read_request")

            local rs = assert(coraza.rule_set(crs.directives()))
            local res = assert(coraza.eval(rs, read_request()))
            ngx.say("920620: ", res.rule_ids:find("920620", 1, true) ~= nil)
            ngx.say("941100: ", res.rule_ids:find("941100", 1, true) ~= nil)
        }
    }
--- request
POST /t
{"q": "<script>alert(1)</script>"}
--- more_headers
Content-Type: application/json
Content-Type: application/json
User-Agent: curl/8.5.0
Accept: */*
--- response_body
920620: true
941100: true
