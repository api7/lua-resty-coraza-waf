use t::Coraza 'no_plan';

run_tests();

__DATA__

=== TEST 1: new builds on the calling thread and reports the build
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")

            local a = assert(coraza.new(crs.directives("# 1")))
            local b = assert(coraza.new(crs.directives("# 1")))
            ngx.say("state: ", a.state, ", same object: ", a == b)
            ngx.say("rules: ", a.rules > 600, ", build time: ", a.build_time > 0)
            local s = coraza.stats()
            ngx.say("held: ", s.held, ", go rule sets: ", s.rule_sets)
        }
    }
--- response_body
state: ready, same object: false
rules: true, build time: true
held: 2, go rule sets: 2



=== TEST 2: a rule set nobody references is freed
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")

            local rs = assert(coraza.new(crs.directives("# 2")))
            ngx.say("held: ", coraza.stats().held)
            rs = nil  -- luacheck: ignore 311
            collectgarbage("collect")
            local s = coraza.stats()
            ngx.say("held: ", s.held, ", go rule sets: ", s.rule_sets)
        }
    }
--- response_body
held: 1
held: 0, go rule sets: 0



=== TEST 3: invalid directives and reserved names are rejected
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")

            local rs, reason, err = coraza.new("SecRule ARGS \"@rx (\" \"id:1,phase:1,pass\"")
            ngx.say(rs, " ", reason, " ", err ~= nil and err ~= "")
            rs, reason, err = coraza.new("SecMarker CORAZA_WAF_BUDGET_END")
            ngx.say(rs, " ", reason, " ", err:find("reserved", 1, true) ~= nil)
            ngx.say("held: ", coraza.stats().held)
        }
    }
--- response_body
nil invalid true
nil invalid true
held: 0



=== TEST 4: max_rule_sets is enforced, and unreferenced rule sets make room
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local opts = { max_rule_sets = 1 }

            local a = assert(coraza.new(crs.directives("# 4a"), opts))
            a = nil  -- luacheck: ignore 311
            -- the full collection on reaching the limit frees a
            local b, reason = coraza.new(crs.directives("# 4b"), opts)
            ngx.say(b and b.state, " ", reason)
            local c
            c, reason = coraza.new(crs.directives("# 4c"), opts)
            ngx.say(c, " ", reason)
        }
    }
--- response_body
ready nil
nil limit



=== TEST 5: an async build is shared, not ready until built, then waited for
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local read_request = require("read_request")
            local d = crs.directives("# 5")

            local a = assert(coraza.new(d, { async = true }))
            local b = assert(coraza.new(d, { async = true }))
            ngx.say("state: ", a.state, ", same object: ", a == b)
            ngx.say("eval: ", select(2, coraza.eval(a, read_request())))
            ngx.say("building: ", coraza.stats().building)

            local c = assert(coraza.new(d, { async = true, wait = true }))
            ngx.say("waited: ", c == a, ", state: ", a.state)
            local res = assert(coraza.eval(a, read_request()))
            ngx.say("rule ids: ", res.rule_ids)

            -- the build is over, the next call starts a new one
            local e = assert(coraza.new(d, { async = true }))
            ngx.say("new task: ", e ~= a)
        }
    }
--- request
GET /t?id=1'%20OR%20'1'='1
--- more_headers
User-Agent: curl/8.5.0
Accept: */*
--- response_body
state: building, same object: true
eval: not_ready
building: 1
waited: true, state: ready
rule ids: 942100,949110,980170
new task: true



=== TEST 6: the event loop runs while an async build runs
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")

            local rs = assert(coraza.new(crs.directives("# 6"), { async = true }))
            local ticks = 0
            while rs.state == "building" do
                ngx.sleep(0.001)
                ticks = ticks + 1
            end
            ngx.say("state: ", rs.state, ", ticks: ", ticks > 5)
        }
    }
--- response_body
state: ready, ticks: true



=== TEST 7: a wait that times out leaves the build running
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local d = crs.directives("# 7")

            local rs, reason = coraza.new(d, { async = true, wait = true,
                                               build_wait_timeout = 0.001 })
            ngx.say(rs, " ", reason)
            local a = coraza.new(d, { async = true })
            ngx.say("still building: ", a.state)
            rs = assert(coraza.wait(a, 60))
            ngx.say("state: ", rs.state)
        }
    }
--- response_body
nil timeout
still building: building
state: ready



=== TEST 8: every request waiting on invalid directives gets the error
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local d = "SecRule ARGS \"@rx (\" \"id:1,phase:1,pass\""

            local threads = {}
            for i = 1, 3 do
                threads[i] = ngx.thread.spawn(function()
                    local rs, reason = coraza.new(d, { async = true, wait = true })
                    return rs == nil and reason
                end)
            end
            for i = 1, 3 do
                local _, reason = ngx.thread.wait(threads[i])
                ngx.say(i, ": ", reason)
            end
            ngx.say("held: ", coraza.stats().held, ", building: ", coraza.stats().building)
        }
    }
--- response_body
1: invalid
2: invalid
3: invalid
held: 0, building: 0



=== TEST 9: an async rule set nobody waits for is freed once built
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")

            coraza.new(crs.directives("# 9"), { async = true })
            while coraza.stats().building > 0 do
                ngx.sleep(0.005)
            end
            -- let the poller drop the task
            ngx.sleep(0.01)
            collectgarbage("collect")
            local s = coraza.stats()
            ngx.say("held: ", s.held, ", go rule sets: ", s.rule_sets)
        }
    }
--- response_body
held: 0, go rule sets: 0



=== TEST 10: a budget ends the inspection at a checkpoint
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local read_request = require("read_request")

            local rs = assert(coraza.new(crs.directives()))
            local req = read_request()
            local res = assert(coraza.eval(rs, req))
            ngx.say(res.status, " ", res.budget_phase, " ", res.rule_ids)

            req.budget = 1e-6
            res = assert(coraza.eval(rs, req))
            ngx.say(res.status, " ", res.budget_phase, " ", res.rule_ids)

            req.budget = 60
            res = assert(coraza.eval(rs, req))
            ngx.say(res.status, " ", res.budget_phase, " ", res.rule_ids,
                    " ", res.elapsed > 0 and res.elapsed < 60)
        }
    }
--- request
GET /t?id=1'%20OR%20'1'='1
--- more_headers
User-Agent: curl/8.5.0
Accept: */*
--- response_body
done nil 942100,949110,980170
budget 1 nil
done nil 942100,949110,980170 true



=== TEST 11: a library of another ABI is refused
--- config
    location /t {
        content_by_lua_block {
            local loaded = package.loaded["resty.coraza"]
            package.loaded["resty.coraza"] = nil
            local fresh = require("resty.coraza")
            package.loaded["resty.coraza"] = loaded

            local ok, err = fresh.load("libc.so.6")
            ngx.say(ok, " ", err:find("is not a coraza_waf library", 1, true) ~= nil)
            ngx.say("loaded: ", fresh.loaded())
        }
    }
--- response_body
nil true
loaded: false



=== TEST 12: runtime settings and counters
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")

            assert(coraza.init_runtime({ max_procs = 3, gc_percent = "off",
                                         memory_limit = 512 * 1024 * 1024 }))
            local s = coraza.stats()
            ngx.say("max_procs: ", s.max_procs)
            ngx.say("threads: ", s.threads > 1, ", affinity mismatch: ", s.affinity_mismatch)
            ngx.say("heap: ", s.heap_bytes > 0, ", goroutines: ", s.goroutines > 0)
            assert(coraza.init_runtime({ gc_percent = 100 }))
            local ok, err = coraza.init_runtime({ memory_limit = -1 })
            ngx.say(ok, " ", err)
        }
    }
--- response_body
max_procs: 3
threads: true, affinity mismatch: 0
heap: true, goroutines: true
nil max_procs and memory_limit must not be negative
