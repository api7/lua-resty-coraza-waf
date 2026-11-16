use t::Coraza 'no_plan';

run_tests();

__DATA__

=== TEST 1: calls with the same directives share one rule set
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local d = crs.directives()

            local a, reason, err = coraza.rule_set(d)
            assert(a, err)
            local b = assert(coraza.rule_set(d))
            ngx.say("same: ", a == b)
            ngx.say("cached: ", coraza.stats().cached)
            ngx.say("go rule sets: ", coraza.stats().rule_sets)
        }
    }
--- response_body
same: true
cached: 1
go rule sets: 1



=== TEST 2: a rule set nobody references is freed
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")

            local rs = assert(coraza.rule_set(crs.directives("# 2")))
            ngx.say("cached: ", coraza.stats().cached)
            rs = nil
            collectgarbage()
            collectgarbage()
            ngx.say("cached: ", coraza.stats().cached)
            ngx.say("go rule sets: ", coraza.stats().rule_sets)
        }
    }
--- response_body
cached: 1
cached: 0
go rule sets: 0



=== TEST 3: invalid directives are rejected, and the error is cached
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local d = 'SecRule ARGS "@rx (" "id:1,phase:1,pass"'

            local rs, reason, err = coraza.rule_set(d)
            ngx.say(rs, " ", reason, " ", err ~= nil and err ~= "")

            rs, reason = coraza.rule_set(d)
            ngx.say(rs, " ", reason)
            ngx.say("building: ", coraza.stats().building)
            ngx.say("cached: ", coraza.stats().cached)
        }
    }
--- response_body
nil invalid true
nil invalid
building: 0
cached: 0



=== TEST 4: a build that outlives the waiting request is kept and reused
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local d = crs.directives("# 4")

            -- the first request sees the job as running whatever its real
            -- progress, and gives up at once
            local build_poll = coraza.build_poll
            coraza.build_poll = function() return false end
            local rs, reason = coraza.rule_set(d, { timeout = 0 })
            coraza.build_poll = build_poll
            ngx.say("first: ", rs and "built" or reason)

            collectgarbage()
            collectgarbage()
            rs, reason = coraza.rule_set(d)
            ngx.say("second: ", rs and rs.handle and "built" or reason)
            ngx.say("cached: ", coraza.stats().cached)
            ngx.say("building: ", coraza.stats().building)
        }
    }
--- response_body
first: timeout
second: built
cached: 1
building: 0



=== TEST 5: max_rule_sets is enforced, and unreferenced rule sets make room
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local opts = { max_rule_sets = 1 }

            local a = assert(coraza.rule_set(crs.directives("# 5a"), opts))
            local b, reason = coraza.rule_set(crs.directives("# 5b"), opts)
            ngx.say("while held: ", b and "built" or reason)

            a = nil
            collectgarbage()
            collectgarbage()
            b, reason = coraza.rule_set(crs.directives("# 5b"), opts)
            ngx.say("after release: ", b and "built" or reason)
        }
    }
--- response_body
while held: limit
after release: built



=== TEST 6: other requests are served while a rule set builds, including the first one
--- config
    location /build {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            assert(coraza.rule_set(crs.directives("# 6")))
            ngx.say("built")
        }
    }
    location /ping {
        return 200 "pong\n";
    }
    location /t {
        content_by_lua_block {
            local build = ngx.thread.spawn(function()
                return ngx.location.capture("/build")
            end)
            ngx.update_time()
            local start = ngx.now()
            local ping = ngx.location.capture("/ping")
            ngx.update_time()
            ngx.print("ping: ", ping.body)
            ngx.say("ping waited for the build: ", ngx.now() - start > 0.1)
            local _, res = ngx.thread.wait(build)
            ngx.print("build: ", res.body)
        }
    }
--- response_body
ping: pong
ping waited for the build: false
build: built



=== TEST 7: every request waiting on invalid directives gets the error
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            -- the CRS first, so that the build runs long enough for both
            local d = crs.directives('SecRule ARGS "@rx (" "id:1,phase:1,pass"')

            local function get()
                local rs, reason = coraza.rule_set(d)
                return rs and "built" or reason
            end
            local a = ngx.thread.spawn(get)
            local b = ngx.thread.spawn(get)
            local _, ra = ngx.thread.wait(a)
            local _, rb = ngx.thread.wait(b)
            ngx.say(ra, " ", rb)
            ngx.say("cached: ", coraza.stats().cached)
        }
    }
--- response_body
invalid invalid
cached: 0



=== TEST 8: a build nobody asks for again does not hold max_rule_sets
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local opts = { max_rule_sets = 1 }

            local build_poll = coraza.build_poll
            coraza.build_poll = function() return false end
            local rs, reason = coraza.rule_set(crs.directives("# 8a"),
                                               { timeout = 0, max_rule_sets = 1 })
            coraza.build_poll = build_poll
            ngx.say("abandoned: ", rs and "built" or reason)

            while coraza.stats().building > 0 do
                ngx.sleep(0.05)
            end

            rs, reason = coraza.rule_set(crs.directives("# 8b"), opts)
            ngx.say("other: ", rs and "built" or reason)
            ngx.say("cached: ", coraza.stats().cached)
        }
    }
--- response_body
abandoned: timeout
other: built
cached: 1



=== TEST 9: a build that ends during the last wait is returned, not timed out
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")

            -- running on the first poll, and over on the next one
            local build_poll = coraza.build_poll
            local polls = 0
            coraza.build_poll = function(job, on_free)
                polls = polls + 1
                if polls == 1 then
                    return false
                end
                while true do
                    local rs, err = build_poll(job, on_free)
                    if rs ~= false then
                        return rs, err
                    end
                    ngx.sleep(0.01)
                end
            end
            local rs, reason = coraza.rule_set(crs.directives("# 9"), { timeout = 0.001 })
            coraza.build_poll = build_poll
            ngx.say(rs and "built" or reason)
        }
    }
--- response_body
built



=== TEST 10: the wait starts from the current time, not the cached one
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")

            -- leaves ngx.now() 0.2s behind
            local t = os.clock()
            while os.clock() - t < 0.2 do end

            local build_poll = coraza.build_poll
            local polls = 0
            coraza.build_poll = function(job, on_free)
                polls = polls + 1
                if polls <= 3 then
                    return false
                end
                while true do
                    local rs, err = build_poll(job, on_free)
                    if rs ~= false then
                        return rs, err
                    end
                    ngx.sleep(0.01)
                end
            end
            local rs, reason = coraza.rule_set(crs.directives("# 10"), { timeout = 0.1 })
            coraza.build_poll = build_poll
            ngx.say(rs and "built" or reason)
        }
    }
--- response_body
built



=== TEST 11: an abandoned build that fails is cached for its own failed_ttl
--- config
    location /t {
        content_by_lua_block {
            local coraza = require("resty.coraza")
            local crs = require("crs")
            local d = 'SecRule ARGS "@rx (" "id:11,phase:1,pass"'

            local build_poll = coraza.build_poll
            coraza.build_poll = function() return false end
            local rs, reason = coraza.rule_set(d, { timeout = 0, failed_ttl = 0 })
            coraza.build_poll = build_poll
            ngx.say("abandoned: ", rs and "built" or reason)

            while coraza.stats().building > 0 do
                ngx.sleep(0.05)
            end

            -- this call finishes the abandoned build
            local other = assert(coraza.rule_set(crs.directives("# 11"),
                                                 { failed_ttl = 3600 }))

            local build_start = coraza.build_start
            local starts = 0
            coraza.build_start = function(...)
                starts = starts + 1
                return build_start(...)
            end
            rs, reason = coraza.rule_set(d, { failed_ttl = 0 })
            coraza.build_start = build_start
            ngx.say("again: ", rs and "built" or reason, ", built again: ", starts == 1)
            ngx.say("other: ", other.handle ~= nil)
        }
    }
--- response_body
abandoned: timeout
again: invalid, built again: true
other: true
