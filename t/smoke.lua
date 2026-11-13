-- Loads coraza_waf.so in a fresh LuaJIT process, builds the embedded CRS and
-- inspects a clean and an SQL injection request.
--
--   luajit t/smoke.lua [path/to/coraza_waf.so]
package.path = "lib/?.lua;" .. package.path

local ffi = require("ffi")
ffi.cdef[[ int usleep(unsigned int usec); ]]

local coraza = require("resty.coraza")

local function check(cond, ...)
    if not cond then
        io.stderr:write("FAIL: ", table.concat({ ... }, " "), "\n")
        os.exit(1)
    end
end

local ok, err = coraza.load(arg[1] or "./coraza_waf.so")
check(ok, err)

local directives = table.concat({
    "Include @coraza.conf-recommended",
    "Include @crs-setup.conf.example",
    "Include @owasp_crs/*.conf",
    "SecRuleEngine DetectionOnly",
}, "\n")

local function build(d)
    local job = assert(coraza.build_start(d))
    local start = os.clock()
    while true do
        local rs, berr = coraza.build_poll(job)
        if rs ~= false then
            return rs, berr
        end
        check(os.clock() - start < 120, "build timed out")
        ffi.C.usleep(10000)
    end
end

local rs
rs, err = build(directives)
check(rs, err)

local headers = {
    { "Host", "example.com" },
    { "User-Agent", "curl/8.5.0" },
    { "Accept", "*/*" },
}

local res
res, err = coraza.eval(rs, { uri = "/hello?name=alice", headers = headers,
                             client_ip = "10.0.0.1", server_name = "example.com" })
check(res, err)
check(res.anomaly_score == 0, "clean request scored", tostring(res.anomaly_score))

res, err = coraza.eval(rs, { uri = "/hello?id=1%27%20OR%20%271%27=%271", headers = headers,
                             client_ip = "10.0.0.1", server_name = "example.com",
                             log_matched_data = true })
check(res, err)
check(res.rule_ids and res.rule_ids:find("942100", 1, true),
      "942100 not matched:", tostring(res.rule_ids))
check(res.anomaly_score >= 5, "low score", tostring(res.anomaly_score))
check(not res.interrupted, "DetectionOnly interrupted the request")

local bad
bad, err = build("SecRule ARGS \"@rx (\" \"id:1,phase:1,pass\"")
check(bad == nil and err and err ~= "", "invalid directives were accepted")

rs = nil
collectgarbage("collect")
local stats = coraza.stats()
check(stats.rule_sets == 0, "rule set not freed:", tostring(stats.rule_sets))
check(stats.panics == 0, "panics:", tostring(stats.panics))

print("ok: rule ids " .. res.rule_ids .. ", score " .. res.anomaly_score)
