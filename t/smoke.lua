-- Loads coraza_waf.so in a fresh LuaJIT process, builds the embedded CRS and
-- inspects a clean and an SQL injection request, then with a budget.
--
--   luajit t/smoke.lua [path/to/coraza_waf.so]
package.path = "lib/?.lua;" .. package.path

local ffi = require("ffi")
ffi.cdef[[
int chdir(const char *path);
]]

local coraza = require("resty.coraza")

local function check(cond, ...)
    if not cond then
        io.stderr:write("FAIL: ", table.concat({ ... }, " "), "\n")
        os.exit(1)
    end
end

local lib_path = arg[1] or "./coraza_waf.so"

local cpath = package.cpath
package.cpath = "/nonexistent/?.so"
local ok, err = coraza.load()
check(not ok and err:find("not found in package.cpath", 1, true),
      "load without the library in package.cpath:", tostring(err))

-- found as coraza_waf.so through a relative package.cpath entry
local dir = os.tmpname()
os.remove(dir)
local rc = os.execute(string.format('mkdir %q && ln -s "$(realpath %q)" %q/coraza_waf.so',
                                    dir, lib_path, dir))
check(rc == 0 or rc == true, "failed to link the library in", dir)
local cwd = assert(os.getenv("PWD"))
check(ffi.C.chdir(dir) == 0, "failed to enter", dir)
package.cpath = "?.so;" .. cpath
ok, err = coraza.load(nil, { max_procs = 1, gc_percent = 200 })
ffi.C.chdir(cwd)
os.execute(string.format("rm -r %q", dir))
check(ok, err)
check(coraza.stats().max_procs == 1, "GOMAXPROCS not applied:",
      tostring(coraza.stats().max_procs))
ok, err = coraza.init_runtime({ max_procs = -1 })
check(not ok and err:find("negative", 1, true), "negative max_procs accepted:", tostring(err))

local directives = table.concat({
    "Include @coraza.conf-recommended",
    "Include @crs-setup.conf.example",
    "Include @owasp_crs/*.conf",
    "SecRuleEngine DetectionOnly",
}, "\n")

local rs, reason
rs, reason, err = coraza.new(directives)
check(rs, reason, err)
check(rs.state == "ready" and rs.rules > 0 and rs.build_time > 0, "build information missing")

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
check(not res.interrupted and res.status == "done", "DetectionOnly interrupted the request")

-- a budget already spent skips the rules after the first checkpoint
res, err = coraza.eval(rs, { uri = "/hello?id=1%27%20OR%20%271%27=%271", headers = headers,
                             budget = 1e-6 })
check(res, err)
check(res.status == "budget" and res.budget_phase == 1, "budget not applied:", res.status,
      tostring(res.budget_phase))
check(not res.rule_ids or not res.rule_ids:find("942100", 1, true),
      "rules ran after the budget:", tostring(res.rule_ids))

local bad
bad, reason, err = coraza.new("SecRule ARGS \"@rx (\" \"id:1,phase:1,pass\"")
check(bad == nil and reason == "invalid" and err ~= "", "invalid directives were accepted")

rs = nil  -- luacheck: ignore 311 (drop the reference so it is collected)
collectgarbage("collect")
local stats = coraza.stats()
check(stats.rule_sets == 0 and stats.held == 0, "rule set not freed:", tostring(stats.rule_sets))
check(stats.threads > 1, "threads not counted:", tostring(stats.threads))
check(stats.panics == 0, "panics:", tostring(stats.panics))
check(stats.close_errors == 0, "close errors:", tostring(stats.close_errors))

print("ok")
