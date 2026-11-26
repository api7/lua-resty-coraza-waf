# lua-resty-coraza-waf

[Coraza](https://github.com/corazawaf/coraza) v3 with the embedded
[OWASP CRS](https://github.com/coreruleset/coreruleset) v4 for OpenResty,
called through LuaJIT FFI.

The engine is a Go shared library, `coraza_waf.so`. `@rx` runs on RE2 through
[go-re2](https://github.com/wasilibs/go-re2). Releases ship the library
prebuilt for Linux x86_64 and aarch64, with RE2, Abseil and the C++ runtime
linked statically: it only needs glibc 2.28 or later, and installing it needs
neither Go nor libre2.

| Component | Version |
|---|---|
| Coraza | v3.8.1 |
| OWASP CRS | v4.30.0 |
| RE2 / Abseil | 2025-11-05 / 20260817.0 |

## Install

```sh
luarocks install https://github.com/api7/lua-resty-coraza-waf/releases/download/v0.1.0/lua-resty-coraza-waf-0.1.0-1.rockspec
```

The rockspec downloads the release tarball and installs `resty/coraza.lua` and
the library matching `uname -m` as `coraza_waf.so` in the Lua C module
directory. Other platforms build from source (below).

## Usage

The Go runtime does not survive `fork()`: load the library after fork, in the
processes that use it, for example in `init_worker_by_lua*` of HTTP workers.
`load` checks that the library matches this module and waits for the Go
runtime to start, so that no request does.

```lua
-- init_worker_by_lua_block
local coraza = require("resty.coraza")
-- finds coraza_waf.so in package.cpath; the second argument is optional
assert(coraza.load(nil, { max_procs = 1 }))

-- build the rule set before the worker serves traffic, and keep a reference:
-- it is freed when it is garbage collected
local my_waf = require("my_waf")
my_waf.rule_set = assert(coraza.new([[
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine DetectionOnly
]]))
```

```lua
-- access_by_lua_block
local coraza = require("resty.coraza")
local rule_set = require("my_waf").rule_set

-- { {name, value}, ... }, one entry per value
local headers = {}
for name, value in pairs(ngx.req.get_headers(100)) do
    if type(value) == "table" then
        for _, v in ipairs(value) do
            headers[#headers + 1] = { name, v }
        end
    else
        headers[#headers + 1] = { name, value }
    end
end

ngx.req.read_body()
local body = ngx.req.get_body_data()  -- nil when spooled to a file

local res, err = coraza.eval(rule_set, {
    method = ngx.req.get_method(),
    uri = ngx.var.request_uri,
    protocol = ngx.var.server_protocol,
    client_ip = ngx.var.remote_addr,
    client_port = tonumber(ngx.var.remote_port),
    server_name = ngx.var.host,
    headers = headers,
    body = body,
    budget = 0.005,  -- optional, seconds
})
if not res then
    -- the request is not inspected: reject it to fail closed, or go on to
    -- fail open
    ngx.log(ngx.ERR, "inspection failed: ", err)
    return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end
-- res.status ("done", "budget"), res.anomaly_score,
-- res.rule_ids ("942100,949110,980170"), res.matches (JSON)
```

### Building rule sets

`new(directives, opts)` compiles the directives on the calling thread and
blocks the nginx worker for the build, about 0.1 s for the full CRS. Each
call builds a new rule set: cache them by their directives, for example with
`resty.lrucache`. `new` returns `nil`, a reason (`"invalid"`, `"limit"`) and
a message on failure; `max_rule_sets` caps the rule sets alive in the Lua VM.
A rule set has `rules` and `build_time` (seconds).

To keep serving requests while a rule set builds, pass `async = true`: the
build runs on a goroutine, and the object comes back in the `"building"`
state. `eval` returns `nil, "not_ready"` until it is `"ready"`. Calls with
the same directives while it builds return the same object. A request that
can yield waits for it with `coraza.wait(rule_set, timeout)` or with
`new(directives, { async = true, wait = true, build_wait_timeout = 5 })`;
the wait can end with `"timeout"` while the build goes on. The module polls
the builds from one timer per worker and wakes the waiters; Go never calls
into Lua.

Directives must not use the name prefix `CORAZA_WAF_BUDGET`, nor define or
remove rules with IDs 2147483000 to 2147483647: the module uses them for the
budget checkpoints.

### Inspecting requests

`eval` runs request phases 1 and 2 and logging in one call, on the calling
thread; the worker serves no other request meanwhile. Response phases are
never run. Logging also runs when a phase fails, for example when a body over
`SecRequestBodyInMemoryLimit` cannot be written to a temporary file; `eval`
then returns `nil` and the error. With `SecRuleEngine DetectionOnly` nothing
is interrupted and the result only reports what matched;
`res.would_interrupt_rule_id` is the rule that would interrupt with
`SecRuleEngine On` (0 for none), to watch before blocking. To block, use
`SecRuleEngine On` and act on `res.status == "interrupted"` (and
`res.interrupt_rule_id`), for example with `ngx.exit(ngx.HTTP_FORBIDDEN)`.

`budget` bounds the time of the request phases. Coraza cannot stop a rule
that is running, so the module checks the budget before each CRS file, in
each phase. Once it has run out, the remaining rules of the phase are
skipped, custom rules included, and the body phase is skipped too when the
headers phase ran out. Logging still runs. `res.status` is then `"budget"`,
`res.budget_phase` the phase that ran out, and the result keeps what matched
before; the inspection is incomplete. An inspection can still exceed the
budget by the time of one CRS file, of parsing the body and of logging;
`res.elapsed` (seconds) shows the time taken. The input limits
(`SecRequestBodyLimit`, `SecArgumentsLimit`, `SecRequestBodyJsonDepthLimit`)
remain the main bound on that time.

With `SecRuleEngine On`, the skipped rules include the CRS blocking
evaluation (949110), so a request over the budget is not blocked: reject it
on `"budget"` to fail closed. The first requests of a worker take longer
than the next ones (a small JSON request took 6.9 ms, then 3.0 and 0.5 ms),
so a tight budget mostly hits them.

Coraza inspects only what `eval` is given. When reading the request:

- HTTP/2 and HTTP/3 carry the host in `:authority`, not in a `Host` header;
  add one from `ngx.var.host` for the rules on `Host`.
- Headers past the `ngx.req.get_headers` limit, a body spooled to a file
  (over `client_body_buffer_size`) and a compressed body (`Content-Encoding`)
  are not inspected, or not usefully.
- Coraza picks the body parser from the first `Content-Type`, by the
  prefixes of rules 200000, 200001 and 200006 of `coraza.conf-recommended`;
  a multipart, JSON or XML body cut to a size limit fails to parse. CRS
  parses a body without `Content-Type` as URLENCODED (rule 901340).
- CRS rule 920620 flags repeated `Content-Type` headers.

### Go runtime

Each nginx worker runs its own Go runtime and builds its own copy of a rule
set. The runtime has threads of its own (5 or more per worker, also with
`GOMAXPROCS=1`), which run the GC and async builds and inherit the worker's
CPU affinity; `load` logs a warning when some thread has another affinity
than the worker.

`load(path, runtime)` and `init_runtime(runtime)` set, for the process:

- `max_procs` (`GOMAXPROCS`): the threads that run Go code at once. Setting
  it stops Go from adjusting it. Go defaults it to the CPUs the worker may
  use, which is 1 with `worker_cpu_affinity`. With 1, an async build and
  `eval` take turns.
- `gc_percent` (`GOGC`, or `"off"`): the GC takes about 10% of the CPU of a
  busy worker; a higher value trades memory for less GC.
- `memory_limit` (`GOMEMLIMIT`, bytes): a soft limit of the Go heap. nginx,
  Lua and RE2 memory is not counted.

The same variables in the environment that the nginx master was started with
apply too. The nginx `env` directive neither sets nor clears what Go sees.

`stats()` returns process counters: `heap_bytes`, `runtime_bytes`,
`gc_cycles`, `goroutines`, `max_procs`, `threads`, `affinity_mismatch`,
`rule_sets` (alive in Go), `building`, `panics`, `close_errors`, and `held`
(rule sets alive or building through `new` in this Lua VM).

## Test

```sh
make build && make test                        # Go
CORAZA_WAF_LIB=$PWD/coraza_waf.so prove -I. -r t/  # OpenResty, Test::Nginx
luajit t/smoke.lua ./coraza_waf.so             # plain LuaJIT
```

## Build from source

Needs Go 1.27 or later and a C++17 compiler.

```sh
# against the system libre2 (libre2-dev, pkg-config)
make build && make test

# fully static RE2, as in releases
PREFIX=$PWD/build/re2 scripts/build-re2.sh
make build RE2_STATIC=$PWD/build/re2

make install INST_PREFIX=/usr/local
```

Release libraries are built by `ci/build.sh` in `manylinux_2_28` containers.

## Release

1. Add `rockspec/lua-resty-coraza-waf-X.Y.Z-1.rockspec` and move the
   `[Unreleased]` notes of `CHANGELOG.md` under `## [X.Y.Z]`.
2. Merge it with the title `feat: release vX.Y.Z`, or run the Release
   workflow by hand with the version.

The workflow builds and tests both libraries, creates the GitHub release with
the tarball and the rockspec (with the tarball md5 added), installs it back
from the release on x86_64 and aarch64, then uploads the rockspec to LuaRocks
with the `LUAROCKS_TOKEN` secret.

## License

Apache License 2.0.
