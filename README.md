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

Build from source (below).

## Usage

The Go runtime does not survive `fork()`: load the library after fork, in the
processes that use it, for example in `init_worker_by_lua*` of HTTP workers.
`load` also waits for the Go runtime to start, so that no request does.

```lua
-- init_worker_by_lua_block
assert(require("resty.coraza").load())  -- finds coraza_waf.so in package.cpath
```

```lua
-- access_by_lua_block (any phase that can yield)
local coraza = require("resty.coraza")

-- built once per process on a Go goroutine, and shared by every call with the
-- same directives; the calling request waits with ngx.sleep. The rule set is
-- freed once nobody references it, so keep it, here in a module of your own
-- (my_waf.lua) that holds it between requests.
local my_waf = require("my_waf")
local rule_set = my_waf.rule_set
if not rule_set then
    local reason, err
    rule_set, reason, err = coraza.rule_set([[
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine DetectionOnly
]], { timeout = 60, max_rule_sets = 8 })
    if not rule_set then
        -- "invalid", "timeout", "limit" or "error": the request is not
        -- inspected. Reject it to fail closed, or return to let it through
        -- (fail open).
        ngx.log(ngx.ERR, reason, ": ", err)
        return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
    my_waf.rule_set = rule_set
end

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

local res = assert(coraza.eval(rule_set, {
    method = ngx.req.get_method(),
    uri = ngx.var.request_uri,
    protocol = ngx.var.server_protocol,
    client_ip = ngx.var.remote_addr,
    client_port = tonumber(ngx.var.remote_port),
    server_name = ngx.var.host,
    headers = headers,
    body = body,
}))
-- res.anomaly_score, res.rule_ids ("942100,949110,980170"), res.matches (JSON)
```

`eval` runs request phases 1 and 2 and logging in one call. Response phases
are never run. Logging also runs when a phase fails, for example when a body
over `SecRequestBodyInMemoryLimit` cannot be written to a temporary file;
`eval` then returns `nil` and the error. With `SecRuleEngine DetectionOnly`
nothing is interrupted and the result only reports what matched;
`res.would_interrupt_rule_id` is the rule that would interrupt with
`SecRuleEngine On` (0 for none), to watch before blocking. To block, use
`SecRuleEngine On` and act on `res.interrupted` (and `res.interrupt_rule_id`),
for example with `ngx.exit(ngx.HTTP_FORBIDDEN)`.

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

Each nginx worker runs its own Go runtime and builds its own copy of a rule
set. Go sizes its scheduler from the CPUs it may use,
and its GC and build goroutines run on threads beside the nginx worker. To
limit them, set `GOMAXPROCS`, `GOGC` or `GOMEMLIMIT` and pass them to the
workers with the nginx `env` directive, which nginx otherwise clears:

```nginx
env GOMAXPROCS=2;
env GOMEMLIMIT=512MiB;
```

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

## License

Apache License 2.0.
