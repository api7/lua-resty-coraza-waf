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
| OWASP CRS | v4.14.0 |
| RE2 / Abseil | 2024-07-02 / 20240722.0 |

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
`load` also waits for the Go runtime to start, so that no request does.

```lua
-- init_worker_by_lua_block
assert(require("resty.coraza").load())  -- finds coraza_waf.so in package.cpath
```

```lua
-- access_by_lua_block (any phase that can yield)
local coraza = require("resty.coraza")
local request = require("resty.coraza.request")

-- built once per process on a Go goroutine, and shared by every call with the
-- same directives; the calling request waits with ngx.sleep
local rule_set, reason, err = coraza.rule_set([[
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine DetectionOnly
]], { timeout = 60, max_rule_sets = 8 })
if not rule_set then
    ngx.log(ngx.ERR, reason, ": ", err)  -- "invalid", "timeout", "limit" or "error"
    return
end

local headers, too_many_headers = request.get_headers(100)
local body, body_state = request.read_body({
    max_size = 131072,
    media_type_allowed = request.media_type_matcher({
        "application/json", "application/*+json", "application/x-www-form-urlencoded",
    }),
})

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
-- res.anomaly_score, res.rule_ids ("942100,949110"), res.matches (JSON)
```

`eval` runs request phases 1 and 2 and logging in one call. Response phases
are never run. With `SecRuleEngine DetectionOnly` nothing is interrupted and
the result only reports what matched. To block, use `SecRuleEngine On` and act
on `res.interrupted` (and `res.interrupt_rule_id`), for example with
`ngx.exit(ngx.HTTP_FORBIDDEN)`. Keep a reference to the rule set (for example next to the
configuration it was built from): it is freed once nobody references it.

`read_body` returns the body state: `none`, `skipped_type`,
`skipped_encoding`, `skipped_oversize`, `inspected` or `truncated`. Multipart,
JSON and XML bodies over `max_size` are skipped, as Coraza cannot parse them
cut; other types are inspected up to `max_size`.

## Test

```sh
make build && make test                        # Go
CORAZA_WAF_LIB=$PWD/coraza_waf.so prove -I. -r t/  # OpenResty, Test::Nginx
luajit t/smoke.lua ./coraza_waf.so             # plain LuaJIT
```

## Build from source

Needs Go 1.25 or later and a C++17 compiler.

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
