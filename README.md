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
| Coraza | v3.3.3 |
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

```lua
local coraza = require("resty.coraza")

assert(coraza.load())  -- finds coraza_waf.so in package.cpath

local job = assert(coraza.build_start([[
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine DetectionOnly
]]))

-- building the CRS takes a few hundred milliseconds on a Go goroutine
local rule_set, err
repeat
    ngx.sleep(0.002)
    rule_set, err = coraza.build_poll(job)
until rule_set ~= false
assert(rule_set, err)

local res = assert(coraza.eval(rule_set, {
    method = ngx.req.get_method(),
    uri = ngx.var.request_uri,
    protocol = "HTTP/" .. ngx.req.http_version(),
    client_ip = ngx.var.remote_addr,
    client_port = tonumber(ngx.var.remote_port),
    server_name = ngx.var.host,
    headers = { { "Host", ngx.var.host }, { "User-Agent", ngx.var.http_user_agent or "" } },
    body = ngx.req.get_body_data(),
}))
-- res.anomaly_score, res.rule_ids ("942100,949110"), res.matches (JSON)
```

`eval` runs request phases 1 and 2 and logging in one call. Response phases
are never run. The rule set is freed when `rule_set` is garbage collected.

## Build from source

Needs Go 1.24 or later and a C++17 compiler.

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
