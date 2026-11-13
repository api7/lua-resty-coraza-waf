# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0]

### Added

- `coraza_waf.so`: Coraza v3.8.1 with the embedded OWASP CRS v4.14.0 as a Go
  shared library. `@rx` runs on RE2 through go-re2, linked statically together
  with Abseil and the C++ runtime, so the library only needs glibc 2.28.
- Rule sets built asynchronously on a Go goroutine (`cwaf_build_start` /
  `cwaf_build_poll`), one `cwaf_eval` call per request running phases 1 and 2
  and logging, and panic recovery in every exported function.
- Coraza v3.8.1 or later is required: earlier versions take time and memory
  quadratic in the nesting depth of a JSON body (GHSA-6gcq-wc29-5xf2; a 32 KiB
  body took about a minute and 2.7 GB on v3.3.3).
- `args_limit_reached` is Coraza's `ARGUMENTS_LIMIT_REACHED`: arguments were
  dropped over `SecArgumentsLimit`, from the query or from a body.
- `resty.coraza`: the LuaJIT FFI binding, and `rule_set()`, which builds a rule
  set once per process while the request waits with `ngx.sleep`, shares it
  between calls with the same directives, keeps a build that outlives the
  waiting request, caches invalid directives and limits the rule sets alive.
  `load()` waits for the Go runtime to start, so that the first request does
  not block the worker.
- `resty.coraza.request`: reads the request headers (with `Host` added for
  HTTP/2) and the body (media type filter, Content-Encoding, size limit,
  truncation only where Coraza can parse a cut body, spooled bodies read up to
  the limit).
- Releases with the library prebuilt for Linux x86_64 and aarch64, installed by
  the rockspec without Go or libre2.
