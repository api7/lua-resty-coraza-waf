# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0]

### Added

- `coraza_waf.so`: Coraza v3.8.1 with the embedded OWASP CRS v4.30.0 as a Go
  shared library. `@rx` runs on RE2 through go-re2, linked statically together
  with Abseil and the C++ runtime, so the library only needs glibc 2.28.
- A versioned C ABI over the importable `go/waf` package: `rt_abi_version`,
  `rt_init`, `rt_stats`, `waf_new`, `waf_free`, `waf_eval`, `waf_build_start`
  and `waf_build_poll`. One `waf_eval` call per request runs phases 1 and 2
  and logging, and every exported function recovers panics. `waf_free`
  releases the matchers that the rule set shares (Coraza `WAF.Close`).
- Coraza v3.8.1 or later is required. On earlier versions a JSON body takes
  time and memory quadratic in its nesting depth (GHSA-6gcq-wc29-5xf2; a
  32 KiB body took about a minute and 2.7 GB on v3.3.3), and a dotted property
  such as `"a.b"` overwrites a nested `{"a":{"b":...}}` value before the rules
  see it (GHSA-5gj4-9gm7-2fx2).
- libinjection-go v0.3.4 or later is required, above the v0.3.3 Coraza
  v3.8.1 pins: on earlier versions `@detectSQLi` takes time quadratic in the
  length of a quote-heavy string literal (GHSA-974q-67pr-5pc2; a 1 MiB
  literal took about 12 seconds per call).
- CRS is embedded from the `coraza-coreruleset/crs/v4` module, not the legacy
  `coraza-coreruleset/v4`, which is frozen at CRS v4.25.0 and misses the fixes
  for GHSA-575j-qr6p-9763, GHSA-89h9-2j8h-9gp2, GHSA-qmx4-jfcv-fgww,
  GHSA-6jp8-c2w2-x7wr and V29-260924.
- `eval` runs the logging phase, and closes the transaction, also when a
  request phase fails. `stats().close_errors` counts transactions that failed
  to close; their result is kept.
- `args_limit_reached` is Coraza's `ARGUMENTS_LIMIT_REACHED`: arguments were
  dropped over `SecArgumentsLimit`, from the query or from a body.
- `resty.coraza`: the LuaJIT FFI binding. `load()` checks the ABI version,
  applies `GOMAXPROCS`, `GOGC` and `GOMEMLIMIT` given by the caller and waits
  for the Go runtime to start, so that the first request does not. `new()`
  builds a rule set on the calling thread, or with `async` on a goroutine,
  polled from one timer per worker, shared between callers with the same
  directives and waited for with `wait()`; `eval()` returns `not_ready` until
  it is built. `stats()` reports the Go heap, GC, threads and their CPU
  affinity, and the rule sets.
- An evaluation budget: `eval()` takes `budget`, checked before each CRS
  file in each request phase. Once spent, the rest of the phase is skipped,
  and the body phase when the headers phase ran out; logging still runs and
  the result has `status = "budget"`.
- `would_interrupt_rule_id`: the rule that interrupts, or would interrupt with
  `SecRuleEngine On`, so that `DetectionOnly` shows what blocking would do.
- The Go, Abseil and RE2 archives of the release build are checked against
  pinned sha256 sums.
- Releases with the library prebuilt for Linux x86_64 and aarch64, installed by
  the rockspec without Go or libre2.
