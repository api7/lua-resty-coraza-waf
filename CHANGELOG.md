# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0]

### Added

- `coraza_waf.so`: Coraza v3.3.3 with the embedded OWASP CRS v4.14.0 as a Go
  shared library. `@rx` runs on RE2 through go-re2, linked statically together
  with Abseil and the C++ runtime, so the library only needs glibc 2.28.
- Rule sets built asynchronously on a Go goroutine (`cwaf_build_start` /
  `cwaf_build_poll`), one `cwaf_eval` call per request running phases 1 and 2
  and logging, and panic recovery in every exported function.
- `resty.coraza`: the LuaJIT FFI binding.
- Releases with the library prebuilt for Linux x86_64 and aarch64, installed by
  the rockspec without Go or libre2.
