#!/usr/bin/env bash
#
# Installs the packed rockspec with luarocks on a machine without Go or
# libre2, serving dist/ over HTTP in place of the GitHub release, and loads
# the library from package.cpath.
#
#   ci/luarocks-test.sh 0.1.0
#
set -euo pipefail

version=$1

docker run --rm -v "$PWD:/src:ro" ubuntu:24.04 bash -c '
set -e
apt-get update -qq && apt-get install -y -qq luarocks lua5.1 luajit make python3 >/dev/null
! command -v go
cd /src/dist && (python3 -m http.server 8000 >/dev/null 2>&1 &) && sleep 1
spec=lua-resty-coraza-waf-'"$version"'-1.rockspec
mkdir /tmp/spec
sed "s#https://github.com/.*/releases/download/v[^/]*#http://127.0.0.1:8000#" "$spec" > "/tmp/spec/$spec"
cd /tmp && luarocks --lua-version=5.1 install "/tmp/spec/$spec"
eval "$(luarocks --lua-version=5.1 path)"
luajit -e "local c = require(\"resty.coraza\"); assert(c.load()); assert(c.stats().panics == 0)"
echo "luarocks install ok"
'
