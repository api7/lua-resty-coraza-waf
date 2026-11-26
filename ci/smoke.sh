#!/usr/bin/env bash
#
# Runs t/smoke.lua with the distribution's LuaJIT, in a container of image.
#
#   ci/smoke.sh ubuntu:24.04 prebuilt/coraza_waf-x86_64.so
#
set -euo pipefail

image=$1
lib=$2

docker run --rm -v "$PWD:/src:ro" -w /src "$image" bash -c '
set -e
if command -v apt-get >/dev/null; then
    apt-get update -qq && apt-get install -y -qq luajit >/dev/null
else
    dnf install -y -q epel-release && dnf install -y -q luajit
fi
luajit t/smoke.lua "'"$lib"'"
'
