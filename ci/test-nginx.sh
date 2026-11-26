#!/usr/bin/env bash
#
# Runs the test-nginx suites (t/*.t) under OpenResty against a library.
# Installs OpenResty and Test::Nginx on Ubuntu when they are missing.
#
#   ci/test-nginx.sh prebuilt/coraza_waf-x86_64.so
#
set -euo pipefail

lib=$(realpath "$1")

if [ ! -x /usr/local/openresty/nginx/sbin/nginx ]; then
    case "$(uname -m)" in
        x86_64) repo=http://openresty.org/package/ubuntu ;;
        aarch64) repo=http://openresty.org/package/arm64/ubuntu ;;
    esac
    sudo apt-get update -qq
    sudo apt-get install -y -qq --no-install-recommends wget gnupg ca-certificates lsb-release
    wget -qO - https://openresty.org/package/pubkey.gpg \
        | sudo gpg --dearmor -o /usr/share/keyrings/openresty.gpg
    echo "deb [signed-by=/usr/share/keyrings/openresty.gpg] $repo $(lsb_release -sc) main" \
        | sudo tee /etc/apt/sources.list.d/openresty.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq --no-install-recommends openresty
fi

if ! perl -MTest::Nginx::Socket::Lua -e 1 2>/dev/null; then
    sudo apt-get install -y -qq --no-install-recommends cpanminus
    sudo cpanm --notest Test::Nginx >/dev/null
fi

export PATH=/usr/local/openresty/nginx/sbin:$PATH
CORAZA_WAF_LIB=$lib prove -I. -r t/
