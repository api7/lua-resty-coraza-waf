#!/usr/bin/env bash
#
# Builds prebuilt/coraza_waf-<arch>.so inside a manylinux_2_28 container
# (glibc 2.28), with RE2, Abseil and the C++ runtime linked statically, then
# runs the Go tests against it.
#
#   docker run --rm -v "$PWD:/src" -w /src quay.io/pypa/manylinux_2_28_$(uname -m) ci/build.sh
#
set -euo pipefail

GO_VERSION=${GO_VERSION:-1.26.11}
arch=$(uname -m)
case "$arch" in
    x86_64) goarch=amd64 ;;
    aarch64) goarch=arm64 ;;
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

if ! command -v go >/dev/null; then
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" | tar -xz -C /usr/local
    export PATH=/usr/local/go/bin:$PATH
fi

re2=$(pwd)/build/re2
if [ ! -f "$re2/lib/pkgconfig/static/re2.pc" ]; then
    PREFIX=$re2 scripts/build-re2.sh
fi

out=prebuilt/coraza_waf-${arch}.so
mkdir -p prebuilt
make build RE2_STATIC="$re2" OUTPUT_NAME="$out"
make test RE2_STATIC="$re2"

# the library must only need glibc, at most the version of this image
readelf -d "$out" | awk '/NEEDED/ {print $5}' | tr -d '[]' | while read -r lib; do
    case "$lib" in
        libc.so.6|libm.so.6|libpthread.so.0|libresolv.so.2|librt.so.1|libdl.so.2|ld-linux-*) ;;
        *) echo "unexpected dependency: $lib" >&2; exit 1 ;;
    esac
done
echo "glibc: $(objdump -T "$out" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"
