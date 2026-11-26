#!/usr/bin/env bash
#
# Builds prebuilt/coraza_waf-<arch>.so inside a manylinux_2_28 container
# (glibc 2.28), with RE2, Abseil and the C++ runtime linked statically, then
# runs the Go tests against it. Also writes the notices of the third-party
# code it contains, prebuilt/THIRD_PARTY_NOTICES-<arch>.
#
#   docker run --rm -v "$PWD:/src" -w /src quay.io/pypa/manylinux_2_28_$(uname -m) ci/build.sh
#
set -euo pipefail

# a version given without its sha256 fails the checksum
GO_VERSION=${GO_VERSION:-1.27.4}
arch=$(uname -m)
case "$arch" in
    x86_64)
        goarch=amd64
        go_sha256=${GO_SHA256:-7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840}
        ;;
    aarch64)
        goarch=arm64
        go_sha256=${GO_SHA256:-3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92}
        ;;
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

if ! command -v go >/dev/null; then
    go_tar=$(mktemp)
    curl -fsSL -o "$go_tar" "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz"
    echo "$go_sha256  $go_tar" | sha256sum -c --quiet -
    tar -xzf "$go_tar" -C /usr/local
    rm -f "$go_tar"
    export PATH=/usr/local/go/bin:$PATH
fi

re2=$(pwd)/build/re2
if [ ! -f "$re2/lib/pkgconfig/static/re2.pc" ] || [ ! -f "$re2/share/licenses/re2/LICENSE" ]; then
    PREFIX=$re2 scripts/build-re2.sh
fi

out=prebuilt/coraza_waf-${arch}.so
mkdir -p prebuilt
make build RE2_STATIC="$re2" OUTPUT_NAME="$out"
make test RE2_STATIC="$re2"
scripts/third-party-notices.sh "$re2" "prebuilt/THIRD_PARTY_NOTICES-${arch}"

# the library must only need glibc, at most the version of this image
readelf -d "$out" | awk '/NEEDED/ {print $5}' | tr -d '[]' | while read -r lib; do
    case "$lib" in
        libc.so.6|libm.so.6|libpthread.so.0|libresolv.so.2|librt.so.1|libdl.so.2|ld-linux-*) ;;
        *) echo "unexpected dependency: $lib" >&2; exit 1 ;;
    esac
done
echo "glibc: $(objdump -T "$out" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"
