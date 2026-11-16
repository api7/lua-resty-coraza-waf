#!/usr/bin/env bash
#
# Builds RE2 and Abseil as position independent static libraries under PREFIX
# and writes a re2.pc that links them statically, so that the shared library
# only depends on glibc.
#
#   PREFIX=/opt/re2 scripts/build-re2.sh
#   make build RE2_STATIC=/opt/re2
#
set -euo pipefail

PREFIX=${PREFIX:-$(pwd)/build/re2}
# a version given without its sha256 fails the checksum
ABSEIL_VERSION=${ABSEIL_VERSION:-20240722.0}
ABSEIL_SHA256=${ABSEIL_SHA256:-f50e5ac311a81382da7fa75b97310e4b9006474f9560ac46f54a9967f07d4ae3}
RE2_VERSION=${RE2_VERSION:-2024-07-02}
RE2_SHA256=${RE2_SHA256:-eb2df807c781601c14a260a507a5bb4509be1ee626024cb45acbd57cb9d4032b}
JOBS=${JOBS:-$(nproc)}

src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT

fetch() {
    curl -fsSL -o "$src/archive.tar.gz" "$1"
    echo "$2  $src/archive.tar.gz" | sha256sum -c --quiet -
    tar -xzf "$src/archive.tar.gz" -C "$src"
    rm "$src/archive.tar.gz"
}

fetch "https://github.com/abseil/abseil-cpp/releases/download/${ABSEIL_VERSION}/abseil-cpp-${ABSEIL_VERSION}.tar.gz" \
    "$ABSEIL_SHA256"
fetch "https://github.com/google/re2/releases/download/${RE2_VERSION}/re2-${RE2_VERSION}.tar.gz" \
    "$RE2_SHA256"

common=(
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX="$PREFIX"
    -DCMAKE_INSTALL_LIBDIR=lib
    -DCMAKE_PREFIX_PATH="$PREFIX"
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DCMAKE_CXX_STANDARD=17
    -DBUILD_SHARED_LIBS=OFF
)

cmake -S "$src/abseil-cpp-${ABSEIL_VERSION}" -B "$src/absl-build" "${common[@]}" \
    -DABSL_PROPAGATE_CXX_STD=ON -DABSL_BUILD_TESTING=OFF -DBUILD_TESTING=OFF
cmake --build "$src/absl-build" -j "$JOBS"
cmake --install "$src/absl-build"

cmake -S "$src/re2-${RE2_VERSION}" -B "$src/re2-build" "${common[@]}" \
    -DRE2_BUILD_TESTING=OFF
cmake --build "$src/re2-build" -j "$JOBS"
cmake --install "$src/re2-build"

# cgo runs "pkg-config --cflags --libs re2" without --static, so the full
# static link line goes into Libs. The C++ runtime flags are not allowed in
# pkg-config output; the Makefile passes them through CGO_LDFLAGS.
libs=$(PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" pkg-config --static --libs-only-l re2)
mkdir -p "$PREFIX/lib/pkgconfig/static"
cat > "$PREFIX/lib/pkgconfig/static/re2.pc" <<EOF
Name: re2
Description: RE2 and Abseil, static
Version: ${RE2_VERSION}
Cflags: -I${PREFIX}/include
Libs: -L${PREFIX}/lib -Wl,--start-group ${libs} -Wl,--end-group
EOF

echo "PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig/static"
