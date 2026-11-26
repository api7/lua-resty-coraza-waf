#!/usr/bin/env bash
#
# Packs the release tarball from prebuilt/coraza_waf-{x86_64,aarch64}.so and
# writes the rockspec to publish next to it: the committed
# rockspec/lua-resty-coraza-waf-<version>-1.rockspec plus the md5 of the
# tarball.
#
#   ci/package.sh 0.1.0
#
set -euo pipefail

version=${1:?version}
name=lua-resty-coraza-waf-${version}
rockspec=rockspec/lua-resty-coraza-waf-${version}-1.rockspec

test -f "$rockspec" || { echo "missing $rockspec" >&2; exit 1; }
for arch in x86_64 aarch64; do
    test -f "prebuilt/coraza_waf-${arch}.so" || { echo "missing $arch library" >&2; exit 1; }
done

rm -rf "dist/$name"
mkdir -p "dist/$name"
cp -r Makefile LICENSE README.md lib prebuilt "dist/$name/"
tar -C dist -czf "dist/$name.tar.gz" "$name"
rm -rf "dist/$name"

md5=$(md5sum "dist/$name.tar.gz" | cut -d' ' -f1)
awk -v md5="$md5" '{ print } /^   url = / { print "   md5 = \"" md5 "\"," }' \
    "$rockspec" > "dist/$(basename "$rockspec")"
grep -q "md5 = \"$md5\"" "dist/$(basename "$rockspec")"
ls -la dist
