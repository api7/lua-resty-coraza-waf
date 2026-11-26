#!/usr/bin/env bash
#
# Writes the license texts of the third-party code linked into coraza_waf.so:
# the Go modules and the Go standard library it is built from, and RE2 and
# Abseil from the prefix written by scripts/build-re2.sh. Run it after
# "make build", so that the Go modules are in the module cache.
#
#   scripts/third-party-notices.sh RE2_PREFIX OUTPUT
#
# The C++ runtime is linked under the GCC Runtime Library Exception, which
# needs no notice.
set -euo pipefail

prefix=${1:?RE2 prefix}
out=${2:?output file}
tags=${GO_TAGS:-$(make -s -f "$(dirname "$0")/../Makefile" print-go-tags)}

section() {
    printf '%s\n%s\n%s\n\n' \
        "================================================================================" \
        "$1" \
        "================================================================================"
}

# the license files at the root of a source tree; none is an error
licenses() {
    local dir=$1 name=$2 found=0 f
    for f in "$dir"/*; do
        case "$(basename "$f" | tr '[:upper:]' '[:lower:]')" in
            *.go) ;;
            license* | licence* | copying* | notice*)
                [ -f "$f" ] || continue
                printf -- '--- %s ---\n\n' "$(basename "$f")"
                cat "$f"
                printf '\n'
                found=1
                ;;
        esac
    done
    if [ "$found" -eq 0 ]; then
        echo "no license file for $name in $dir" >&2
        return 1
    fi
}

{
    echo "coraza_waf.so contains the following third-party code."
    echo

    section "Go standard library $(cd go && go env GOVERSION)"
    licenses "$(cd go && go env GOROOT)" "the Go standard library"

    for name in re2 abseil-cpp; do
        section "$name $(cat "$prefix/share/licenses/$name/VERSION")"
        licenses "$prefix/share/licenses/$name" "$name"
    done

    # the modules of the packages linked into the library, not of the whole
    # module graph
    (cd go && go list -deps -tags "$tags" \
        -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' .) |
        sort -u |
        while read -r path version dir; do
            section "$path $version"
            licenses "$dir" "$path"
        done
} > "$out"
