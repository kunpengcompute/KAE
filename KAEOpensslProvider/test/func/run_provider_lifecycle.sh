#!/usr/bin/env bash
set -euo pipefail
: "${OPENSSL_PREFIX:?Set OPENSSL_PREFIX to the matching OpenSSL installation}"
: "${OPENSSL_MODULES:?Set OPENSSL_MODULES to the candidate provider directory}"
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-$PWD}/kae-provider-lifecycle.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
ulimit -c 0
LIBDIR="$OPENSSL_PREFIX/lib"
[[ -f "$LIBDIR/libcrypto.so" ]] || LIBDIR="$OPENSSL_PREFIX/lib64"
export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"
CFLAGS=(-O2 -g -Wall -Wextra)
LDFLAGS=()
if [[ "${SANITIZE:-0}" == 1 ]]; then
    CFLAGS=(-O1 -g -Wall -Wextra -fsanitize=address -fno-omit-frame-pointer)
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}"
    if [[ -n "${ASAN_LIB_DIR:-}" ]]; then
        LDFLAGS+=(-L"$ASAN_LIB_DIR" -Wl,-rpath,"$ASAN_LIB_DIR")
        export LD_LIBRARY_PATH="$ASAN_LIB_DIR:$LD_LIBRARY_PATH"
    fi
fi
"${CC:-cc}" "${CFLAGS[@]}" -I"$OPENSSL_PREFIX/include" \
    "$SOURCE_DIR/provider_lifecycle_test.c" "${LDFLAGS[@]}" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$WORK/lifecycle"
for mode in simple reload contexts selection; do
    timeout 120 "$WORK/lifecycle" "$mode"
done
