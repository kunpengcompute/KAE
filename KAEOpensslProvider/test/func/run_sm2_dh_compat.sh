#!/usr/bin/env bash
set -euo pipefail
: "${OPENSSL_PREFIX:?Set OPENSSL_PREFIX to the matching OpenSSL installation}"
: "${OPENSSL_MODULES:?Set OPENSSL_MODULES to the candidate provider directory}"
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-$PWD}/kae-sm2-dh-test.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
LIBDIR="$OPENSSL_PREFIX/lib"
[[ -f "$LIBDIR/libcrypto.so" ]] || LIBDIR="$OPENSSL_PREFIX/lib64"
export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"
"${CC:-cc}" -O2 -g -Wall -Wextra -pthread \
    -I"$OPENSSL_PREFIX/include" "$SOURCE_DIR/sm2_dh_compat_test.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$WORK/sm2-dh-compat"
"$OPENSSL_PREFIX/bin/openssl" version
for mode in sync async; do
    timeout 120 "$WORK/sm2-dh-compat" sm2-sign 32 "$mode"
    for size in 16 64 256 1024; do
        for alg in sm2-stream sm2-crypt sm2-sha256; do
            timeout 120 "$WORK/sm2-dh-compat" "$alg" "$size" "$mode"
        done
    done
    for size in 2048 3072 4096 6144 8192; do
        timeout 120 "$WORK/sm2-dh-compat" dh "$size" "$mode"
        if [[ "$size" -le 4096 ]]; then
            timeout 120 "$WORK/sm2-dh-compat" dh-pg "$size" "$mode"
        fi
    done
done
for alg in sm2-sign sm2-stream sm2-crypt sm2-sha256; do
    size=64
    [[ "$alg" != sm2-sign ]] || size=32
    timeout 120 "$WORK/sm2-dh-compat" "$alg" "$size" async32
done
timeout 120 "$WORK/sm2-dh-compat" dh 2048 async32
for size in 2048 3072 4096; do
    timeout 120 "$WORK/sm2-dh-compat" dh-pg "$size" async32
done
for alg in rand-private rand-public; do
    for size in 32 256 8192; do
        timeout 120 "$WORK/sm2-dh-compat" "$alg" "$size" async32
    done
done
if [[ "${RUN_BOUNDS:-0}" == 1 ]]; then
    for mode in sync async; do
        timeout 120 "$WORK/sm2-dh-compat" sm2-bounds 32 "$mode"
    done
fi
