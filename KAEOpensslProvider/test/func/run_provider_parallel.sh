#!/usr/bin/env bash
set -euo pipefail
: "${OPENSSL_PREFIX:?Set OPENSSL_PREFIX to the matching OpenSSL installation}"
: "${OPENSSL_MODULES:?Set OPENSSL_MODULES to the candidate provider directory}"
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-$PWD}/kae-provider-parallel.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
ulimit -c 0
LIBDIR="$OPENSSL_PREFIX/lib"
[[ -f "$LIBDIR/libcrypto.so" ]] || LIBDIR="$OPENSSL_PREFIX/lib64"
export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"
CFLAGS=(-O2 -g -Wall -Wextra -Werror -pthread)
LDFLAGS=()
if [[ "${SANITIZE:-0}" == 1 ]]; then
    CFLAGS=(-O1 -g -Wall -Wextra -Werror -pthread -fsanitize=address -fno-omit-frame-pointer)
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}"
    if [[ -n "${ASAN_LIB_DIR:-}" ]]; then
        LDFLAGS+=(-L"$ASAN_LIB_DIR" -Wl,-rpath,"$ASAN_LIB_DIR")
        export LD_LIBRARY_PATH="$ASAN_LIB_DIR:$LD_LIBRARY_PATH"
    fi
fi
"${CC:-cc}" "${CFLAGS[@]}" \
    -I"$OPENSSL_PREFIX/include" "$SOURCE_DIR/provider_parallel_test.c" \
    "${LDFLAGS[@]}" -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$WORK/parallel"
if [[ $# -gt 0 ]]; then
    timeout 300 "$WORK/parallel" "$@"
    exit
fi
for bits in 128 192 256; do
    for mode in CBC ECB CTR OFB CFB; do
        timeout 300 "$WORK/parallel" "AES-$bits-$mode" 1 32 7 global explicit
    done
done
for alg in AES-128-XTS AES-256-XTS SM4-CBC SM4-ECB SM4-CTR SM4-OFB SM4-CFB; do
    timeout 300 "$WORK/parallel" "$alg" 1 32 7 global explicit
done
for alg in MD5 SM3; do
    timeout 300 "$WORK/parallel" "$alg" 1 32 13 global explicit
done
for alg in rsa1024 rsa2048 rsa3072 rsa4096 sm2 dh2048 dh3072 dh4096 rand-public rand-private; do
    timeout 300 "$WORK/parallel" "$alg" 1 32 2 global explicit
done
for context in global shared isolated; do
    for selection in explicit prefer; do
        for threads in 4 8; do
            timeout 300 "$WORK/parallel" mixed "$threads" 32 13 "$context" "$selection"
        done
    done
done
timeout 300 "$WORK/parallel" mixed 4 32 13 isolated partition
