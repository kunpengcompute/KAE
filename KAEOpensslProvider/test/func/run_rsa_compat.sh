#!/usr/bin/env bash
set -euo pipefail

# Use the same OpenSSL prefix that was used to build kae_provider.so.
: "${OPENSSL_PREFIX:?Set OPENSSL_PREFIX to the target OpenSSL installation}"
: "${OPENSSL_MODULES:?Set OPENSSL_MODULES to the candidate provider directory}"
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-$PWD}/kae-rsa-test.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT

LIBDIR="$OPENSSL_PREFIX/lib"
if [[ ! -f "$LIBDIR/libcrypto.so" ]]; then
    LIBDIR="$OPENSSL_PREFIX/lib64"
fi
export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"

"${CC:-cc}" -O2 -g -Wall -Wextra -pthread \
    -I"$OPENSSL_PREFIX/include" "$SOURCE_DIR/rsa_compat_test.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$WORK/rsa-compat"

"$OPENSSL_PREFIX/bin/openssl" version
for bits in 1024 2048 3072 4096; do
    for mode in 0 1; do
        timeout 120 "$WORK/rsa-compat" "$bits" "$mode"
    done
done
timeout 120 "$WORK/rsa-compat" 2048 2
