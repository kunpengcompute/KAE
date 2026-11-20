#!/usr/bin/env bash
set -euo pipefail

: "${OPENSSL_PREFIX:?Set OPENSSL_PREFIX to the target OpenSSL installation}"
: "${OPENSSL_MODULES:?Set OPENSSL_MODULES to the candidate provider directory}"
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-$PWD}/kae-cipher-test.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
LIBDIR="$OPENSSL_PREFIX/lib"
if [[ ! -f "$LIBDIR/libcrypto.so" ]]; then
    LIBDIR="$OPENSSL_PREFIX/lib64"
fi
export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-/dev/null}"

"${CC:-cc}" -O2 -g -Wall -Wextra -pthread \
    -I"$OPENSSL_PREFIX/include" "$SOURCE_DIR/cipher_stream_test.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$WORK/cipher-stream"
"$OPENSSL_PREFIX/bin/openssl" version
for mode in sync async; do
    timeout 120 "$WORK/cipher-stream" "$mode" "$@"
done
