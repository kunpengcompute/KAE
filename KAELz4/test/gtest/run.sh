#!/bin/bash

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:${LD_LIBRARY_PATH:-}
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8

sh "${SCRIPT_DIR}/build.sh"

exec "${SCRIPT_DIR}/kaelz4test" "$@"
