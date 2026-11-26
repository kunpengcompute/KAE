#!/bin/sh
# Read the KAE release only; upstream and BoostKit versions are independent.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(cat "$root/VERSION")
if ! printf '%s\n' "$version" | LC_ALL=C grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
   [ "$(printf '%s\n' "$version" | wc -l | tr -d ' ')" != 1 ]; then
    echo "Invalid KAE VERSION: expected MAJOR.MINOR.PATCH without leading zeros" >&2
    exit 1
fi
case "${1:---version}" in
    --version) printf '%s\n' "$version" ;;
    --libtool) printf '%s\n' "$version" | tr . : ;;
    *) echo "Usage: sh $0 [--version|--libtool]" >&2; exit 1 ;;
esac
