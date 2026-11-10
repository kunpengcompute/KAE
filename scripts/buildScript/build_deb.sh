#!/bin/bash
# Expand the upstream packaging template into a separate Debian build tree.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
case "${1:-}" in
    -h|--help)
        echo 'Usage: bash build.sh debpack [dpkg-buildpackage options]'
        echo 'Defaults: binary ARM64 packages, running kernel (uname -r), OpenSSL 3.0.'
        echo 'Install matching kernel headers first.'
        echo 'KAE layout: scripts/debian is staged under kae_output/debpack/run.XXXXXX/.'
        echo 'Ubuntu layout: root debian is used directly; output is in the parent directory.'
        exit 0 ;;
esac

# Resolve headers relative to the caller before changing into the source tree.
if [ -n "${KERNEL_DIR:-}" ]; then
    if ! resolved_kernel_dir=$(cd -- "$KERNEL_DIR" && pwd -P); then
        printf 'Invalid KERNEL_DIR: %s. Check the path and install the matching kernel headers.\n' "$KERNEL_DIR" >&2
        exit 1
    fi
    export KERNEL_DIR="$resolved_kernel_dir"
fi
cd "$ROOT"

if [ -e debian ] || [ -L debian ]; then
    [ -f debian/control ] && [ -f debian/rules ] || {
        echo 'The existing root debian directory is incomplete.' >&2
        exit 1
    }
    [ ! -e scripts/debian ] || {
        echo 'Keep one packaging directory: scripts/debian in KAE, or debian in the Ubuntu repository.' >&2
        exit 1
    }
    PACKAGING=debian
else
    PACKAGING=scripts/debian
    [ -f "$PACKAGING/control" ] && [ -f "$PACKAGING/rules" ] || {
        echo "Missing Debian packaging files: $PACKAGING" >&2
        exit 1
    }
fi
command -v dpkg-buildpackage >/dev/null || {
    echo "Install the Build-Depends from $PACKAGING/control first." >&2
    exit 1
}

if [ "$PACKAGING" = scripts/debian ]; then
    mkdir -p "$ROOT/kae_output/debpack"
    WORK=$(mktemp -d "$ROOT/kae_output/debpack/run.XXXXXX")
    SOURCE="$WORK/source"
    mkdir "$SOURCE"
    printf 'Debian build tree: %s\nPackage output directory: %s\n' "$SOURCE" "$WORK"

    excludes=(--exclude=.git --exclude=kae_build --exclude=kae_output --exclude=.vscode
              --exclude=.DS_Store --exclude='._*')
    if command -v git >/dev/null &&
        [ "$(git rev-parse --show-toplevel 2>/dev/null || true)" = "$ROOT" ]; then
        # Include local source edits and new files, but no ignored build/debug data.
        git ls-files --cached --others --exclude-standard -z |
            while IFS= read -r -d '' file; do
                [ -e "$file" ] || [ -L "$file" ] || continue
                printf '%s\0' "$file"
            done |
            tar "${excludes[@]}" --null --no-recursion -T - -cf - |
            tar -C "$SOURCE" -xf -
    else
        # Also support an unpacked upstream source archive without Git metadata.
        tar "${excludes[@]}" -cf - . | tar -C "$SOURCE" -xf -
    fi
    mv "$SOURCE/scripts/debian" "$SOURCE/debian"
    cd "$SOURCE"
fi
exec dpkg-buildpackage -b -us -uc "$@"
