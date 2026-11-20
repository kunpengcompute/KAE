#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

function build_provider()
{
    local openssl_install_path="${1:-}"
    local openssl_version

    if [ -z "$openssl_install_path" ]; then
        openssl_install_path="$(dirname "$(dirname "$(command -v openssl)")")"
    fi
    openssl_install_path="$(cd "$openssl_install_path" && pwd)"
    [ -f "$openssl_install_path/include/openssl/opensslv.h" ] ||
        kae_die "OpenSSL headers not found under $openssl_install_path"
    [ -x "$openssl_install_path/bin/openssl" ] ||
        kae_die "OpenSSL executable not found under $openssl_install_path"

    export LD_LIBRARY_PATH="$openssl_install_path/lib64:$openssl_install_path/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export PKG_CONFIG_PATH="$openssl_install_path/lib64/pkgconfig:$openssl_install_path/lib/pkgconfig:/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    openssl_version="$("$openssl_install_path/bin/openssl" version)"
    case "$openssl_version" in
        "OpenSSL 3."*) ;;
        *) kae_die "KAE provider requires OpenSSL 3.x; found: $openssl_version" ;;
    esac
    cd "${SRC_PATH}/KAEOpensslProvider"
    autoreconf -fi
    ./configure --prefix="$openssl_install_path" --libdir=/usr/local/lib/provider \
        --enable-kae --with-openssl_install_dir="$openssl_install_path"
    make -j"$(kae_jobs)"
    make install
}

function clean_provider()
{
    cd "${SRC_PATH}/KAEOpensslProvider"
    if [ -f Makefile ]; then
        make uninstall
        make clean
    fi
}

case "${1:-}" in
    ossl_provider)
        if [ "${2:-}" = clean ]; then
            clean_provider
        else
            build_provider "${2:-}"
        fi
        ;;
    *) kae_die "Usage: bash build.sh ossl_provider [OpenSSL-prefix|clean]" ;;
esac
