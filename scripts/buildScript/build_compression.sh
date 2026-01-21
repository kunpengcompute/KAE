#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/common.sh"

function build_zlib()
{
    cd ${SRC_PATH}/KAEZlib
    bash setup.sh install
}

function zlib_clean()
{
    cd ${SRC_PATH}/KAEZlib
    bash setup.sh uninstall
    rm -rf /usr/local/kaezip
}

function build_zstd()
{
    cd ${SRC_PATH}/KAEZstd
    bash build.sh install
}

function zstd_clean()
{
    cd ${SRC_PATH}/KAEZstd
    bash build.sh uninstall
    rm -rf /usr/local/kaezstd/
}

function build_lz4()
{
    cd ${SRC_PATH}/KAELz4
    bash build.sh install
}

function lz4_clean()
{
    cd ${SRC_PATH}/KAELz4
    bash build.sh uninstall
    rm -rf /usr/local/kaelz4/
}

function build_gzip()
{
    cd ${SRC_PATH}/KAEGzip
    bash build.sh install
}

function gzip_clean()
{
    cd ${SRC_PATH}/KAEGzip
    bash build.sh uninstall
}

# Main execution logic
check_environment
build_check_OS_version

ACTION=$1
OPTION=$2

case "$ACTION" in
    "zlib")  
        if [ "$OPTION" = "clean" ]; then  
            zlib_clean
        else  
            build_zlib
        fi  
        ;;  
    "zstd")  
        if [ "${IMPLEMENTER}-${CPUPART}" == "0x48-0xd01" ]; then  
            echo "This CPU does not support zstd."  
        else  
            if [ "$OPTION" = "clean" ]; then  
                zstd_clean
            else  
                build_zstd
            fi  
        fi  
        ;;  
    "lz4")  
        if [ "${IMPLEMENTER}-${CPUPART}" == "0x48-0xd01" ]; then  
            echo "This CPU does not support lz4."  
        else  
            if [ "$OPTION" = "clean" ]; then  
                lz4_clean
            else  
                build_lz4
            fi  
        fi  
        ;;  
    "gzip")
        if [ "$OPTION" = "clean" ]; then  
            gzip_clean
        else  
            build_gzip
        fi  
        ;;
    *)
        echo "Usage: $0 {zlib|zstd|lz4|gzip} [clean]"
        exit 1
        ;;
esac
