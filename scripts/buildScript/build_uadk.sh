#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/common.sh"

function build_uadk()
{
    kae_require_cmd patch
    kae_apply_uadk_patches

    cd "${SRC_PATH}/uadk"
    bash autogen.sh
    bash conf.sh
    make -j"$(kae_jobs)"
    make install
}

function uadk_clean()
{
    cd "${SRC_PATH}/uadk"
    make uninstall
    make clean
    bash cleanup.sh
}

# Main execution logic
check_environment
build_check_OS_version

ACTION=$1
OPTION=$2

case "$ACTION" in
    "uadk")
        if [ "$OPTION" = "clean" ]; then
            uadk_clean
        else
            build_uadk
        fi
        ;;
    *)
        echo "Usage: $0 uadk [clean]"
        exit 1
        ;;
esac
