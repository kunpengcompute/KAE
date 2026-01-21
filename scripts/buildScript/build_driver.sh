#!/bin/bash
set -e
# Get the directory of the current script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/common.sh"

function build_driver()
{
    lsmod | grep -q "^hisi_migration"       && modprobe -r hisi_migration
    lsmod | grep -q "^hisi_acc_vfio_pci"    && modprobe -r hisi_acc_vfio_pci
    lsmod | grep -q "^hisi_zip"             && modprobe -r hisi_zip
    lsmod | grep -q "^hisi_hpre"            && modprobe -r hisi_hpre
    lsmod | grep -q "^hisi_sec2"            && modprobe -r hisi_sec2
    lsmod | grep -q "^hisi_qm"              && modprobe -r hisi_qm
    lsmod | grep -q "^uacce"                && modprobe -r uacce

    cd ${KAE_KERNEL_DIR}
    
    if [ "$1" = "migration" ]; then 
        make ENABLE_MIGRATION=y -j"$(kae_jobs)"
        make nosva ENABLE_MIGRATION=y
    else
        make -j"$(kae_jobs)" 
        make nosva #默认使用nosva模式
    fi
    # make install
    # chmod 666 /dev/hisi_*
}

function build_driver_sva()
{
    cd ${KAE_KERNEL_DIR}
    make -j"$(kae_jobs)"
    # make nosva #默认使用nosva模式
    if [ "$1" = "migration" ]; then 
        make install ENABLE_MIGRATION=y
    else 
        make install #默认使用nosva模式
    fi
    chmod 666 /dev/hisi_*
}

function driver_clean()
{
    cd ${KAE_KERNEL_DIR}
    if [ "$1" = "migration" ]; then 
        make uninstall ENABLE_MIGRATION=y
    else 
        make uninstall #默认使用nosva模式
    fi
    make clean
}

function driver_delete()
{
    cd ${KAE_KERNEL_DIR}
    make delete-modules
}

function driver_check()
{
    cd ${KAE_KERNEL_DIR}
    make check
}

# Main execution logic
check_environment
build_check_OS_version

# Handle arguments
ACTION=$1
OPTION=$2

case "$ACTION" in
    "driver")
        if [ "$OPTION" = "clean" ]; then  
            driver_clean
        elif [ "$OPTION" = "sva" ]; then  
            build_driver_sva
        elif [ "$OPTION" = "check" ]; then  
            driver_check
        elif [ "$OPTION" = "delete" ]; then  
            driver_delete
        else  
            build_driver
        fi  
        ;;
    "driver_migration")
        if [ "$OPTION" = "clean" ]; then  
            driver_clean migration
        elif [ "$OPTION" = "sva" ]; then  
            build_driver_sva migration
        elif [ "$OPTION" = "check" ]; then  
            driver_check
        elif [ "$OPTION" = "delete" ]; then  
            driver_delete
        else  
            build_driver migration
        fi  
        ;;
    *)
        echo "Usage: $0 {driver|driver_migration} [clean|sva|check|delete]"
        exit 1
        ;;
esac
