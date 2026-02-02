#!/bin/bash
set -e
# Get the directory of the current script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source ${SCRIPT_DIR}/scripts/buildScript/common.sh

function build_all_components()
{
    bash ${SCRIPT_DIR}/scripts/buildScript/build_driver.sh driver
    bash ${SCRIPT_DIR}/scripts/buildScript/build_uadk.sh uadk
    bash ${SCRIPT_DIR}/scripts/buildScript/build_engine.sh engine
    bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh zlib
    bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh gzip
    if [ "${IMPLEMENTER}-${CPUPART}" == "0x48-0xd01" ];then
        echo "this cpu not support kaezstd, kaelz4 and kaesnappy."
    else
        bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh zstd
        bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh lz4
        bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh snappy
    fi
}

function clear_all_components()
{
    bash ${SCRIPT_DIR}/scripts/buildScript/build_driver.sh driver clean     || true  
    bash ${SCRIPT_DIR}/scripts/buildScript/build_uadk.sh uadk clean         || true 
    bash ${SCRIPT_DIR}/scripts/buildScript/build_engine.sh engine clean     || true  
    bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh zlib clean  || true  
    bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh gzip clean  || true
 
    if [ "${IMPLEMENTER}-${CPUPART}" == "0x48-0xd01" ];then
        echo "this cpu not support kaezstd, kaelz4 and kaesnappy."
    else
        bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh zstd clean   || true  
        bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh lz4 clean    || true
        bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh snappy clean || true
    fi
}

function help()
{
    cat << EOF
Usage: sh build.sh <command> [options]

Description: Build and manage KAE (Kunpeng Accelerator Engine) components.

Commands:
  General:
    all                     Install all components (excluding gmssl/tongsuo/boringssl)
    rpmpack                 Build RPM package (excluding gmssl/tongsuo/boringssl)
    cleanup                 Clean up all components

  Driver:
    driver                  Install KAE driver
    driver clean            Uninstall KAE driver
    driver_migration        Install KAE driver with migration support
    driver_migration clean  Uninstall KAE driver with migration support

  UADK:
    uadk                    Install UADK
    uadk clean              Uninstall UADK

  OpenSSL Engine:
    engine                  Install KAE OpenSSL engine
    engine clean            Uninstall KAE OpenSSL engine
    engine3 <path>          Install KAE OpenSSL 3.0 engine (specify OpenSSL 3.0 install path)
    engine3 clean           Uninstall KAE OpenSSL 3.0 engine
    engine_gmssl            Install KAE GmSSL engine
    engine_gmssl clean      Uninstall KAE GmSSL engine
    engine3_tongsuo         Install KAE Tongsuo engine
    engine3_tongsuo clean   Uninstall KAE Tongsuo engine
    engine_boringssl        Install KAE BoringSSL engine
    engine_boringssl clean  Uninstall KAE BoringSSL engine

  Compression:
    zlib                    Install KAE-accelerated zlib
    zlib clean              Uninstall KAE-accelerated zlib
    zstd                    Install KAE-accelerated zstd
    zstd clean              Uninstall KAE-accelerated zstd
    gzip                    Install KAE-accelerated gzip
    gzip clean              Uninstall KAE-accelerated gzip
    lz4                     Install KAE-accelerated lz4
    lz4 clean               Uninstall KAE-accelerated lz4
    snappy                  Install KAE-accelerated snappy
    snappy clean            Uninstall KAE-accelerated snappy
EOF
}

main() {  
    check_environment  
    build_check_OS_version  
    export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
    
    case "$1" in  
        "all")  
            build_all_components  
            ;;  
        "driver"|"driver_migration")  
            bash ${SCRIPT_DIR}/scripts/buildScript/build_driver.sh "$@"
            ;;  
        "uadk")  
            bash ${SCRIPT_DIR}/scripts/buildScript/build_uadk.sh "$@"
            ;;  
        "engine"|"engine_asm"|"engine3"|"engine3_asm"|"engine_gmssl"|"engine3_tongsuo"|"engine_boringssl")  
            bash ${SCRIPT_DIR}/scripts/buildScript/build_engine.sh "$@"
            ;;
        "zlib"|"zstd"|"lz4"|"gzip"|"snappy")  
            bash ${SCRIPT_DIR}/scripts/buildScript/build_compression.sh "$@"
            ;;  
        "rpm")  
            set +e  
            clear_all_components  
            set -e  
            bash ${SCRIPT_DIR}/scripts/buildScript/build_rpm.sh rpm  
            ;;  
        "rpmpack")  
            bash ${SCRIPT_DIR}/scripts/buildScript/build_rpm.sh rpmpack
            ;;  
        "cleanup")  
            echo "Cleanup all"  
            clear_all_components  
            rm -rf $KAE_BUILD/*  
            ;;  
        *)  
            help  
            ;;  
    esac  
}  

main "$@"
exit $?
