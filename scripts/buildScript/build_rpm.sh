#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/common.sh"

function build_all_comp_sva()
{
    kae_prepare_dir_clean "$KAE_BUILD"

    mkdir -p "$KAE_BUILD_LIB"
    mkdir -p "$KAE_BUILD_HEAD"
    # 编译Kernel
    cd "${KAE_KERNEL_DIR}"
    make -j"$(kae_jobs)"

    cp "${KAE_KERNEL_DIR}/hisilicon/sec2/hisi_sec2.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/hisilicon/hpre/hisi_hpre.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/hisilicon/hisi_qm.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/uacce/uacce.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/hisilicon/zip/hisi_zip.ko" "$KAE_BUILD_LIB"

    # 编译uadk
    cd "$KAE_UADK_DIR"
    bash autogen.sh
    bash conf.sh
    make -j"$(kae_jobs)"

    cp "${KAE_UADK_DIR}"/.libs/lib* "$KAE_BUILD_LIB"
    mkdir -p "$KAE_BUILD_HEAD/uadk"
    mkdir -p "$KAE_BUILD_HEAD/uadk/v1"
    cp -r "${KAE_UADK_DIR}/include/"* "$KAE_BUILD_HEAD/uadk"
        
    cp -r "${KAE_UADK_DIR}/v1/"*.h "$KAE_BUILD_HEAD/uadk/v1"

    # 编译openssl
    cd "$KAE_OPENSSL_DIR"
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/
    make -j"$(kae_jobs)"

    cp "$KAE_OPENSSL_DIR"/src/.libs/*kae*so* "$KAE_BUILD_LIB"

    # 编译zlib
    cd "$KAE_ZLIB_DIR"
    bash setup.sh devbuild KAE2

    cp "$KAE_ZLIB_DIR"/lib* "$KAE_BUILD_LIB"
    cp "$KAE_ZLIB_DIR"/open_source/zlib-1.2.11/lib* "$KAE_BUILD_LIB"

    # 编译zstd
    cd "$KAE_ZSTD_DIR"
    bash build.sh devbuild

    cp "$KAE_ZSTD_DIR"/lib* "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/programs/zstd "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/programs/zstdgrep "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/programs/zstdless "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/lib/libzstd.so* "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/lib/libzstd.a "$KAE_BUILD_LIB"
}

source "$SCRIPT_DIR/build_package_components.sh"

function build_rpm()
{
    local kernel_version
    kernel_version=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel | head -n 1)
    build_package_components "$kernel_version"
}

# Main execution logic
check_environment
build_check_OS_version

ACTION=$1

case "$ACTION" in
    "rpm")  
        set +e  
        build_rpm  
        ;;
    "rpmpack")  
        rm -rf /root/rpmbuild/SOURCES/kae* /root/rpmbuild/RPMS/aarch64/kae-* "$KAE_BUILD"
        mkdir -p "$KAE_BUILD" /root/rpmbuild/SOURCES  
        tar --exclude=kae_output -zcvf /root/rpmbuild/SOURCES/kae-2.2.0.tar.gz .
        rpmbuild -bb "$KAE_SPEC_FILE" --define "kae_allow_non_kunpeng ${KAE_ALLOW_NON_KUNPENG_BUILD:-0}"  
        cp /root/rpmbuild/RPMS/aarch64/kae* "$KAE_BUILD"  
        ;;
    "all_sva")
        build_all_comp_sva
        ;;
    *)
        echo "Usage: $0 {rpm|rpmpack|all_sva}"
        exit 1
        ;;
esac
