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

function build_rpm()
{
    kae_prepare_dir_clean "$KAE_BUILD"
    mkdir -p "$KAE_BUILD_LIB"
    mkdir -p "$KAE_BUILD_HEAD"

    local KERNEL_VERSION_BY_BUILDENV=`rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel | head -n 1`

    # 编译 driver 
    cd "${KAE_KERNEL_DIR}"
    make KERNEL_VERSION_BY_BUILDENV="${KERNEL_VERSION_BY_BUILDENV}" -j"$(kae_jobs)"

    mkdir -p "$KAE_BUILD/driver"
    cp "${KAE_KERNEL_DIR}/hisilicon/sec2/hisi_sec2.ko" "$KAE_BUILD/driver"
    cp "${KAE_KERNEL_DIR}/hisilicon/hpre/hisi_hpre.ko" "$KAE_BUILD/driver"
    cp "${KAE_KERNEL_DIR}/hisilicon/hisi_qm.ko" "$KAE_BUILD/driver"
    cp "${KAE_KERNEL_DIR}/uacce/uacce.ko" "$KAE_BUILD/driver"
    cp "${KAE_KERNEL_DIR}/hisilicon/zip/hisi_zip.ko" "$KAE_BUILD/driver"
    cp "${KAE_KERNEL_DIR}"/conf/*.conf "$KAE_BUILD/driver"

    # 编译 uadk
    kae_require_cmd patch
    kae_apply_uadk_patches

    cd "$KAE_UADK_DIR"
    bash autogen.sh
    # bash conf.sh
    # 在 conf.sh中的内容后添加 --prefix 参数，为了使uadk编译生成的pkgconfig/*.pc文件中动态库的路径为RPM包编译时的临时目录，这样Opensslengine编译时才能够找到uadk动态库。
    ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
        --enable-perf=yes \
        --host aarch64-linux-gnu \
        --target aarch64-linux-gnu \
        --includedir=/usr/local/include/ \
        --disable-static --enable-shared \
        --prefix="$KAE_BUILD/uadk/"
    make -j"$(kae_jobs)"

    mkdir -p "$KAE_BUILD/uadk/lib"
    mkdir -p "$KAE_BUILD/uadk/include"
    mkdir -p "$KAE_BUILD/uadk/include/v1"
    mkdir -p "$KAE_BUILD/uadk/include/drv"
    mkdir -p "$KAE_BUILD/uadk/pkgconfig"

    cp -r "${KAE_UADK_DIR}"/.libs/*.so*              "$KAE_BUILD/uadk/lib"
    cp -r "${KAE_UADK_DIR}"/include/*.h              "$KAE_BUILD/uadk/include"
    cp -r "${KAE_UADK_DIR}"/v1/*.h                   "$KAE_BUILD/uadk/include/v1"
    cp -r "${KAE_UADK_DIR}"/include/drv/*.h          "$KAE_BUILD/uadk/include/drv"
    cp -r "${KAE_UADK_DIR}"/lib/*.pc                 "$KAE_BUILD/uadk/pkgconfig"

    mkdir -p "$KAE_BUILD_HEAD/uadk"
    mkdir -p "$KAE_BUILD_HEAD/uadk/v1"
    mkdir -p "$KAE_BUILD_HEAD/uadk/drv"

    cp -r "${KAE_UADK_DIR}"/include/*.h              "$KAE_BUILD_HEAD/uadk"
    cp -r "${KAE_UADK_DIR}"/v1/*.h                   "$KAE_BUILD_HEAD/uadk/v1"
    cp -r "${KAE_UADK_DIR}"/include/drv/*.h          "$KAE_BUILD_HEAD/uadk/drv"

    mkdir -p "$KAE_BUILD/lib"
    cp "${KAE_UADK_DIR}"/.libs/*.so* "$KAE_BUILD/lib"

    # 编译openssl
    cd "$KAE_OPENSSL_DIR"
    export PKG_CONFIG_PATH="$KAE_BUILD/uadk/pkgconfig"
    autoreconf -i
    ./configure $OPENSSL_CONFIGURE_FLAG
    make -j"$(kae_jobs)"


    mkdir -p "$KAE_BUILD/KAEOpensslEngine/lib"
    cp -r "$KAE_OPENSSL_DIR"/src/.libs/*.so* "$KAE_BUILD/KAEOpensslEngine/lib"

    # 编译 zlib
    cd "$KAE_ZLIB_DIR"
    bash setup.sh devbuild KAE2

    mkdir -p "$KAE_BUILD/kaezip"
    mkdir -p "$KAE_BUILD/kaezip/include"
    mkdir -p "$KAE_BUILD/kaezip/lib"
    mkdir -p "$KAE_BUILD/kaezip/lib/pkgconfig"
    mkdir -p "$KAE_BUILD/kaezip/share/man/man3"

    cp -a "$KAE_ZLIB_DIR"/lib* "$KAE_BUILD/kaezip/lib"
    cp -a "$KAE_ZLIB_DIR"/open_source/zlib-1.2.11/lib* "$KAE_BUILD/kaezip/lib"
    cp "$KAE_ZLIB_DIR"/open_source/zlib-1.2.11/zlib.pc "$KAE_BUILD/kaezip/lib/pkgconfig"
    cp "$KAE_ZLIB_DIR"/include/*.h "$KAE_BUILD/kaezip/include"
    cp "$KAE_ZLIB_DIR"/open_source/zlib-1.2.11/zlib.h "$KAE_BUILD/kaezip/include"
    cp "$KAE_ZLIB_DIR"/open_source/zlib-1.2.11/zconf.h "$KAE_BUILD/kaezip/include"
    cp "$KAE_ZLIB_DIR"/open_source/zlib-1.2.11/zlib.3 "$KAE_BUILD/kaezip/share/man/man3"

    # 编译 gzip
    cd "$KAE_GZIP_DIR"
    bash build.sh devbuild

    mkdir -p "$KAE_BUILD/kaegzip"
    cp "$KAE_GZIP_DIR"/open_source/gzip-1.13/gzip "$KAE_BUILD/kaegzip"

    # 编译 zstd
    cd "$KAE_ZSTD_DIR"
    mkdir -p "$KAE_BUILD/kaezstd/lib/"
    mkdir -p "$KAE_BUILD/kaezstd/include"

    bash build.sh devbuild

    cp -a "$KAE_ZSTD_DIR"/lib* "$KAE_BUILD/kaezstd/lib"
    cp "$KAE_ZSTD_DIR"/include/*.h "$KAE_BUILD/kaezstd/include"

    # 编译 lz4
    cd "${SRC_PATH}/KAELz4"
    bash build.sh devbuild

    mkdir -p "$KAE_BUILD/kaelz4/lib"
    mkdir -p "$KAE_BUILD/kaelz4/bin"
    mkdir -p "$KAE_BUILD/kaelz4/include"
    mkdir -p "$KAE_BUILD/kaelz4/share/man/man1"

    cp -a "$KAE_LZ4_DIR"/lib* "$KAE_BUILD/kaelz4/lib"
    cp -a "$KAE_LZ4_DIR"/open_source/lz4-1.9.4/lib/liblz4.so* "$KAE_BUILD/kaelz4/lib"
    cp "$KAE_LZ4_DIR"/open_source/lz4-1.9.4/lib/liblz4.a "$KAE_BUILD/kaelz4/lib"

    cp "$KAE_LZ4_DIR"/open_source/lz4-1.9.4/programs/lz4 "$KAE_BUILD/kaelz4/bin"
    cp "$KAE_LZ4_DIR"/open_source/lz4-1.9.4/lib/*.h "$KAE_BUILD/kaelz4/include"
    cp "$KAE_LZ4_DIR"/include/*.h "$KAE_BUILD/kaelz4/include"
    cp "$KAE_LZ4_DIR"/src/utils/kaelz4_log.h "$KAE_BUILD/kaelz4/include"
    cp "$KAE_LZ4_DIR"/open_source/lz4-1.9.4/programs/lz4.1 "$KAE_BUILD/kaelz4/share/man/man1"

    # 编译 kaesnappy
    cd "${SRC_PATH}/KAESnappy"
    mkdir -p "$KAE_BUILD/kaesnappy/lib"
    mkdir -p "$KAE_BUILD/kaesnappy/include"
    bash build.sh devbuild

    cp -a "$KAE_SNAPPY_DIR"/lib* "$KAE_BUILD/kaesnappy/lib"
    cp "$KAE_SNAPPY_DIR"/include/kaesnappy.h "$KAE_BUILD/kaesnappy/include"
    cp "$KAE_SNAPPY_DIR"/src/utils/kaesnappy_log.h "$KAE_BUILD/kaesnappy/include"
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
        tar -zcvf /root/rpmbuild/SOURCES/kae-2.2.0.tar.gz .
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
