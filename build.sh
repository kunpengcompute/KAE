#!/bin/bash
set -e
SRC_PATH=$(pwd)
KAE_KERNEL_DIR=""
KAE_SPEC_FILE=""
OPENSSL_CONFIGURE_FLAG=""
KAE_UADK_DIR=${SRC_PATH}/uadk
KAE_OPENSSL_DIR=${SRC_PATH}/KAEOpensslEngine
KAE_ZLIB_DIR=${SRC_PATH}/KAEZlib
KAE_ZSTD_DIR=${SRC_PATH}/KAEZstd
KAE_LZ4_DIR=${SRC_PATH}/KAELz4
KAE_GZIP_DIR=${SRC_PATH}/KAEGzip

KAE_BUILD=${SRC_PATH}/kae_build/
KAE_BUILD_LIB=${SRC_PATH}/kae_build/lib
KAE_BUILD_HEAD=${SRC_PATH}/kae_build/head

IMPLEMENTER=""
CPUPART=""

function build_check_OS_version()
{
    # local KERNEL_VERSION=`rpm -q --qf '%{VERSION}\n' kernel-devel | head -n 1`
    local KERNEL_VERSION=`uname -r`
    if [[ "$KERNEL_VERSION" == 6.6.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-6.6
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae_openeuler2403.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-3.0 --enable-kae --enable-engine --with-openssl_install_dir=/usr/"
    elif [[ "$KERNEL_VERSION" == 5.15.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-5.10
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-1.1/ --enable-kae"
    elif [[ "$KERNEL_VERSION" == 5.10.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-5.10
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-1.1/ --enable-kae"
    elif [[ "$KERNEL_VERSION" == 5.4.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-5.4
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-1.1/ --enable-kae"
    else
		echo "[KAE error]:unsupport kernel version $KERNEL_VERSION"
    fi
}

function build_all_comp_sva()
{
    if [ -d $KAE_BUILD ]; then
        rm -rf $KAE_BUILD/*
    else
        mkdir $KAE_BUILD
    fi

    mkdir -p $KAE_BUILD_LIB
    mkdir -p $KAE_BUILD_HEAD
    # 编译Kernel
    cd ${KAE_KERNEL_DIR}
    make -j

    cp ${KAE_KERNEL_DIR}/hisilicon/sec2/hisi_sec2.ko $KAE_BUILD_LIB
    cp ${KAE_KERNEL_DIR}/hisilicon/hpre/hisi_hpre.ko $KAE_BUILD_LIB
    cp ${KAE_KERNEL_DIR}/hisilicon/hisi_qm.ko $KAE_BUILD_LIB
    cp ${KAE_KERNEL_DIR}/uacce/uacce.ko $KAE_BUILD_LIB
    cp ${KAE_KERNEL_DIR}/hisilicon/zip/hisi_zip.ko $KAE_BUILD_LIB

    # 编译uadk
    cd $KAE_UADK_DIR
    bash autogen.sh
    bash conf.sh
    make -j

    cp ${KAE_UADK_DIR}/.libs/lib* $KAE_BUILD_LIB
    mkdir -p $KAE_BUILD_HEAD/uadk
    mkdir -p $KAE_BUILD_HEAD/uadk/v1
    cp -r ${KAE_UADK_DIR}/include/* $KAE_BUILD_HEAD/uadk
        
    cp -r ${KAE_UADK_DIR}/v1/*.h $KAE_BUILD_HEAD/uadk/v1

    # 编译openssl
    cd $KAE_OPENSSL_DIR
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/
    make -j

    cp $KAE_OPENSSL_DIR/src/.libs/*kae*so* $KAE_BUILD_LIB

    # 编译zlib
    cd $KAE_ZLIB_DIR
    bash setup.sh devbuild KAE2

    cp $KAE_ZLIB_DIR/lib* $KAE_BUILD_LIB
    cp $KAE_ZLIB_DIR/open_source/zlib-1.2.11/lib* $KAE_BUILD_LIB

    # 编译zstd
    cd $KAE_ZSTD_DIR
    bash build.sh devbuild

    cp $KAE_ZSTD_DIR/lib* $KAE_BUILD_LIB
    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstd $KAE_BUILD_LIB
    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstdgrep $KAE_BUILD_LIB
    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstdless $KAE_BUILD_LIB
    cp $KAE_ZSTD_DIR/open_source/zstd/lib/libzstd.so* $KAE_BUILD_LIB
    cp $KAE_ZSTD_DIR/open_source/zstd/lib/libzstd.a $KAE_BUILD_LIB
}

function build_rpm()
{
    if [ -d $KAE_BUILD ]; then
            rm -rf $KAE_BUILD/*
    else
            mkdir $KAE_BUILD
    fi
    mkdir -p $KAE_BUILD_LIB
    mkdir -p $KAE_BUILD_HEAD

    local KERNEL_VERSION_BY_BUILDENV=`rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel | head -n 1`

    # 编译 driver 
    cd ${KAE_KERNEL_DIR}
    make -j

    mkdir -p $KAE_BUILD/driver
    cp ${KAE_KERNEL_DIR}/hisilicon/sec2/hisi_sec2.ko $KAE_BUILD/driver
    cp ${KAE_KERNEL_DIR}/hisilicon/hpre/hisi_hpre.ko $KAE_BUILD/driver
    cp ${KAE_KERNEL_DIR}/hisilicon/hisi_qm.ko $KAE_BUILD/driver
    cp ${KAE_KERNEL_DIR}/uacce/uacce.ko $KAE_BUILD/driver
    cp ${KAE_KERNEL_DIR}/hisilicon/zip/hisi_zip.ko $KAE_BUILD/driver 
    cp ${KAE_KERNEL_DIR}/conf/*.conf $KAE_BUILD/driver

    # 编译 uadk
    cd ${SRC_PATH}
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0001-uadk-add-ctr-mode.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0001-uadk-add-ctr-mode.patch # uadk没支持ctr模式，engine层已经软件层面适配，可以定制化使能
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0003-fix-uadk-openssl3-bug.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0003-fix-uadk-openssl3-bug.patch
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0005-add-uadk-ecc-and-comp-header-for-kae.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0005-add-uadk-ecc-and-comp-header-for-kae.patch
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0006-fix-uadk-lz77-data-error.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0006-fix-uadk-lz77-data-error.patch

    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0007-uadk-support-lz77-only-for-kaelz4.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0007-uadk-support-lz77-only-for-kaelz4.patch

    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0008-uadk-support-sgl-zero-copy-for-kaelz4.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0008-uadk-support-sgl-zero-copy-for-kaelz4.patch


    cd $KAE_UADK_DIR
    bash autogen.sh
    # bash conf.sh
    # 在 conf.sh中的内容后添加 --prefix 参数，为了使uadk编译生成的pkgconfig/*.pc文件中动态库的路径为RPM包编译时的临时目录，这样Opensslengine编译时才能够找到uadk动态库。
    ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
        --enable-perf=yes \
        --host aarch64-linux-gnu \
        --target aarch64-linux-gnu \
        --includedir=/usr/local/include/ \
        --disable-static --enable-shared \
        --prefix=$KAE_BUILD/uadk/
    make -j

    mkdir -p $KAE_BUILD/uadk/lib
    mkdir -p $KAE_BUILD/uadk/include
    mkdir -p $KAE_BUILD/uadk/include/v1
    mkdir -p $KAE_BUILD/uadk/include/drv
    mkdir -p $KAE_BUILD/uadk/pkgconfig

    cp ${KAE_UADK_DIR}/.libs/*so* $KAE_BUILD/uadk/lib
    cp -r $KAE_UADK_DIR/include/*.h              $KAE_BUILD/uadk/include
    cp -r $KAE_UADK_DIR/v1/*.h                   $KAE_BUILD/uadk/include/v1
    cp -r $KAE_UADK_DIR/include/drv/*.h          $KAE_BUILD/uadk/include/drv
    cp -r $KAE_UADK_DIR/lib/*.pc                 $KAE_BUILD/uadk/pkgconfig

    mkdir -p $KAE_BUILD_HEAD/uadk
    mkdir -p $KAE_BUILD_HEAD/uadk/v1
    mkdir -p $KAE_BUILD_HEAD/uadk/drv

    cp -r $KAE_UADK_DIR/include/*.h              $KAE_BUILD_HEAD/uadk
    cp -r $KAE_UADK_DIR/v1/*.h                   $KAE_BUILD_HEAD/uadk/v1
    cp -r $KAE_UADK_DIR/include/drv/*.h          $KAE_BUILD_HEAD/uadk/drv

    mkdir -p $KAE_BUILD/lib
    cp ${KAE_UADK_DIR}/.libs/*so* $KAE_BUILD/lib


    # 编译openssl
    cd $KAE_OPENSSL_DIR
    export PKG_CONFIG_PATH=$KAE_BUILD/uadk/pkgconfig
    autoreconf -i
    ./configure $OPENSSL_CONFIGURE_FLAG
    make -j


    mkdir -p $KAE_BUILD/KAEOpensslEngine/lib
    cp -r $KAE_OPENSSL_DIR/src/.libs/*so* $KAE_BUILD/KAEOpensslEngine/lib



    # 编译 zlib
    cd $KAE_ZLIB_DIR
    bash setup.sh devbuild KAE2

    mkdir -p $KAE_BUILD/kaezip
    mkdir -p $KAE_BUILD/kaezip/include
    mkdir -p $KAE_BUILD/kaezip/lib
    mkdir -p $KAE_BUILD/kaezip/lib/pkgconfig
    mkdir -p $KAE_BUILD/kaezip/share/man/man3

    cp $KAE_ZLIB_DIR/lib* $KAE_BUILD/kaezip/lib
    cp $KAE_ZLIB_DIR/open_source/zlib-1.2.11/lib* $KAE_BUILD/kaezip/lib
    cp $KAE_ZLIB_DIR/open_source/zlib-1.2.11/zlib.pc $KAE_BUILD/kaezip/lib/pkgconfig
    cp $KAE_ZLIB_DIR/include/*.h $KAE_BUILD/kaezip/include
    cp $KAE_ZLIB_DIR/open_source/zlib-1.2.11/zlib.h $KAE_BUILD/kaezip/include
    cp $KAE_ZLIB_DIR/open_source/zlib-1.2.11/zconf.h $KAE_BUILD/kaezip/include
    cp $KAE_ZLIB_DIR/open_source/zlib-1.2.11/zlib.3 $KAE_BUILD/kaezip/share/man/man3


    # 编译 zstd
    cd $KAE_ZSTD_DIR
    bash build.sh devbuild

    mkdir -p $KAE_BUILD/kaezstd/lib/pkgconfig
    mkdir -p $KAE_BUILD/kaezstd/bin
    mkdir -p $KAE_BUILD/kaezstd/include
    mkdir -p $KAE_BUILD/kaezstd/share/man/man1

    cp $KAE_ZSTD_DIR/lib* $KAE_BUILD/kaezstd/lib
    cp $KAE_ZSTD_DIR/open_source/zstd/lib/libzstd.so* $KAE_BUILD/kaezstd/lib
    cp $KAE_ZSTD_DIR/open_source/zstd/lib/libzstd.a $KAE_BUILD/kaezstd/lib
    cp $KAE_ZSTD_DIR/open_source/zstd/lib/libzstd.pc $KAE_BUILD/kaezstd/lib/pkgconfig

    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstd $KAE_BUILD/kaezstd/bin
    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstdgrep $KAE_BUILD/kaezstd/bin
    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstdless $KAE_BUILD/kaezstd/bin

    cp $KAE_ZSTD_DIR/open_source/zstd/lib/*.h $KAE_BUILD/kaezstd/include
    cp $KAE_ZSTD_DIR/include/*.h $KAE_BUILD/kaezstd/include

    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstd.1 $KAE_BUILD/kaezstd/share/man/man1
    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstdgrep.1 $KAE_BUILD/kaezstd/share/man/man1
    cp $KAE_ZSTD_DIR/open_source/zstd/programs/zstdless.1 $KAE_BUILD/kaezstd/share/man/man1

    # 编译 lz4
    cd ${SRC_PATH}/KAELz4
    bash build.sh devbuild

    mkdir -p $KAE_BUILD/kaelz4/lib
    mkdir -p $KAE_BUILD/kaelz4/bin
    mkdir -p $KAE_BUILD/kaelz4/include
    mkdir -p $KAE_BUILD/kaelz4/share/man/man1

    cp $KAE_LZ4_DIR/lib* $KAE_BUILD/kaelz4/lib
    cp $KAE_LZ4_DIR/open_source/lz4-1.9.4/lib/liblz4.so* $KAE_BUILD/kaelz4/lib
    cp $KAE_LZ4_DIR/open_source/lz4-1.9.4/lib/liblz4.a $KAE_BUILD/kaelz4/lib

    cp $KAE_LZ4_DIR/open_source/lz4-1.9.4/programs/lz4 $KAE_BUILD/kaelz4/bin


    cp $KAE_LZ4_DIR/open_source/lz4-1.9.4/lib/*.h $KAE_BUILD/kaelz4/include
    cp $KAE_LZ4_DIR/include/*.h $KAE_BUILD/kaelz4/include
    cp $KAE_LZ4_DIR/src/utils/kaelz4_log.h $KAE_BUILD/kaelz4/include

    cp $KAE_LZ4_DIR/open_source/lz4-1.9.4/programs/lz4.1 $KAE_BUILD/kaelz4/share/man/man1
}

function build_driver()
{
    cd ${KAE_KERNEL_DIR}
    make -j
    make nosva #默认使用nosva模式
    # make install
    chmod 666 /dev/hisi_*
}

function build_driver_sva()
{
    cd ${KAE_KERNEL_DIR}
    make -j
    # make nosva #默认使用nosva模式
    make install
    chmod 666 /dev/hisi_*
}

function driver_clean()
{
    cd ${KAE_KERNEL_DIR}
    make uninstall
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

function build_uadk()
{
    cd ${SRC_PATH}
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0001-uadk-add-ctr-mode.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0001-uadk-add-ctr-mode.patch # uadk没支持ctr模式，engine层已经软件层面适配，可以定制化使能
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0003-fix-uadk-openssl3-bug.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0003-fix-uadk-openssl3-bug.patch
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0005-add-uadk-ecc-and-comp-header-for-kae.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0005-add-uadk-ecc-and-comp-header-for-kae.patch
    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0006-fix-uadk-lz77-data-error.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0006-fix-uadk-lz77-data-error.patch

    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0007-uadk-support-lz77-only-for-kaelz4.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0007-uadk-support-lz77-only-for-kaelz4.patch

    patch --no-backup-if-mismatch -p1 -R -s --forward < ./scripts/patches/0008-uadk-support-sgl-zero-copy-for-kaelz4.patch || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < ./scripts/patches/0008-uadk-support-sgl-zero-copy-for-kaelz4.patch

	cd ${SRC_PATH}/uadk
    bash autogen.sh
    bash conf.sh
    make -j64
    make install
}

function uadk_clean()
{
    cd ${SRC_PATH}/uadk
    make uninstall
    make clean
    bash cleanup.sh
}

function build_engine_log()
{
    touch /var/log/kae.cnf
    chmod 666 /var/log/kae.cnf
    touch /var/log/kae.log
    chmod 666 /var/log/kae.log
}

function engine_log_clean
{
    rm -rf /var/log/kae.log
}

function build_engine()
{
    openssl_install_path=$1
    if [ "$1" = "" ];then
        openssl_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    openssl_install_path=${openssl_install_path%/}

    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae --with-openssl_install_dir=$openssl_install_path CFLAGS="-Wl,-z,relro,-z,now -fstack-protector-strong"
    make -j
    make install
    build_engine_log
}

function engine_clean()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/lib/engines-1.1
    engine_log_clean
}

function build_engine_openssl3()
{
    openssl3_install_path=$1
    if [ "$1" = "" ];then
        openssl3_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    openssl3_install_path=${openssl3_install_path%/}
    
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i

    if [ ! -f "$openssl3_install_path/include/openssl/opensslv.h" ]; then  
        echo "openssl3 install path is wrong, $openssl3_install_path/include/openssl/opensslv.h is not exist."  
        exit 1  
    else  
        if $openssl3_install_path/bin/openssl version | grep -q "OpenSSL 3."; then    
            echo "OpenSSL version is 3.x."    
        elif $openssl3_install_path/bin/openssl version | grep -q "OpenSSL 1."; then    
            $openssl3_install_path/bin/openssl version  
            echo "OpenSSL version is 1.x, please use openssl3.0 install path"    
            exit 1
        else 
            $openssl3_install_path/bin/openssl version 
            echo "OpenSSL version is not support"   
            exit 1
        fi
    fi

    ./configure --libdir=/usr/local/lib/engines-3.0 --enable-kae --enable-engine --with-openssl_install_dir=$openssl3_install_path  #/usr/local/ssl3 
    make -j
    make install
    build_engine_log
}

function engine_clean_openssl3()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/lib/engines-3.0
    engine_log_clean
}

function build_engine_gmssl()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    # gmssl当前仅支持no-sva设备
    ./configure --libdir=/usr/local/gmssl/lib/engines-1.1 --enable-kae --enable-kae-gmssl CFLAGS="-Wl,-z,relro,-z,now -fstack-protector-strong -I/usr/local/gmssl/include/" 
    make -j
    make install
    build_engine_log
}

function engine_clean_gmssl()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/gmssl/lib/engines-1.1
    engine_log_clean
}

function build_engine3_tongsuo()
{
    tongsuo_install_path=$1
    if [ "$1" = "" ];then
        tongsuo_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    tongsuo_install_path=${tongsuo_install_path%/}
    
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i

    if [ ! -f "$tongsuo_install_path/include/openssl/opensslv.h" ]; then  
        echo "Tongsuo install path is wrong, $tongsuo_install_path/include/openssl/opensslv.h is not exist."  
        exit 1  
    else  
        if $tongsuo_install_path/bin/openssl version | grep -q "OpenSSL 3."; then    
            echo "Tongsuo's openssl version is 3.x."    
        else 
            $tongsuo_install_path/bin/openssl version 
            echo "Tongsuo's openssl version is not support"   
            exit 1
        fi
    fi

    ./configure --libdir=/usr/local/tongsuo/lib/engines-3.0 --enable-kae --enable-engine --enable-kae-tongsuo --with-openssl_install_dir=$tongsuo_install_path
    make -j
    make install
    build_engine_log
}

function engine3_clean_tongsuo()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/tongsuo/lib/engines-3.0
    engine_log_clean
}

function build_engine_boringssl()
{
    boringssl_install_path=$1
    if [ "$1" = "" ];then
        boringssl_install_path=$(which bssl | awk -F'/bin' '{print $1}')
    fi
    boringssl_install_path=${boringssl_install_path%/}
    
    echo $boringssl_install_path
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i

    ./configure --libdir=/usr/local/boringssl/lib/engines-1.1 --enable-kae --enable-engine --enable-kae-boringssl --with-openssl_install_dir=$boringssl_install_path
    make -j
    make install
    build_engine_log
}

function engine_clean_boringssl()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/boringssl/lib/engines-1.1
    engine_log_clean
}

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

function help()
{
	echo "build KAE"
	echo "bash build.sh all -- install all component(not include gmssl)"
    echo "bash build.sh rpmpack -- build rpm pack(not include gmssl)"

	echo "bash build.sh driver -- install KAE driver"
	echo "bash build.sh driver clean -- uninstall KAE driver"

	echo "bash build.sh uadk -- install uadk"
	echo "bash build.sh uadk clean -- uninstall uadk"

	echo "bash build.sh engine -- install KAE openssl engine"
	echo "bash build.sh engine clean -- uninstall KAE openssl engine"

    echo "bash build.sh engine3 <openssl3.0 install path>-- install KAE openssl3.0 engine"
	echo "bash build.sh engine3 clean -- uninstall KAE openssl3.0 engine"

    echo "bash build.sh engine_gmssl -- install KAE gmssl engine"
	echo "bash build.sh engine_gmssl clean -- uninstall KAE gmssl engine"

    echo "bash build.sh engine3_tongsuo -- install KAE tongsuo engine"
	echo "bash build.sh engine3_tongsuo clean -- uninstall KAE tongsuo engine"

    echo "bash build.sh engine_boringssl -- install KAE boringssl engine"
	echo "bash build.sh engine_boringssl clean -- uninstall KAE boringssl engine"

	echo "bash build.sh zlib -- install zlib using KAE"
	echo "bash build.sh zlib clean -- uninstall zlib using KAE"

	echo "bash build.sh zstd -- install zstd using KAE"
	echo "bash build.sh zstd clean -- uninstall zstd using KAE"

    echo "bash build.sh gzip -- install gzip using KAE"
	echo "bash build.sh gzip clean -- uninstall gzip using KAE"

	echo "bash build.sh cleanup -- clean up all component"
}

function check_environment()
{
    IMPLEMENTER=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
    CPUPART=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
    if [ "${IMPLEMENTER}" != "0x48" ];then
        echo "Only installed on kunpeng CPUs"
        exit 1
    fi
}

function build_all_components()
{
    build_driver
    build_uadk
    build_engine
    build_zlib
    build_gzip
    if [ "${IMPLEMENTER}-${CPUPART}" == "0x48-0xd01" ];then
        echo "this cpu not support kaezstd and kaelz4."
    else
        build_zstd
        build_lz4
    fi
}

function clear_all_components()
{
    driver_clean || true  
    uadk_clean   || true 
    engine_clean || true  
    zlib_clean   || true  
    gzip_clean   || true
 
    if [ "${IMPLEMENTER}-${CPUPART}" == "0x48-0xd01" ];then
        echo "this cpu not support kaezstd and kaelz4."
    else
        zstd_clean || true  
        lz4_clean  || true
    fi
}

main() {  
    check_environment  
    build_check_OS_version  
  
    case "$1" in  
        "all")  
            build_all_components  
            ;;  
        "driver")  
            if [ "$2" = "clean" ]; then  
                driver_clean
            elif [ "$2" = "sva" ]; then  
                build_driver_sva
            elif [ "$2" = "check" ]; then  
                driver_check
            elif [ "$2" = "delete" ]; then  
                driver_delete
            else  
                build_driver
            fi  
            ;;  
        "uadk")  
            if [ "$2" = "clean" ]; then  
                uadk_clean
            else  
	            build_uadk
            fi  
            ;;  
        "engine")  
            if [ "$2" = "clean" ]; then  
                engine_clean
            else  
                build_engine $2
            fi  
            ;;  
        "engine3")
            if [ "$2" = "clean" ]; then
                engine_clean_openssl3
            else
                build_engine_openssl3 $2
            fi
            ;;
        "engine_gmssl")  
            if [ "$2" = "clean" ]; then  
                engine_clean_gmssl
            else  
                build_engine_gmssl
            fi  
            ;;
        "engine3_tongsuo")
            if [ "$2" = "clean" ]; then
                engine3_clean_tongsuo
            else
                build_engine3_tongsuo $2
            fi
            ;;    
        "engine_boringssl")
            if [ "$2" = "clean" ]; then
                engine_clean_boringssl
            else
                build_engine_boringssl $2
            fi
            ;;
        "zlib")  
            if [ "$2" = "clean" ]; then  
                zlib_clean
            else  
                build_zlib
            fi  
            ;;  
        "zstd")  
            if [ "${IMPLEMENTER}-${CPUPART}" == "0x48-0xd01" ]; then  
                echo "This CPU does not support zstd."  
            else  
                if [ "$2" = "clean" ]; then  
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
                if [ "$2" = "clean" ]; then  
                    lz4_clean
                else  
                    build_lz4
                fi  
            fi  
            ;;  
        "gzip")
            if [ "$2" = "clean" ]; then  
                gzip_clean
            else  
                build_gzip
            fi  
            ;; 
        "rpm")  
            set +e  
            clear_all_components  
            set -e  
            build_rpm  
            ;;  
        "rpmpack")  
            rm -rf /root/rpmbuild/SOURCES/kae* /root/rpmbuild/RPMS/aarch64/kae-* $KAE_BUILD
            mkdir -p $KAE_BUILD /root/rpmbuild/SOURCES  
            tar -zcvf /root/rpmbuild/SOURCES/kae-2.0.4.tar.gz .  
            rpmbuild -bb $KAE_SPEC_FILE  
            cp /root/rpmbuild/RPMS/aarch64/kae* $KAE_BUILD  
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
