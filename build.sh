#!/bin/sh
set -e
SRC_PATH=$(pwd)
KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver
KAE_UADK_DIR=${SRC_PATH}/uadk
KAE_OPENSSL_DIR=${SRC_PATH}/KAEOpensslEngine
KAE_ZLIB_DIR=${SRC_PATH}/KAEZlib
KAE_ZSTD_DIR=${SRC_PATH}/KAEZstd

KAE_BUILD=${SRC_PATH}/kae_build/
KAE_BUILD_LIB=${SRC_PATH}/kae_build/lib
KAE_BUILD_HEAD=${SRC_PATH}/kae_build/head

IMPLEMENTER=""
CPUPAET=""
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
        sh autogen.sh
        sh conf.sh
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
        sh setup.sh devbuild KAE2

        cp $KAE_ZLIB_DIR/lib* $KAE_BUILD_LIB
        cp $KAE_ZLIB_DIR/open_source/zlib-1.2.11/lib* $KAE_BUILD_LIB

        # 编译zstd
        cd $KAE_ZSTD_DIR
        sh build.sh devbuild

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
    local KERNEL_VERSION_BY_BUILDENV=`rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel | head -n 1`

    # 编译
    build_driver
    build_uadk
    build_engine
    build_zlib
    build_zstd
    ## copy driver
    mkdir -p $KAE_BUILD/driver

    cp /lib/modules/$KERNEL_VERSION_BY_BUILDENV/extra/*.ko $KAE_BUILD/driver
    cp /etc/modprobe.d/*.conf $KAE_BUILD/driver

    ## copy uadk
    mkdir -p $KAE_BUILD/uadk/include
    mkdir -p $KAE_BUILD/uadk/include/drv
    mkdir -p $KAE_BUILD/uadk/lib

    cp $KAE_UADK_DIR/include/*.h                       $KAE_BUILD/uadk/include
    cp $KAE_UADK_DIR/include/drv/*.h                   $KAE_BUILD/uadk/include/drv
    cp -r $KAE_UADK_DIR/.libs/*so*                     $KAE_BUILD/uadk/lib

    ## copy opensslengine
    mkdir -p $KAE_BUILD/KAEOpensslEngine/lib
    cp -r $KAE_OPENSSL_DIR/src/.libs/*so* $KAE_BUILD/KAEOpensslEngine/lib

    ## copy zlib
    mkdir -p $KAE_BUILD/KAEZlib
    cp -r /usr/local/kaezip  $KAE_BUILD/KAEZlib

    ## copy zstd
    mkdir -p $KAE_BUILD/KAEZstd
    cp -r /usr/local/kaezstd  $KAE_BUILD/KAEZstd

}

function build_driver()
{
        if [ "${IMPLEMENTER}-${CPUPAET}" == "0x48-0xd01" ];then
            #NOSVA
            cd ${SRC_PATH}/KAEKernelDriver
            make -j
            make nosva
        elif [ "${IMPLEMENTER}-${CPUPAET}" == "0x48-0xd02" ];then
            #SVA
            cd ${SRC_PATH}/KAEKernelDriver
            make -j
            make install
        else
            echo "unknow cpu type:${IMPLEMENTER}-${CPUPAET}"
            exit 1
        fi
}

function driver_clean()
{
        cd ${SRC_PATH}/KAEKernelDriver
        make uninstall
        make clean
}

function build_uadk()
{
        cd ${SRC_PATH}/uadk
        sh autogen.sh
        sh conf.sh
        make CFLAGS="-fstack-protector-strong -Wl,-z,relro,-z,now" -j 64
        make install
}

function uadk_clean()
{
        cd ${SRC_PATH}/uadk
        make uninstall
        make clean
        sh cleanup.sh
}

function build_engine()
{
            cd ${SRC_PATH}/KAEOpensslEngine
            export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
            autoreconf -i
            ./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae CFLAGS="-Wl,-z,relro,-z,now -fstack-protector-strong"
            make -j
            make install
}

function engine_clean()
{
        cd ${SRC_PATH}/KAEOpensslEngine
        make uninstall
        make clean
        rm -rf /usr/local/gmssl/lib/engines-1.1
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
}

function engine_clean_gmssl()
{
        cd ${SRC_PATH}/KAEOpensslEngine
        make uninstall
        make clean
        rm -rf /usr/local/gmssl/lib/engines-1.1
}

function build_zlib()
{
            cd ${SRC_PATH}/KAEZlib
            sh setup.sh install
}

function zlib_clean()
{
        cd ${SRC_PATH}/KAEZlib
        sh setup.sh uninstall
        rm -rf /usr/local/kaezip
}

function build_zstd()
{
        cd ${SRC_PATH}/KAEZstd
        sh build.sh install
}

function zstd_clean()
{
        cd ${SRC_PATH}/KAEZstd
        sh build.sh uninstall
        rm -rf /usr/local/kaezstd/
}

function help()
{
	echo "build KAE"
	echo "sh build.sh all -- install all component(not include gmssl)"
    echo "sh build.sh rpmpack -- build rpm pack(not include gmssl)"

	echo "sh build.sh driver -- install KAE SVA driver"
	echo "sh build.sh driver clean -- uninstall KAE driver"

	echo "sh build.sh uadk -- install uadk"
	echo "sh build.sh uadk clean -- uninstall uadk"

	echo "sh build.sh engine -- install KAE openssl engine"
	echo "sh build.sh engine clean -- uninstall KAE openssl engine"

    echo "sh build.sh engine_gmssl -- install KAE gmssl engine"
	echo "sh build.sh engine_gmssl clean -- uninstall KAE gmssl engine"

	echo "sh build.sh zlib -- install zlib using KAE"
	echo "sh build.sh zlib clean -- uninstall zlib using KAE"

	echo "sh build.sh zstd -- install zstd using KAE"
	echo "sh build.sh zstd clean -- uninstall zstd using KAE"

	echo "sh build.sh cleanup -- clean up all component"
}

function check_enviroment()
{
        IMPLEMENTER=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
        CPUPAET=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
        if [ "${IMPLEMENTER}-${CPUPAET}" != "0x48-0xd01" ] && [ "${IMPLEMENTER}-${CPUPAET}" != "0x48-0xd02" ];then
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
    if [ "${IMPLEMENTER}-${CPUPAET}" == "0x48-0xd01" ];then
        #NOSVA
        echo "this cpu not support kaezstd."
    elif [ "${IMPLEMENTER}-${CPUPAET}" == "0x48-0xd02" ];then
        #SVA
        build_zstd
    else
        echo "unknow cpu type:${IMPLEMENTER}-${CPUPAET}"
    fi
}

function clear_all_components()
{
    driver_clean || true  
    engine_clean || true  
    zlib_clean || true  
    zstd_clean || true  
    uadk_clean || true  
}

function main()
{
        check_enviroment

	if [ "$1" = "all" ];then
	    echo "build all"
        build_all_components
	elif [ "$1" = "driver" ];then
            echo "build driver"
            if [ "$2" = "clean" ];then
                driver_clean
            else
                build_driver
            fi
	elif [ "$1" = "uadk" ];then
            if [ "$2" = "clean" ];then
                uadk_clean
            else
	        build_uadk
	    fi
	elif [ "$1" = "engine" ];then
            if [ "$2" = "clean" ];then
                engine_clean
            else
                build_engine
            fi
    elif [ "$1" = "engine_gmssl" ];then
            if [ "$2" = "clean" ];then
                engine_clean_gmssl
            else
                build_engine_gmssl
            fi
	elif [ "$1" = "zlib" ];then
            if [ "$2" = "clean" ];then
                zlib_clean
            else
                build_zlib
            fi
	elif [ "$1" = "zstd" ];then
            if [ "$2" = "clean" ];then
                zstd_clean
            else
                build_zstd
            fi
	elif [ "$1" = "rpm" ];then
            set +e
            clear_all_components
            set -e
            build_rpm
    elif [ "$1" = "rpmpack" ];then
            rm -rf /root/rpmbuild
            rm -rf $KAE_BUILD
            mkdir -p $KAE_BUILD
            mkdir -p /root/rpmbuild/SOURCES/
            tar -zcvf /root/rpmbuild/SOURCES/kae-2.0.0.tar.gz .
            rpmbuild -bb ./scripts/specFile/kae.spec
            cp /root/rpmbuild/RPMS/aarch64/kae* $KAE_BUILD
    elif [ "$1" = "cleanup" ];then
	    echo "cleanup all"
        clear_all_components
	    rm -rf $KAE_BUILD/*
    else
	    help
	fi
}

main "$@"
exit $?
