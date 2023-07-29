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
function build_all_comp_v2()
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
function build_driver()
{
        cd ${SRC_PATH}/KAEKernelDriver
        make -j
        make install
}
function driver_clean()
{
        cd ${SRC_PATH}/KAEKernelDriver
        make uninstall
        make clean
}
function build_driver_v1()
{
        cd ${SRC_PATH}/KAEKernelDriver
        make -j
        make nosva
}
function build_uadk()
{
        cd ${SRC_PATH}/uadk
        sh autogen.sh
        sh conf.sh
        make -j
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
        ./configure --libdir=/usr/local/lib/engines-1.1/
        make -j
        make install
}
function engine_clean()
{
        cd ${SRC_PATH}/KAEOpensslEngine
        make uninstall
        make clean
}
function build_engine_v1()
{
        cd ${SRC_PATH}/KAEOpensslEngine
        export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
        autoreconf -i
        ./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae
        make -j
        make install
}
function build_zlib()
{
        cd ${SRC_PATH}/KAEZlib
        sh setup.sh install KAE2
}
function build_zlib_v1()
{
        cd ${SRC_PATH}/KAEZlib
        sh setup.sh install
}
function zlib_clean()
{
        cd ${SRC_PATH}/KAEZlib
        sh setup.sh uninstall
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
}
function help()
{
	echo "build KAE"
	echo "sh build.sh all -- install all component [v2]"
        echo "sh build.sh allv1 -- install all component [v1]"
        echo "sh build.sh buildallv2 -- build all component"
	echo "sh build.sh driver -- install KAE SVA driver"
	echo "sh build.sh driver v1 -- install KAE NoSVA driver"
	echo "sh build.sh driver clean -- uninstall KAE driver"
	echo "sh build.sh uadk -- install uadk"
	echo "sh build.sh uadk clean -- uninstall uadk"
	echo "sh build.sh engine -- install KAE openssl engine"
	echo "sh build.sh engine v1 -- install KAE openssl engine including v1 part"
	echo "sh build.sh engine clean -- uninstall KAE openssl engine"
	echo "sh build.sh zlib -- install zlib using KAE"
	echo "sh build.sh zlib v1 -- install zlib using KAE v1"
	echo "sh build.sh zlib clean -- uninstall zlib using KAE"
	echo "sh build.sh zstd -- install zstd using KAE"
	echo "sh build.sh zstd clean -- uninstall zstd using KAE"
	echo "sh build.sh cleanup -- clean up all component"
}
function main()
{
	if [ "$1" = "all" ];then
		echo "build all"
                build_driver
                build_uadk
                build_engine
                build_zlib
                build_zstd
	elif [ "$1" = "driver" ];then
                echo "build driver"
                if [ "$2" = "v1" ];then
                        build_driver_v1
                elif [ "$2" = "clean" ];then
                        driver_clean
                else
                        build_driver
                fi
        elif [ "$1" = "allv1" ];then
                build_driver_v1
                build_uadk
                build_engine_v1
                build_zlib_v1
	elif [ "$1" = "uadk" ];then
                if [ "$2" = "clean" ];then
                        uadk_clean
                else
			build_uadk
		fi
	elif [ "$1" = "engine" ];then
                if [ "$2" = "v1" ];then
                        build_engine_v1
                elif [ "$2" = "clean" ];then
                        engine_clean
                else
                        build_engine
                fi
	elif [ "$1" = "zlib" ];then
                if [ "$2" = "v1" ];then
                        build_zlib_v1
                elif [ "$2" = "clean" ];then
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
	elif [ "$1" = "cleanup" ];then
		echo "cleanup all"
                driver_clean
                uadk_clean
                engine_clean
                zlib_clean
                zstd_clean
	        rm -rf $KAE_BUILD/*
	elif [ "$1" = "buildallv2" ];then
                build_all_comp_v2
        else
		help
	fi
}

main "$@"
exit $?
