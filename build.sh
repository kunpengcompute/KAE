#!/bin/sh
set -e
SRC_PATH=$(pwd)
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
        sh setup.sh install
}
function build_zlib_v1()
{
        cd ${SRC_PATH}/KAEZlib
        sh setup.sh install KAE2
}
function zlib_clean()
{
        cd ${SRC_PATH}/KAEZlib
        sh setup.sh uninstall
}
function build_zlib_v1()
{
        cd ${SRC_PATH}/KAEZstd
        sh setup.sh install
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
	echo "sh build.sh all -- install all component"
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
	elif [ "$1" = "uadk" ];then
		build_uadk
                if [ "$2" = "clean" ];then
                        uadk_clean
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
	else
		help
	fi
}

main "$@"
exit $?
