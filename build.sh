#!/bin/sh
set -e
SRC_PATH=$(pwd)
function build_driver()
{
        cd ${SRC_PATH}/kae_driver
        make -j
        make install
}
function build_uadk()
{
        cd ${SRC_PATH}/uadk
        sh autogen.sh
        sh conf.sh
        make -j
        make install
}
function build_engine()
{
        cd ${SRC_PATH}/kae_engine
        export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
        autoreconf -i
        ./configure --libdir=/usr/local/lib/engines-1.1/
        make -j
        make install
}
function build_zstd()
{
        cd ${SRC_PATH}/kae_zstd
        sh build.sh install
}
function main()
{
	echo $1
	if [ "$1" = "all" ];then
		echo "build all"
                build_driver
                build_uadk
                build_engine
                build_zstd
	elif [ "$1" = "cleanup" ];then
		echo "cleanup all"
	        cd ${SRC_PATH}/kae_driver
                make uninstall
                cd ${SRC_PATH}/uadk
                make uninstall
                cd ${SRC_PATH}/kae_engine
                make uninstall
                cd ${SRC_PATH}/kae_zstd
                make uninstall

	else
		echo "not support cmd, please input all/cleanup"
	fi
}

main "$@"
exit $?
