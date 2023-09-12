#!/bin/bash
# Copyright © Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
# @rem Copyright © Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
# @rem Description: build script
set -e
#set -x
SRC_PATH=$(pwd)
BUILDVERSION=$(ls "${SRC_PATH}"/open_source | grep libwd | awk '{print substr($0,7,5)}')

function Target_zlib()
{
    cd "${SRC_PATH}"/open_source
    rm -rf zstd
    tar -zxvf zstd-1.5.2.tar.gz
    patch -p0 < kaezstd_1_5_2.patch
    cd "${SRC_PATH}"/open_source/zstd/
}

function Build_kaezstd()
{
    Target_zlib
    cd "${SRC_PATH}"
	make clean && make
    make install
    echo "install kaezstd"

    cd -
    make -j
    echo "build zstd success"
}

function Dev_Build_kaezstd()
{
    Target_zlib
    cd "${SRC_PATH}"
	make clean && make
    make 
    echo "install kaezstd"

    cd -
    make -j KAEBUILDPATH=${SRC_PATH}/../kae_build/ KAEZSTDPATH=${SRC_PATH}
    echo "build zstd success"
}

function Install_kaezstd()
{
    if [ -d "${SRC_PATH}"/open_source/zstd/ ]; then
        cd "${SRC_PATH}"/open_source/zstd/
        echo "build and intsall zstd."
        CFLAGS="-fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now"  make -j 64
		make PREFIX=/usr/local/kaezstd/ install
    fi 
    echo "install zlib success"
}

function Uninstall_kaezstd()
{
    local zlib_path=
    if [ -d "${SRC_PATH}"/open_source/zstd/ ]; then
	set +e
        zlib_path=$(ls /usr/local/kaezstd/lib | grep libzstd.so)
        set -e
	if [ -n "${zlib_path}" ]; then
            cd "${SRC_PATH}"/open_source/zstd/
            make PREFIX=/usr/local/kaezstd/ uninstall && make clean
            rm -rf "${SRC_PATH}"/open_source/zstd
        fi
    fi

    local kaezstd_path=$(ls /usr/local/kaezstd/lib | grep libkaezstd.so.${BUILDVERSION})
    if [ -n "${kaezstd_path}" ]; then
        if [ -d "${SRC_PATH}" ]; then
            cd "${SRC_PATH}"
            make uninstall && make clean
        fi
    fi
    echo "uninstall success"
}

function Operate()
{
    cd "${SRC_PATH}"/open_source
    case "$1" in 
        devbuild)
            Dev_Build_kaezstd "$2"
            ;;
        build)
            Build_kaezstd "$2"
            ;;
        install)
            Build_kaezstd "$2"
            Install_kaezstd
            ;;
        uninstall)
            Uninstall_kaezstd
            ;;
    esac
}

function main()
{
    Operate    "$1" "$2"
}

main "$@"
exit $?
