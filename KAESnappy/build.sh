#!/bin/bash
# Copyright © Huawei Technologies Co., Ltd. 2010-2024. All rights reserved.
# @rem Copyright © Huawei Technologies Co., Ltd. 2010-2024. All rights reserved.
# @rem Description: build script
set -e
#set -x
SRC_PATH=$(pwd)
BUILDVERSION=$(ls "${SRC_PATH}"/open_source | grep libwd | awk '{print substr($0,7,5)}')

function Target_lz4()
{
    cd "${SRC_PATH}"/open_source
    rm -rf lz4-1.9.4
    tar -zxvf lz4-1.9.4.tar.gz
    patch -p0 < kaelz4_1_9_4.patch
    cp "${SRC_PATH}"/open_source/lz4-1.9.4/lib/xxhash.h "${SRC_PATH}"/src/utils
    cp "${SRC_PATH}"/open_source/lz4-1.9.4/lib/xxhash.c "${SRC_PATH}"/src/utils
    cp "${SRC_PATH}"/open_source/lz4-1.9.4/lib/lz4.h "${SRC_PATH}"/src/utils
    cp "${SRC_PATH}"/open_source/lz4-1.9.4/lib/lz4frame.h "${SRC_PATH}"/src/utils
    cd "${SRC_PATH}"/open_source/lz4-1.9.4/
}

function Build_kaelz4()
{
    Target_lz4
    cd "${SRC_PATH}"
	make clean && make
    make install
    echo "install kaelz4"

    cd -
    make -j KAELZ4PATH=${SRC_PATH}
    echo "build lz4 success"
}

function Dev_Build_kaelz4()
{
    Target_lz4
    cd "${SRC_PATH}"
	make clean
    make
    echo "install kaelz4"

    cd -
    make -j KAEBUILDPATH=${SRC_PATH}/../kae_build/ KAELZ4PATH=${SRC_PATH}
    echo "build lz4 success"
}

function Install_kaelz4()
{
    if [ -d "${SRC_PATH}"/open_source/lz4-1.9.4/ ]; then
        cd "${SRC_PATH}"/open_source/lz4-1.9.4/
        echo "build and intsall lz4."
        make
		make PREFIX=/usr/local/kaelz4/ install
    fi
    echo "install lz4 success"
}

function Uninstall_kaelz4()
{
    local lz4_path=
    if [ -d "${SRC_PATH}"/open_source/lz4-1.9.4/ ]; then
	set +e
        lz4_path=$(ls /usr/local/kaelz4/lib | grep liblz4-1.9.4.so)
        set -e
	if [ -n "${lz4_path}" ]; then
            cd "${SRC_PATH}"/open_source/lz4-1.9.4/
            make PREFIX=/usr/local/kaelz4/ uninstall && make clean
            rm -rf "${SRC_PATH}"/open_source/lz4-1.9.4
        fi
    fi

    local kaelz4_path=$(ls /usr/local/kaelz4/lib | grep libkaelz4.so.${BUILDVERSION})
    if [ -n "${kaelz4_path}" ]; then
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
            Dev_Build_kaelz4 "$2"
            ;;
        build)
            Build_kaelz4 "$2"
            ;;
        install)
            Build_kaelz4 "$2"
            Install_kaelz4
            ;;
        uninstall)
            Uninstall_kaelz4
            ;;
    esac
}

function main()
{
    Operate    "$1" "$2"
}

main "$@"
exit $?
