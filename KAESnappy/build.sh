#!/bin/bash
# Copyright © Huawei Technologies Co., Ltd. 2010-2024. All rights reserved.
# @rem Copyright © Huawei Technologies Co., Ltd. 2010-2024. All rights reserved.
# @rem Description: build script
set -e
#set -x
SRC_PATH=$(pwd)
BUILDVERSION=$(ls "${SRC_PATH}"/open_source | grep libwd | awk '{print substr($0,7,5)}')

function Target_snappy()
{
    cd "${SRC_PATH}"/open_source
    rm -rf snappy-1.1.10
    tar -zxvf snappy-1.1.10.tar.gz
    patch -p0 --forward < kaesnappy_1_1_10.patch
    cd ./snappy-1.1.10
}

function Build_kaesnappy()
{
    Target_snappy
    cd "${SRC_PATH}"
	make clean && make
    make install
    echo "install kaelz4"

    cd -
    rm -rf build
    mkdir build && cd build
    cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON
    make -j
    echo "build snappy success"
}

function Dev_Build_kaelz4()
{
    Target_snappy
    cd "${SRC_PATH}"
	make clean && make
    make install
    echo "install kaelz4"

    cd -
    rm -rf build
    mkdir build && cd build
    cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON
    make -j
    echo "build snappy success"
}

function Install_kaesnappy()
{
    Target_snappy
    cd "${SRC_PATH}"
	make clean && make
    make install
    echo "install kaelz4"
    
    if [ -d "${SRC_PATH}"/open_source/snappy-1.1.10/ ]; then
        cd "${SRC_PATH}"/open_source/snappy-1.1.10/
        echo "build and intsall snappy."
        rm -rf build
        mkdir build && cd build
        cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local/kaesnappy \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_SHARED_LIBS=ON
        make -j
        make install
    fi
    echo "install snappy success"
}

function Uninstall_kaesnappy()
{
    local snappy_path=
    if [ -d "${SRC_PATH}"/open_source/snappy-1.1.10/ ]; then
	set +e
        snappy_path=$(ls /usr/local/kaesnappy/lib | grep libsnappy.so.1.1.10)
        set -e
	if [ -n "${snappy_path}" ]; then
            rm -rf "${SRC_PATH}"/open_source/snappy-1.1.10
        fi
    fi

    local kaesnappy_path=$(ls /usr/local/kaesnappy/lib | grep libkaelz4.so.${BUILDVERSION})
    if [ -n "${kaesnappy_path}" ]; then
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
            Dev_Build_kaesnappy "$2"
            ;;
        build)
            Build_kaesnappy "$2"
            ;;
        install)
            # Build_kaesnappy "$2"
            Install_kaesnappy
            ;;
        uninstall)
            Uninstall_kaesnappy
            ;;
    esac
}

function main()
{
    Operate    "$1" "$2"
}

main "$@"
exit $?
