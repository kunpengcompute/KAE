#!/bin/bash
# Copyright © Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
# @rem Copyright © Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
# @rem Description: build script
set -e
#set -x
SRC_PATH=$(pwd)
BUILDVERSION=$(ls "${SRC_PATH}"/open_source | grep libwd | awk '{print substr($0,7,5)}')

function Install_warpdrive()
{
    local wd_src_path=$(ls /usr/local/lib | grep libwd.so.${BUILDVERSION})
    local wd_rpm_path=$(ls /usr/lib64 | grep libwd.so.${BUILDVERSION})
    if [ ! -n "${wd_src_path}" ] && [ ! -n "${wd_rpm_path}" ];  then
        cd "${SRC_PATH}"/open_source
        rm -rf warpdrive
        tar -zxvf libwd-"${BUILDVERSION}".tar.gz

        cd warpdrive/
        sh autogen.sh
        ./configure
        make clean && make
        make install
    fi
}

function Target_zlib()
{
    cd "${SRC_PATH}"/open_source
    rm -rf zlib-1.2.11
    tar -zxvf zlib-1.2.11.tar.gz
    cd "${SRC_PATH}"/open_source/zlib-1.2.11/
    ./configure
    make
}

function Dev_Build_kaezip()
{
    #Install_warpdrive
    Target_zlib
    cd "${SRC_PATH}"
	make clean
    make
    echo "build kaezip"

    cd -
    patch -Np1 < ../../patch/kaezip_for_zlib-1.2.11.patch
    ./configure  --prefix=/usr/local/kaezip
    make KAEBUILDPATH=${SRC_PATH}/../kae_build KAEZLIBPATH=${SRC_PATH}
    echo "build zlib success"
}


function Build_kaezip()
{
    #Install_warpdrive
    Target_zlib
    cd "${SRC_PATH}"
	make clean && make KAE=KAE
    make install
    echo "install kaezip"

    cd -
    patch -Np1 < ../../patch/kaezip_for_zlib-1.2.11.patch
    ./configure  --prefix=/usr/local/kaezip
    make KAEBUILDPATH=${SRC_PATH}/../kae_build KAEZLIBPATH=${SRC_PATH}
    echo "build zlib success"
}

function Install_kaezip()
{
    if [ -d "${SRC_PATH}"/open_source/zlib-1.2.11/ ]; then
        cd "${SRC_PATH}"/open_source/zlib-1.2.11/
		make install
    fi 
    echo "install zlib success"
}

function Uninstall_kaezip()
{
    local zlib_path=
    if [ -d "${SRC_PATH}"/open_source/zlib-1.2.11/ ]; then
	set +e
        zlib_path=$(ls /usr/local/kaezip/lib | grep libz.so.1.2.11)
        set -e
	if [ -n "${zlib_path}" ]; then
            cd "${SRC_PATH}"/open_source/zlib-1.2.11/
            make uninstall && make clean
            rm -rf "${SRC_PATH}"/open_source/zlib-1.2.11
        fi
    fi

#    local wd_src_path=$(ls /usr/local/lib | grep libwd.so.${BUILDVERSION})
#    local wd_rpm_path=$(ls /usr/lib64 | grep libwd.so.${BUILDVERSION})
#    if [ -n "${wd_src_path}" ] || [ -n "${wd_rpm_path}" ]; then
#        if [ -d "${SRC_PATH}"/open_source/warpdrive ]; then
#            cd "${SRC_PATH}"/open_source/warpdrive
#            make uninstall && make clean
#            rm -rf "${SRC_PATH}"/open_source/warpdrive
#        fi
#    fi

    local kaezip_path=$(ls /usr/local/kaezip/lib | grep libkaezip.so.${BUILDVERSION})
    if [ -n "${kaezip_path}" ]; then
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
            Dev_Build_kaezip "$2"
            ;;
        build)
            Build_kaezip "$2"
            ;;
        install)
            Build_kaezip "$2"
            Install_kaezip
            ;;
        uninstall)
            Uninstall_kaezip
            ;;
    esac
}

function main()
{
    Operate    "$1" "$2"
}

main "$@"
exit $?
