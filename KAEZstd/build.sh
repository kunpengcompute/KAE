#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
#set -x
SRC_PATH=$(pwd)
BUILDVERSION=$(ls "${SRC_PATH}"/open_source | grep libwd | awk '{print substr($0,7,5)}')

function Target_zstd()
{
    cd "${SRC_PATH}"/open_source
    rm -rf zstd
    tar -zxvf zstd-1.5.4.tar.gz
    patch -p0 < kaezstd_1_5_4.patch
    patch -p0 < zstd_decompress.patch
    mv zstd-1.5.4 zstd
    cd "${SRC_PATH}"/open_source/zstd/
}

function Build_kaezstd()
{
    Target_zstd
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
    Target_zstd
    cd "${SRC_PATH}"
	make clean && make
    make 
    echo "install kaezstd"

    cd -
    make -j KAEBUILDPATH=${SRC_PATH}/../kae_build/ KAEZSTDPATH=${SRC_PATH}
    make PREFIX="${SRC_PATH}/../kae_build/kaezstd" install
    echo "build zstd success"
}

function Install_kaezstd()
{
    if [ -d "${SRC_PATH}"/open_source/zstd/ ]; then
        cd "${SRC_PATH}"/open_source/zstd/
        echo "build and intsall zstd."
        make
		make PREFIX=/usr/local/kaezstd/ install
    fi 
    echo "install zstd success"
}

function Uninstall_kaezstd()
{
    local zstd_path=
    if [ -d "${SRC_PATH}"/open_source/zstd/ ]; then
	set +e
        zstd_path=$(ls /usr/local/kaezstd/lib | grep libzstd.so)
        set -e
	if [ -n "${zstd_path}" ]; then
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
