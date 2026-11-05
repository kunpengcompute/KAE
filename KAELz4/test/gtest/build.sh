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

BUILD_PATH=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
gtest_download="${BUILD_PATH}/gtest-download"
GOOGLE_TEST_DIR="${gtest_download}/googletest-release-1.11.0"

build_googletest()
{
    if [ ! -f "${BUILD_PATH}/test_tool_bins/gtest/libgtest.a" ]; then
        mkdir -p "${BUILD_PATH}/test_tool_bins/gtest"
        mkdir -p "${GOOGLE_TEST_DIR}/build"
        (
            cd "${GOOGLE_TEST_DIR}/build"
            cmake ../
            make -j16
        )
        cp "${GOOGLE_TEST_DIR}"/build/lib/*.a "${BUILD_PATH}/test_tool_bins/gtest/"
    fi
}

download_googletest()
{
    if [ ! -d "${GOOGLE_TEST_DIR}" ]; then
        echo "GoogleTest 1.11.0 is not available; downloading it now."
        sh "${gtest_download}/download.sh"
    fi
}

main()
{
    cd "${BUILD_PATH}"

    if [ "${1:-}" = "clean" ]; then
        echo "MakeClean"
        make clean
        exit 0
    fi

    download_googletest
    build_googletest
    make
}

main "$@"
