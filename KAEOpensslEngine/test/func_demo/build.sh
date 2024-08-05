#!/bin/bash
BUILD_PATH=$(pwd)
gtest_download="${BUILD_PATH}/../gtest-download"
GOOGLE_TEST_DIR="${gtest_download}/googletest-release-1.11.0"
set -ex

function build_googletest()
{
    mkdir -p "${BUILD_PATH}/test_tool_bins/gtest"
    mkdir -p "${GOOGLE_TEST_DIR}/build"
    cd "${GOOGLE_TEST_DIR}/build"
    cmake ../
    make -j16

    cp ${GOOGLE_TEST_DIR}/build/lib/*.a ${BUILD_PATH}/test_tool_bins/gtest/
}

function main()
{
    cd ${gtest_download}
    if [ ! -d ${gtest_download}/googletest-release-1.11.0 ]
    then
        echo -e "\033[32m The googletest-release-1.11.0 directory not exists and need to be downloaded. \033[0m"
        sh download.sh
    fi

    cd ${gtest_download}/googletest-release-1.11.0
    if [ ! -f "${BUILD_PATH}/test_tool_bins/gtest/libgtest.a" ]; then
        build_googletest
    fi
    cd ${BUILD_PATH}/src
    sh build.sh
    make
}

main $@