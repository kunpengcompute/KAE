#!/bin/bash
BUILD_PATH=$(pwd)
GOOGLE_TEST_DIR="${BUILD_PATH}/googletest-release-1.11.0"
KAE_PATH="${BUILD_PATH}/../"
set -ex

function build_googletest()
{
    mkdir -p test_tool_bins/gtest
    mkdir -p "${GOOGLE_TEST_DIR}/build"
    cd "${GOOGLE_TEST_DIR}/build"
    cmake ..
    make -j16

    cp ${GOOGLE_TEST_DIR}/build/lib/*.a ${BUILD_PATH}/test_tool_bins/gtest/
}

function build_kae()
{
    cd ${KAE_PATH}
    sh build.sh all
}

function build_test()
{
    cd ${BUILD_PATH}/src
    make -j96
}

function main()
{
    mkdir -p test_tool_bins
    mkdir -p include
    if [ ! -f "${BUILD_PATH}/test_tool_bins/gtest/libgtest.a" ]; then
        build_googletest
    fi
    build_kae
    cd ${BUILD_PATH}/src
    sh build.sh
    make
}

main $@