#!/bin/bash

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
