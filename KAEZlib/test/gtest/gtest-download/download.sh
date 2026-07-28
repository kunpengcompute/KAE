#!/bin/bash
##############################################################
## Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
## @Filename: download.sh
## @Usage:    sh download.sh
##############################################################

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GTEST_TAG="release-1.11.0"
GTEST_DIR_NAME="googletest-${GTEST_TAG}"
GTEST_DIR="${SCRIPT_DIR}/${GTEST_DIR_NAME}"
GTEST_OFFICIAL_URL="https://github.com/google/googletest/archive/refs/tags/${GTEST_TAG}.zip"
GTEST_MIRROR_URL="https://gitee.com/mirrors/googletest/repository/archive/${GTEST_TAG}.zip"

if [ -d "${GTEST_DIR}" ]; then
    if [ ! -f "${GTEST_DIR}/CMakeLists.txt" ] ||
       [ ! -f "${GTEST_DIR}/googletest/include/gtest/gtest.h" ]; then
        echo "GoogleTest directory is incomplete: ${GTEST_DIR}" >&2
        exit 1
    fi

    echo "GoogleTest ${GTEST_TAG} is already available."
    exit 0
fi

if ! command -v unzip >/dev/null 2>&1; then
    echo "unzip is required to extract GoogleTest." >&2
    exit 1
fi

download_dir=$(mktemp -d "${SCRIPT_DIR}/.googletest-download.XXXXXX")
archive_path="${download_dir}/${GTEST_DIR_NAME}.zip"

cleanup()
{
    rm -rf -- "${download_dir}"
}
trap cleanup 0

if ! command -v wget >/dev/null 2>&1; then
    echo "wget is required to download GoogleTest." >&2
    exit 1
fi

if [ -n "${GTEST_CA_CERT:-}" ] &&
   { [ ! -f "${GTEST_CA_CERT}" ] || [ ! -r "${GTEST_CA_CERT}" ]; }; then
    echo "GTEST_CA_CERT must reference a readable CA certificate file." >&2
    exit 1
fi

download_archive()
{
    url=$1

    if [ -n "${GTEST_CA_CERT:-}" ]; then
        wget --ca-certificate="${GTEST_CA_CERT}" --quiet --tries=2 --timeout=10 \
             --output-document="${archive_path}" "${url}"
    else
        wget --quiet --tries=2 --timeout=10 \
             --output-document="${archive_path}" "${url}"
    fi
}

if [ -n "${GTEST_DOWNLOAD_URL:-}" ]; then
    set -- "${GTEST_DOWNLOAD_URL}"
else
    set -- "${GTEST_OFFICIAL_URL}" "${GTEST_MIRROR_URL}"
fi

archive_ready=0
for download_url do
    echo "Downloading GoogleTest ${GTEST_TAG} from ${download_url}"
    if download_archive "${download_url}" &&
       unzip -tq "${archive_path}" >/dev/null 2>&1; then
        archive_ready=1
        break
    fi
    echo "Failed to download a valid archive from ${download_url}." >&2
done

if [ "${archive_ready}" -ne 1 ]; then
    echo "Unable to download GoogleTest ${GTEST_TAG}." >&2
    exit 1
fi

unzip -q "${archive_path}" -d "${download_dir}"
if [ ! -f "${download_dir}/${GTEST_DIR_NAME}/CMakeLists.txt" ] ||
   [ ! -f "${download_dir}/${GTEST_DIR_NAME}/googletest/include/gtest/gtest.h" ]; then
    echo "Downloaded archive does not contain the expected GoogleTest source tree." >&2
    exit 1
fi

mv "${download_dir}/${GTEST_DIR_NAME}" "${GTEST_DIR}"
echo "GoogleTest ${GTEST_TAG} is ready in ${GTEST_DIR}."
