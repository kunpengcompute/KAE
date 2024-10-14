#!/bin/bash
# Copyright © Huawei Technologies Co., Ltd. 2010-2024. All rights reserved.
# @rem Copyright © Huawei Technologies Co., Ltd. 2010-2024. All rights reserved.
# @rem Description: build script
set -e

SRC_PATH=$(pwd)

rm -rf lzbench-master-raw
rm -rf lzbench-master

unzip lzbench-master.zip
mv lzbench-master lzbench-master-raw
unzip lzbench-master.zip

patch -p0 < lzbench_KAELz4.patch

cd "${SRC_PATH}"/lzbench-master/
make -j
cd "${SRC_PATH}"/lzbench-master-raw/
make -j
exit $?