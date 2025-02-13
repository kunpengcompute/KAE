#!/bin/bash
##############################################################
## Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
## @Filename: download.sh
## @Usage:    sh download.sh download googletest source code
##############################################################

curd=$(pwd)
test=$curd/..
root_path=$curd/../..

if [ -d ./googletest-release-1.11.0 ]
then
    echo -e "\033[32m The googletest-release-1.11.0 directory already exists and does not need to be downloaded. \033[0m"
    exit 0
fi

if [ -d ./googletest-release-1.11.0.zip ]
then
    echo -e "\033[32m The googletest-release-1.11.0.zip was downloaded, now doing unzip. \033[0m"
    unzip googletest-release-1.11.0.zip
    exit 0
fi

if [ -d ~/.ArtGet/conf/Setting.xml ]
then
    nohup artget config
fi

#这里可以考虑通过wget的方式获取想要的gtest包,如果环境有googletest-release-1.11.0.zip，复制到此目录也行

unzip googletest-release-1.11.0.zip