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

cmc_password=encryption:ETMsDgAAAX/ivQNAABRBRVMvQ0JDL1BLQ1M1UGFkZGluZwCAABAAEKr5STl2OcRhT+LTEVcntCgAAAAgj0qJKhxDoLlKf71D8TZ+svEoskxC48Ac2mbIsNPPDn8AFGxAXNHURIA/BEnJIapqrbN6LgqX && sed -i "/<password>/,/<\/password>/s#<password>.*</password>#<password>${cmc_password}</password>#g" ~/.ArtGet/conf/Setting.xml
sed -i "/<userName>/,/<\/userName>/s#<userName>.*</userName>#<userName>pDriverCI</userName>#g" ~/.ArtGet/conf/Setting.xml
sed -i "/<agentPath>/,/<\/agentPath>/s#<agentPath>.*</agentPath>#<agentPath>${test}</agentPath>#g" ~/.ArtGet/conf/Setting.xml

artget pull -d download.xml

unzip googletest-release-1.11.0.zip