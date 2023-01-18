#!/bin/bash
set -e
CODE_PATH=/home/taishan/hisi_acc
declare -a host_lists=("128.5.160.135" "128.5.160.136" "128.5.160.137" "128.5.160.138" "128.5.160.139" "128.5.160.141" "128.5.160.142" "128.5.160.143" "128.5.160.144")

function getcode()
{
    if [ -d $CODE_PATH ];then
        rm -rf $CODE_PATH
    fi
    mkdir -p $CODE_PATH

    cd $CODE_PATH
    git clone https://gitee.com/kunpengcompute/KAEzip.git
    git clone https://gitee.com/kunpengcompute/KAEdriver.git
    git clone https://gitee.com/kunpengcompute/KAE.git

}

function transcode()
{
    for ((i=0;i<${#host_lists[*]};i++))
    do
        scp -r $CODE_PATH root@"${host_lists[i]}":/home/taishan
    done
}

function main()
{
    getcode
    if [ $? -ne 0 ];then
        exit 1
    fi
#    transcode
#    if [ $? -ne 0 ];then
#        exit 1
#    fi
}

main $@
exit $?
