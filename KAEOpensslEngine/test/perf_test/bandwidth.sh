#!/bin/bash
RESFILE="bwidth.txt"
ENV=""

EXE="openssl"
ENGINE_DIR="/usr/local/lib/engines"
ENGINE_NAME="kae"

TIME_SEC="20"

# 获取 CPU 核心数
all_cores=$(nproc)
half_cores=$(($all_cores *1 / 2))

CORES_NUM=($all_cores)
CORES_NUM+=($(($all_cores * 7 / 8)))
CORES_NUM+=($(($all_cores * 6 / 8)))
CORES_NUM+=($(($all_cores * 5 / 8)))

echo "CORES_NUM: ${CORES_NUM[@]}"

function check_enviroment()
{
	openssl_path=$1
	if [ "$1" = "" ];then
		openssl_path=$(which openssl | awk -F'/bin' '{print $1}')
	fi
	
    IMPLEMENTER=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
    CPUPAET=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
    if [ "${IMPLEMENTER}-${CPUPAET}" == "0x48-0xd01" ];then
        ENV="920"
        # EXE="openssl_arm"
        ENGINE_NAME="kae"
    elif [ "${IMPLEMENTER}-${CPUPAET}" == "0x48-0xd02" ];then
        ENV="920B"
        # EXE="./openssl_arm"
        ENGINE_NAME="kae"
    elif [ $(arch) == "x86_64" ];then
        ENV="X86"
        # EXE="./openssl_x86"
        ENGINE_NAME="qatengine"
    else
        ENV="UNKNOW CPU"
        # EXE="openssl"
    fi
	
	$openssl_path/bin/openssl version
	if $openssl_path/bin/openssl version | grep -q "OpenSSL 3."; then    
        ENGINE_DIR="${ENGINE_DIR}-3.0"    
    elif $openssl_path/bin/openssl version | grep -q "OpenSSL 1."; then    
		ENGINE_DIR="${ENGINE_DIR}-1.1"
    else 
        echo "OpenSSL version is not support"   
    fi
}

##########################################
#           general alg perf             #
##########################################

function DO_OPENSSL_SYNC(){
    local ALG=$1
    local MULTI=$2
    local HALF_MULTI=$(($2 / 2))
    local BYTES=$3

    local half_combined="0-$(($half_cores-1))"
    local all_combined="0-$(($MULTI / 2 - 1)),$half_cores-$(($MULTI / 2 - 1 + $half_cores))"


    local SPEED_H
    local SPEED_S
    

    # 单P
    unset OPENSSL_ENGINES
    SPEED_S=`taskset -c $half_combined $EXE speed -elapsed -evp $ALG -multi $HALF_MULTI -bytes $BYTES -seconds $TIME_SEC | tail -n 1 |  awk '{print $NF}'` #soft
    SPEED_S=${SPEED_S/k/}
    export OPENSSL_ENGINES=$ENGINE_DIR
    SPEED_H=`taskset -c $half_combined $EXE speed -engine $ENGINE_NAME -elapsed -evp $ALG -multi $HALF_MULTI -bytes $BYTES -seconds $TIME_SEC | tail -n 1 | awk '{print $NF}'` #hard
    SPEED_H=${SPEED_H/k/}
    echo "$ENV , $ALG , SYNC , $HALF_MULTI , $BYTES , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE

    # 整机
    unset OPENSSL_ENGINES
    SPEED_S=`taskset -c $all_combined $EXE speed -elapsed -evp $ALG -multi $MULTI -bytes $BYTES -seconds $TIME_SEC | tail -n 1 |  awk '{print $NF}'` #soft
    SPEED_S=${SPEED_S/k/}
    export OPENSSL_ENGINES=$ENGINE_DIR
    SPEED_H=`taskset -c $all_combined $EXE speed -engine $ENGINE_NAME -elapsed -evp $ALG -multi $MULTI -bytes $BYTES -seconds $TIME_SEC | tail -n 1 | awk '{print $NF}'` #hard
    SPEED_H=${SPEED_H/k/}
    echo "$ENV , $ALG , SYNC , $MULTI , $BYTES , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}


function DO_EVP_BD(){
    local ALGES=$1
    local BYTES=$2
    #AES
    for alg in $ALGES
    do
        for sync_nulti in ${CORES_NUM[@]}
        do
            for aes_bytes in $BYTES
            do
                DO_OPENSSL_SYNC $alg $sync_nulti $aes_bytes
            done
        done
    done
}

##########################################
#               RSA perf                 #
##########################################

function RSA_SYNC(){
    local ALG=$1
    local MULTI=$2

    local HALF_MULTI=$(($2 / 2))
    local half_combined="0-$(($half_cores-1))"
    local all_combined="0-$(($MULTI / 2 - 1)),$half_cores-$(($MULTI / 2 - 1 + $half_cores))"

    local SPEED_verify_S
    local SPEED_sign_S
    local SPEED_verify_H
    local SPEED_sign_H
    local SPEED



    #单P
    unset OPENSSL_ENGINES
    SPEED=`taskset -c $half_combined $EXE speed -elapsed -multi $HALF_MULTI -seconds $TIME_SEC $ALG | tail -n 1` #soft
    SPEED_sign_S=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_S=$(echo $SPEED | awk '{print $(NF-0)}')

    export OPENSSL_ENGINES=$ENGINE_DIR
    SPEED=`taskset -c $half_combined $EXE speed -engine $ENGINE_NAME -elapsed -multi $HALF_MULTI -seconds $TIME_SEC $ALG | tail -n 1 ` #hard
    SPEED_sign_H=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_H=$(echo $SPEED | awk '{print $(NF-0)}')

    echo "$ENV , $ALG-sign , SYNC , $HALF_MULTI , ${ALG#rsa} , $SPEED_sign_S , $SPEED_sign_H , $(echo "scale=3; $SPEED_sign_H/$SPEED_sign_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
    echo "$ENV , $ALG-verify , SYNC , $HALF_MULTI , ${ALG#rsa} , $SPEED_verify_S , $SPEED_verify_H , $(echo "scale=3; $SPEED_verify_H/$SPEED_verify_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE



    #整机
    unset OPENSSL_ENGINES
    SPEED=`taskset -c $all_combined $EXE speed -elapsed -multi $MULTI -seconds $TIME_SEC $ALG | tail -n 1` #soft
    SPEED_sign_S=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_S=$(echo $SPEED | awk '{print $(NF-0)}')

    export OPENSSL_ENGINES=$ENGINE_DIR
    SPEED=`taskset -c $all_combined $EXE speed -engine $ENGINE_NAME -elapsed -multi $MULTI -seconds $TIME_SEC $ALG | tail -n 1 ` #hard
    SPEED_sign_H=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_H=$(echo $SPEED | awk '{print $(NF-0)}')

    echo "$ENV , $ALG-sign , SYNC , $MULTI , ${ALG#rsa} , $SPEED_sign_S , $SPEED_sign_H , $(echo "scale=3; $SPEED_sign_H/$SPEED_sign_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
    echo "$ENV , $ALG-verify , SYNC , $MULTI , ${ALG#rsa} , $SPEED_verify_S , $SPEED_verify_H , $(echo "scale=3; $SPEED_verify_H/$SPEED_verify_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE

}


function DO_RSA_BD(){
    local ALGES=$1
    #AES-同步
    for alg in $ALGES
    do
        for sync_nulti in ${CORES_NUM[@]}
        do
            RSA_SYNC $alg $sync_nulti
        done
    done
}

##########################################
#               DH perf                 #
##########################################
function DH_SYNC(){
    local ALG=$1
    local MULTI=$2

    local HALF_MULTI=$(($2 / 2))
    local half_combined="0-$(($half_cores-1))"
    local all_combined="0-$(($MULTI / 2 - 1)),$half_cores-$(($MULTI / 2 - 1 + $half_cores))"

    local SPEED_S
    local SPEED_H


    #单P
    unset OPENSSL_ENGINES
    SPEED_S=`taskset -c $half_combined $EXE speed -elapsed -multi $HALF_MULTI -seconds $TIME_SEC $ALG  | tail -n 1 | awk '{print $(NF-0)}'` #soft

    export OPENSSL_ENGINES=$ENGINE_DIR
    SPEED_H=`taskset -c $half_combined $EXE speed -engine $ENGINE_NAME -elapsed -multi $HALF_MULTI -seconds $TIME_SEC $ALG  | tail -n 1 | awk '{print $(NF-0)}' ` #hard

    echo "$ENV , $ALG , SYNC , $HALF_MULTI , ${ALG#ffdh} , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE


    #整机
    unset OPENSSL_ENGINES
    SPEED_S=`taskset -c $all_combined $EXE speed -elapsed -multi $MULTI -seconds $TIME_SEC $ALG | tail -n 1 | awk '{print $(NF-0)}'` #soft

    export OPENSSL_ENGINES=$ENGINE_DIR
    SPEED_H=`taskset -c $all_combined $EXE speed -engine $ENGINE_NAME -elapsed -multi $MULTI -seconds $TIME_SEC $ALG  | tail -n 1 | awk '{print $(NF-0)}' ` #hard

    echo "$ENV , $ALG , SYNC , $MULTI , ${ALG#ffdh} , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DO_DH_BD(){
    local ALGES=$1
    #AES-同步
    for alg in $ALGES
    do
        for sync_nulti in ${CORES_NUM[@]}
        do
            DH_SYNC $alg $sync_nulti
        done
    done
}


function main(){
    check_enviroment
    echo "测试环境 , 算法 , 同步异步 , 进程数量 , 包长 , 软算速度 KB/s , 硬算速度 KB/s , 硬软比 " > $RESFILE

    #AES
    DO_EVP_BD "aes-256-cbc aes-256-ctr aes-256-ecb aes-256-xts aes-256-ofb aes-256-cfb"  "16384 262144 1048576"

    #SM4
    DO_EVP_BD "sm4-cbc sm4-ctr sm4-ecb sm4-ofb sm4-cfb" "16384 262144 1048576"

    #SM3
    DO_EVP_BD "sm3" "16384 262144 1048576"

    #MD5
    DO_EVP_BD "md5" "16384 262144 1048576"

    #RSA
    DO_RSA_BD "rsa2048 rsa4096"

    #SM2
    DO_RSA_BD "sm2"

    #DH
    DO_DH_BD "ffdh2048 ffdh4096"

}

main "$@"
exit $?