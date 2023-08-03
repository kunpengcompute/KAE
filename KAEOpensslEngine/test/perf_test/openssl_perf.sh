#!/bin/bash
#################################################################################################
# This performance test case set is designed based on the algorithm specifications supported by #
# the KAE in the 920 environment. Before using this test case, ensure that the KAE hardware     #
# acceleration takes effect and the path of the openssl.cnf configuration file. The contents    #
# of the openssl.cnf file are as follows:                                                       #
#---------------------------------------------------------------------------------------------- #
# openssl_conf=openssl_def
# [openssl_def]
# engines=engine_section
# [engine_section]
# kae=kae_section
# [kae_section]
# engine_id=kae
# dynamic_path=/usr/local/lib/engines-1.1/kae.so
# default_algorithms=ALL
# init=1          
###############################################################################################

OPENSSL_CONF_PATH=/home/openssl.cnf
RESFILE="res.txt"
ENV="920"
SYNC_MULTIS="1 4 16 32"
ASYNC_MULTIS="1 2 4"

#AES
AES_ALGES="aes-256-cbc aes-256-ctr aes-256-cbc aes-256-xts"
AES_BYTES="512 1024 4096 16384 65536 262144 1048576" #0.5K 1K 4K 16K 64K 256K 1M

#SM4
SM4_ALGES="sm4-cbc sm4-ctr sm4-ecb sm4-ofb"
SM4_BYTES="512 1024 4096 16384 65536 262144 1048576" #0.5K 1K 4K 16K 64K 256K 1M

##########################################
#           general alg perf             #
##########################################

function DO_OPENSSL_SYNC(){
    local ALG=$1
    local MULTI=$2
    local BYTES=$3

    local SPEED_H
    local SPEED_S
    #同步模式
    export OPENSSL_CONF=
    SPEED_S=`taskset -c 0-63 openssl speed -elapsed -evp $ALG -multi $MULTI -bytes $BYTES | tail -n 1 |  awk '{print $NF}'` #soft
    SPEED_S=${SPEED_S/k/}
    export OPENSSL_CONF=$OPENSSL_CONF_PATH
    SPEED_H=`taskset -c 0-63 openssl speed -engine kae -elapsed -evp $ALG -multi $MULTI -bytes $BYTES | tail -n 1 | awk '{print $NF}'` #hard
    SPEED_H=${SPEED_H/k/}
    echo "$ENV , $ALG , SYNC , $MULTI , $BYTES , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DO_OPENSSL_ASYNC(){
    local ALG=$1
    local MULTI=$2
    local BYTES=$3

    local SPEED_H
    local SPEED_S

    #异步模式
    export OPENSSL_CONF=
    SPEED_S=`taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi  $MULTI -evp $ALG -bytes $BYTES  | tail -n 1 | awk '{print $NF}'` #soft
    SPEED_S=${SPEED_S/k/}
    export OPENSSL_CONF=$OPENSSL_CONF_PATH
    SPEED_H=`taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi  $MULTI -evp $ALG -bytes $BYTES  | tail -n 1 | awk '{print $NF}'` #hard
    SPEED_H=${SPEED_H/k/}
    echo "$ENV , $ALG , ASYNC , 16x$MULTI , $BYTES , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DO_ALG(){
    local ALGES=$1
    local BYTES=$2
    #AES-同步
    for alg in $ALGES
    do
        for sync_nulti in $SYNC_MULTIS
        do
            for aes_bytes in $BYTES
            do
                DO_OPENSSL_SYNC $alg $sync_nulti $aes_bytes
            done
        done
    done

    #AES-异步
    for alg in $ALGES
    do
        for sync_nulti in $ASYNC_MULTIS
        do
            for aes_bytes in $BYTES
            do
                DO_OPENSSL_ASYNC $alg $sync_nulti $aes_bytes
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

    local SPEED_verify_S
    local SPEED_sign_S
    local SPEED_verify_H
    local SPEED_sign_H
    local SPEED
    #同步模式
    export OPENSSL_CONF=
    SPEED=`taskset -c 0-63 openssl speed -elapsed -multi $MULTI $ALG  | tail -n 1` #soft
    SPEED_sign_S=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_S=$(echo $SPEED | awk '{print $(NF-0)}')

    export OPENSSL_CONF=$OPENSSL_CONF_PATH
    SPEED=`taskset -c 0-63 openssl speed -engine kae -elapsed -multi $MULTI $ALG  | tail -n 1 ` #hard
    SPEED_sign_H=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_H=$(echo $SPEED | awk '{print $(NF-0)}')

    echo "$ENV , $ALG-sign , SYNC , $MULTI , ${ALG#rsa} , $SPEED_sign_S , $SPEED_sign_H , $(echo "scale=3; $SPEED_sign_H/$SPEED_sign_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
    echo "$ENV , $ALG-verify , SYNC , $MULTI , ${ALG#rsa} , $SPEED_verify_S , $SPEED_verify_H , $(echo "scale=3; $SPEED_verify_H/$SPEED_verify_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function RSA_ASYNC(){
    local ALG=$1
    local MULTI=$2

    local SPEED_verify_S
    local SPEED_sign_S
    local SPEED_verify_H
    local SPEED_sign_H
    local SPEED
    #异步模式
    export OPENSSL_CONF=
    SPEED=`taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 ` #soft
    SPEED_sign_S=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_S=$(echo $SPEED | awk '{print $(NF-0)}')

    export OPENSSL_CONF=$OPENSSL_CONF_PATH
    SPEED=`taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 ` #hard
    SPEED_sign_H=$(echo $SPEED | awk '{print $(NF-1)}')
    SPEED_verify_H=$(echo $SPEED | awk '{print $(NF-0)}')
    echo "$ENV , $ALG-sign , ASYNC , 16x$MULTI , ${ALG#rsa} , $SPEED_sign_S , $SPEED_sign_H , $(echo "scale=3; $SPEED_sign_H/$SPEED_sign_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
    echo "$ENV , $ALG-verify , ASYNC , 16x$MULTI , ${ALG#rsa} , $SPEED_verify_S , $SPEED_verify_H , $(echo "scale=3; $SPEED_verify_H/$SPEED_verify_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DO_RSA(){
    local ALGES=$1
    #AES-同步
    for alg in $ALGES
    do
        for sync_nulti in $SYNC_MULTIS
        do
            RSA_SYNC $alg $sync_nulti
        done
    done

    #AES-异步
    for alg in $ALGES
    do
        for sync_nulti in $ASYNC_MULTIS
        do
            RSA_ASYNC $alg $sync_nulti
        done
    done
}

##########################################
#               DH perf                 #
##########################################
function DH_SYNC(){
    local ALG=$1
    local MULTI=$2

    local SPEED_S
    local SPEED_H
    #同步模式
    export OPENSSL_CONF=
    SPEED_S=`taskset -c 0-63 ./openssl_dh speed -elapsed -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}'` #soft

    export OPENSSL_CONF=$OPENSSL_CONF_PATH
    SPEED_H=`taskset -c 0-63 ./openssl_dh speed -engine kae -elapsed -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}' ` #hard

    echo "$ENV , $ALG , SYNC , $MULTI , ${ALG#ffdh} , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DH_ASYNC(){
    local ALG=$1
    local MULTI=$2
    local SPEED_S
    local SPEED_H
    #异步模式
    export OPENSSL_CONF=
    SPEED_S=`taskset -c 0-63 ./openssl_dh speed -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}'` #soft

    export OPENSSL_CONF=$OPENSSL_CONF_PATH
    SPEED_H=`taskset -c 0-63 ./openssl_dh speed -engine kae -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}'` #hard

    echo "$ENV , $ALG , ASYNC , 16x$MULTI , ${ALG#ffdh} , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DO_DH(){
    local ALGES=$1
    #AES-同步
    for alg in $ALGES
    do
        for sync_nulti in $SYNC_MULTIS
        do
            DH_SYNC $alg $sync_nulti
        done
    done

    #AES-异步
    for alg in $ALGES
    do
        for sync_nulti in $ASYNC_MULTIS
        do
            DH_ASYNC $alg $sync_nulti
        done
    done
}


function main(){
    echo "测试环境 , 算法 , 同步异步 , 进程数量 , 包长 , 软算速度 KB/s , 硬算速度 KB/s , 硬软比 " > $RESFILE

    #AES
    DO_ALG "aes-256-cbc aes-256-ctr aes-256-ecb aes-256-xts"  "512 1024 4096 16384 65536 262144 1048576"

    #SM4
    DO_ALG "sm4-cbc sm4-ctr sm4-ecb sm4-ofb" "512 1024 4096 16384 65536 262144 1048576"

    #SM3
    DO_ALG "sm3" "512 1024 4096 16384 65536 262144 1048576"

    #MD5
    DO_ALG "md5" "512 1024 4096 16384 65536 262144 1048576"

    #RSA
    DO_RSA "rsa2048 rsa4096"

    #DH
    DO_DH "ffdh2048 ffdh4096"

}

main "$@"
exit $?