#!/bin/bash
RESFILE="multi.txt"
ENV=""
SYNC_MULTIS="1 4 16 32 64"
ASYNC_MULTIS="1 2 4 8 16"
EXE="openssl"
ENGINE_DIR="/usr/local/lib/engines"
ENGINE_NAME="kae"
RUN_TIMES=3 

#均匀绑单P的核。因为920B单P就有2个加速器。。也为了较少开超线程带来的影响
all_cores=$(nproc)
quarter_cores=$(($all_cores *1 / 4)) 

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
    local BYTES=$3
    local avg_combined
    if [ "$2" = "1" ]; then  
        avg_combined="0"
    else  
        avg_combined="0-$(($MULTI / 2 - 1)),$quarter_cores-$(($MULTI / 2 - 1 + $quarter_cores))"
    fi  

    local SPEED_H
    local SPEED_S
    local SPEED_TMP
    local TOTAL_SPEED_S=0
    local TOTAL_SPEED_H=0

    #同步模式
    for i in $(seq 1 $RUN_TIMES); do
        unset OPENSSL_ENGINES
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -elapsed -evp $ALG -multi $MULTI -bytes $BYTES | tail -n 1 |  awk '{print $NF}'` #soft
        SPEED_TMP=${SPEED_TMP/k/}
        TOTAL_SPEED_S=$(echo "$TOTAL_SPEED_S + $SPEED_TMP" | bc)

        export OPENSSL_ENGINES=$ENGINE_DIR
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -engine $ENGINE_NAME -elapsed -evp $ALG -multi $MULTI -bytes $BYTES | tail -n 1 | awk '{print $NF}'` #hard
        SPEED_TMP=${SPEED_TMP/k/}
        TOTAL_SPEED_H=$(echo "$TOTAL_SPEED_H + $SPEED_TMP" | bc)
    done

    SPEED_S=$(echo "scale=2; $TOTAL_SPEED_S / $RUN_TIMES" | bc)
    SPEED_H=$(echo "scale=2; $TOTAL_SPEED_H / $RUN_TIMES" | bc)
    echo "$ENV , $ALG , SYNC , $MULTI , $BYTES , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DO_OPENSSL_ASYNC(){
    local ALG=$1
    local MULTI=$2
    local BYTES=$3
    local avg_combined
    if [ "$2" = "1" ]; then  
        avg_combined="0"
    else  
        avg_combined="0-$(($MULTI / 2 - 1)),$quarter_cores-$(($MULTI / 2 - 1 + $quarter_cores))"
    fi 

    local SPEED_H
    local SPEED_S
    local SPEED_TMP
    local TOTAL_SPEED_S=0
    local TOTAL_SPEED_H=0

    #异步模式
    for i in $(seq 1 $RUN_TIMES); do
        unset OPENSSL_ENGINES
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -elapsed -async_jobs 16 -multi  $MULTI -evp $ALG -bytes $BYTES  | tail -n 1 | awk '{print $NF}'` #soft
        SPEED_TMP=${SPEED_TMP/k/}
        TOTAL_SPEED_S=$(echo "$TOTAL_SPEED_S + $SPEED_TMP" | bc)

        export OPENSSL_ENGINES=$ENGINE_DIR
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -engine $ENGINE_NAME -elapsed -async_jobs 16 -multi  $MULTI -evp $ALG -bytes $BYTES  | tail -n 1 | awk '{print $NF}'` #hard
        SPEED_TMP=${SPEED_TMP/k/}
        TOTAL_SPEED_H=$(echo "$TOTAL_SPEED_H + $SPEED_TMP" | bc)
    done

    SPEED_S=$(echo "scale=2; $TOTAL_SPEED_S / $RUN_TIMES" | bc) 
    SPEED_H=$(echo "scale=2; $TOTAL_SPEED_H / $RUN_TIMES" | bc)
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
    local avg_combined
    if [ "$2" = "1" ]; then  
        avg_combined="0"
    else  
        avg_combined="0-$(($MULTI / 2 - 1)),$quarter_cores-$(($MULTI / 2 - 1 + $quarter_cores))"
    fi  

    local SPEED_TMP
    local SPEED_sign_S
    local SPEED_verify_S
    local SPEED_sign_H
    local SPEED_verify_H
    
    local TOTAL_SPEED_SIGN_S=0
    local TOTAL_SPEED_VERIFY_S=0
    local TOTAL_SPEED_SIGN_H=0
    local TOTAL_SPEED_VERIFY_H=0

    #同步模式
    for i in $(seq 1 $RUN_TIMES); do
        unset OPENSSL_ENGINES
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -elapsed -multi $MULTI $ALG  | tail -n 1` #soft
        TOTAL_SPEED_SIGN_S=$(echo "$TOTAL_SPEED_SIGN_S + $(echo $SPEED_TMP | awk '{print $(NF-1)}')" | bc)
        TOTAL_SPEED_VERIFY_S=$(echo "$TOTAL_SPEED_VERIFY_S + $(echo $SPEED_TMP | awk '{print $(NF-0)}')" | bc)
        
        export OPENSSL_ENGINES=$ENGINE_DIR
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -engine $ENGINE_NAME -elapsed -multi $MULTI $ALG  | tail -n 1 ` #hard
        TOTAL_SPEED_SIGN_H=$(echo "$TOTAL_SPEED_SIGN_H + $(echo $SPEED_TMP | awk '{print $(NF-1)}')" | bc)
        TOTAL_SPEED_VERIFY_H=$(echo "$TOTAL_SPEED_VERIFY_H + $(echo $SPEED_TMP | awk '{print $(NF-0)}')" | bc)
    done 

    SPEED_sign_S=$(echo "scale=2; $TOTAL_SPEED_SIGN_S / $RUN_TIMES" | bc)
    SPEED_verify_S=$(echo "scale=2; $TOTAL_SPEED_VERIFY_S / $RUN_TIMES" | bc)
    SPEED_sign_H=$(echo "scale=2; $TOTAL_SPEED_SIGN_H / $RUN_TIMES" | bc)
    SPEED_verify_H=$(echo "scale=2; $TOTAL_SPEED_VERIFY_H / $RUN_TIMES" | bc)

    echo "$ENV , $ALG-sign , SYNC , $MULTI , ${ALG#rsa} , $SPEED_sign_S , $SPEED_sign_H , $(echo "scale=3; $SPEED_sign_H/$SPEED_sign_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
    echo "$ENV , $ALG-verify , SYNC , $MULTI , ${ALG#rsa} , $SPEED_verify_S , $SPEED_verify_H , $(echo "scale=3; $SPEED_verify_H/$SPEED_verify_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function RSA_ASYNC(){
    local ALG=$1
    local MULTI=$2
    local avg_combined
    if [ "$2" = "1" ]; then  
        avg_combined="0"
    else  
        avg_combined="0-$(($MULTI / 2 - 1)),$quarter_cores-$(($MULTI / 2 - 1 + $quarter_cores))"
    fi  

    local SPEED
    local SPEED_sign_S
    local SPEED_verify_S
    local SPEED_sign_H
    local SPEED_verify_H
    
    local SPEED_TMP
    local TOTAL_SPEED_SIGN_S=0
    local TOTAL_SPEED_VERIFY_S=0
    local TOTAL_SPEED_SIGN_H=0
    local TOTAL_SPEED_VERIFY_H=0

    #异步模式
    for i in $(seq 1 $RUN_TIMES); do
        unset OPENSSL_ENGINES
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 ` #soft
        TOTAL_SPEED_SIGN_S=$(echo "$TOTAL_SPEED_SIGN_S + $(echo $SPEED_TMP | awk '{print $(NF-1)}')" | bc)
        TOTAL_SPEED_VERIFY_S=$(echo "$TOTAL_SPEED_VERIFY_S + $(echo $SPEED_TMP | awk '{print $(NF-0)}')" | bc)     
    
        export OPENSSL_ENGINES=$ENGINE_DIR
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -engine $ENGINE_NAME -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 ` #hard
        TOTAL_SPEED_SIGN_H=$(echo "$TOTAL_SPEED_SIGN_H + $(echo $SPEED_TMP | awk '{print $(NF-1)}')" | bc)
        TOTAL_SPEED_VERIFY_H=$(echo "$TOTAL_SPEED_VERIFY_H + $(echo $SPEED_TMP | awk '{print $(NF-0)}')" | bc)
    done

    SPEED_sign_S=$(echo "scale=2; $TOTAL_SPEED_SIGN_S / $RUN_TIMES" | bc)
    SPEED_verify_S=$(echo "scale=2; $TOTAL_SPEED_VERIFY_S / $RUN_TIMES" | bc)
    SPEED_sign_H=$(echo "scale=2; $TOTAL_SPEED_SIGN_H / $RUN_TIMES" | bc)
    SPEED_verify_H=$(echo "scale=2; $TOTAL_SPEED_VERIFY_H / $RUN_TIMES" | bc)
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
    local avg_combined
    if [ "$2" = "1" ]; then  
        avg_combined="0"
    else  
        avg_combined="0-$(($MULTI / 2 - 1)),$quarter_cores-$(($MULTI / 2 - 1 + $quarter_cores))"
    fi  

    local SPEED_S
    local SPEED_H
    local SPEED_TMP
    local TOTAL_SPEED_S=0
    local TOTAL_SPEED_H=0

    #同步模式
    for i in $(seq 1 $RUN_TIMES); do
        unset OPENSSL_ENGINES
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -elapsed -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}'` #soft
        TOTAL_SPEED_S=$(echo "$TOTAL_SPEED_S + $SPEED_TMP" | bc)

        export OPENSSL_ENGINES=$ENGINE_DIR
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -engine $ENGINE_NAME -elapsed -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}' ` #hard
        TOTAL_SPEED_H=$(echo "$TOTAL_SPEED_H + $SPEED_TMP" | bc)
    done

    SPEED_S=$(echo "scale=2; $TOTAL_SPEED_S / $RUN_TIMES" | bc) 
    SPEED_H=$(echo "scale=2; $TOTAL_SPEED_H / $RUN_TIMES" | bc)
    echo "$ENV , $ALG , SYNC , $MULTI , ${ALG#ffdh} , $SPEED_S , $SPEED_H , $(echo "scale=3; $SPEED_H/$SPEED_S" | bc | awk '{printf "%.3f\n", $0}') " >> $RESFILE
}

function DH_ASYNC(){
    local ALG=$1
    local MULTI=$2
    local avg_combined
    if [ "$2" = "1" ]; then  
        avg_combined="0"
    else  
        avg_combined="0-$(($MULTI / 2 - 1)),$quarter_cores-$(($MULTI / 2 - 1 + $quarter_cores))"
    fi  

    local SPEED_S
    local SPEED_H
    local SPEED_TMP
    local TOTAL_SPEED_S=0
    local TOTAL_SPEED_H=0

    #异步模式
    for i in $(seq 1 $RUN_TIMES); do
        unset OPENSSL_ENGINES
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}'` #soft
        TOTAL_SPEED_S=$(echo "$TOTAL_SPEED_S + $SPEED_TMP" | bc)

        export OPENSSL_ENGINES=$ENGINE_DIR
        SPEED_TMP=`taskset -c $avg_combined $EXE speed -engine $ENGINE_NAME -elapsed -async_jobs 16 -multi $MULTI $ALG  | tail -n 1 | awk '{print $(NF-0)}'` #hard
        TOTAL_SPEED_H=$(echo "$TOTAL_SPEED_H + $SPEED_TMP" | bc)
    done

    SPEED_S=$(echo "scale=2; $TOTAL_SPEED_S / $RUN_TIMES" | bc) 
    SPEED_H=$(echo "scale=2; $TOTAL_SPEED_H / $RUN_TIMES" | bc)   
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
    check_enviroment
    echo "测试环境 , 算法 , 同步异步 , 进程数量 , 包长 , 软算速度 KB/s , 硬算速度 KB/s , 硬软比 " > $RESFILE

    #AES
    DO_ALG "aes-256-cbc aes-256-ctr aes-256-ecb aes-256-xts aes-256-ofb aes-256-cfb"  "64 256 512 1024 4096 16384 262144 1048576"

    #SM4
    DO_ALG "sm4-cbc sm4-ctr sm4-ecb sm4-ofb sm4-cfb" "64 256 512 1024 4096 16384 262144 1048576"

    #SM3
    DO_ALG "sm3" "64 256 512 1024 4096 16384 262144 1048576"

    #MD5
    DO_ALG "md5" "64 512 4096 16384 262144 1048576"

    #RSA
    DO_RSA "rsa2048 rsa4096"

    #SM2
    DO_RSA "sm2"

    #DH
    DO_DH "ffdh2048 ffdh4096"

}

main "$@"
exit $?
