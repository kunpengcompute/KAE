#!/bin/bash

WORKPATH=`pwd`
ENGINEPATH=/usr/local/lib/engines-1.1
BITS=(g2_768 g2_1024 g2_1536 g2_2048 g2_3072)

errorflag=(0 0)
declare -i errorcount=(0 0)
declare -i operation_count=0
function record()
{
        cd ${WORKPATH}
        if [ -f dh_long_multi_record ]; then
                rm -rf dh_long_multi_record
        fi
        touch dh_long_multi_record
        echo "operation numbers: ${operation_count}" >> dh_long_multi_record
        echo "dh algo: g2_768 g2_1024 g2_1536 g2_2048 g2_3072" >> dh_long_multi_record
        echo "dh_multi_errornumbers: ${errorcount[0]} ${errorcount[1]}" >> dh_long_multi_record
}

function long_multi_testcase()
{
        cd ${WORKPATH}
        for(( i=0;i<${#BITS[@]};i++ ))
        do
                errorflag[i]=0
                openssl genpkey -engine ${ENGINEPATH}/kae.so -out Akey.pem -paramfile ${BITS}.pem 2> ${WORKPATH}/dh_long_multi_data${BITS[i]}
                openssl genpkey -engine ${ENGINEPATH}/kae.so -out Bkey.pem -paramfile ${BITS}.pem 2> ${WORKPATH}/dh_long_multi_data${BITS[i]}
                openssl pkey -in Akey.pem -pubout -out Apub.pem 2> ${WORKPATH}/dh_long_multi_data${BITS[i]}
                openssl pkey -in Bkey.pem -pubout -out Bpub.pem 2> ${WORKPATH}/dh_long_multi_data${BITS[i]}
                openssl pkeyutl -engine ${ENGINEPATH}/kae.so -derive -inkey Bkey.pem -peerkey Apub.pem -out Bsecret.bin 2> ${WORKPATH}/dh_long_multi_data${BITS[i]}
                openssl pkeyutl -engine ${ENGINEPATH}/kae.so -derive -inkey Akey.pem -peerkey Bpub.pem -out Asecret.bin -engine_impl 2> ${WORKPATH}/dh_long_multi_data${BITS[i]}
                cat ${WORKPATH}/dh_long_multi_data${BITS[i]} | grep rror
                errorflag[i]=$?
                echo $errorflag[i]
                if [ ${errorflag[i]} -eq 0 ]; then
                errorcount[i]=${errorcount[i]}+1
                fi
        done
}
date1=`date +%s`
date2=`date +%s`
date_diff=$((date2-date1))
operation_count=0
while [[ $date_diff -le $1 ]]
do
long_multi_testcase
operation_count=${operation_count}+1
date2=`date +%s`
date_diff=$((date2-date1))
echo $date_diff
done
record
exit $?