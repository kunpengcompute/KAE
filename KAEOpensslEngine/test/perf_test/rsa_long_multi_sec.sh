#!/bin/bash

WORKPATH=`pwd`
ENGINEPATH=/usr/local/lib/engines-1.1
BITS=(rsa1024 rsa2048 rsa3072 rsa4096)

errorflag=(0 0)
declare -i errorcount=(0 0)
declare -i operation_count=0
function record()
{
        cd ${WORKPATH}
        if [ -f sec_long_multi_record ]; then
                rm -rf sec_long_multi_record
        fi
        touch sec_long_multi_record
        echo "operation numbers: ${operation_count}" >> sec_long_multi_record
        echo "sec algo: rsa1024 rsa2048 rsa3072 rsa4096" >> sec_long_multi_record
        echo "sec_multi_errornumbers: ${errorcount[0]} ${errorcount[1]}" >> sec_long_multi_record
}

function long_multi_testcase()
{
        cd ${WORKPATH}
        for(( i=0;i<${#BITS[@]};i++ ))
        do
                errorflag[i]=0
                openssl speed -engine ${ENGINEPATH}/kae.so -multi $1 -evp ${BITS} 2> ${WORKPATH}/sec_long_multi_data${BITS[i]}
                cat ${WORKPATH}/sec_long_multi_data${BITS[i]} | grep cannot
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
while [ $date_diff -le $1 ]
do
long_multi_testcase 512
operation_count=${operation_count}+1
date2=`date +%s`
date_diff=$((date2-date1))
echo $date_diff
done
record
exit $?
