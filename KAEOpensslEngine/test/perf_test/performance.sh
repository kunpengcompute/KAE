#!/bin/sh
set -e
exec > openssl-kae.log 2>&1
function aes_test()
{
    echo "-----------------------------------------------AES 同步性能测试-----------------------------------------------"
    echo "1、AES-CBC:软算 ===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp aes-256-cbc
    echo "2、AES-CBC:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp aes-256-cbc 
    echo "3、AES-ECB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp aes-256-ecb
    echo "4、AES-ECB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp aes-256-ecb
    echo "5、AES-CTR:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp aes-256-ctr
    echo "6、AES-CTR:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp aes-256-ctr
    echo "7、AES-XTS:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp aes-256-xts
    echo "8、AES-XTS:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp aes-256-xts
    echo "9、AES-OFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp aes-256-ofb
    echo "10、AES-OFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp aes-256-ofb
    echo "11、AES-CFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp aes-256-cfb
    echo "12、AES-CFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp aes-256-cfb
    echo "13、AES-GCM:软算===========================================>"

    echo "-----------------------------------------------AES 异步性能测试-----------------------------------------------"
    echo "1、AES-CBC:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp aes-256-cbc
    echo "2、AES-CBC:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp aes-256-cbc
    echo "3、AES-ECB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp aes-256-ecb
    echo "4、AES-ECB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp aes-256-ecb
    echo "5、AES-CTR:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp aes-256-ctr
    echo "6、AES-CTR:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp aes-256-ctr
    echo "7、AES-XTS:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp aes-256-xts
    echo "8、AES-XTS:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp aes-256-xts
    echo "9、AES-OFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp aes-256-ofb
    echo "10、AES-OFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp aes-256-ofb
    echo "11、AES-CFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp aes-256-cfb
    echo "12、AES-CFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp aes-256-cfb
    echo "13、AES-GCM:软算===========================================>"  
}

function sm4_test()
{
    echo "-----------------------------------------------SM4 同步性能测试-----------------------------------------------"
    echo "1、SM4-CBC:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp sm4-cbc
    echo "2、SM4-CBC:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp sm4-cbc
    echo "3、SM4-ECB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp sm4-ecb
    echo "4、SM4-ECB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp sm4-ecb
    echo "5、SM4-CTR:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp sm4-ctr
    echo "6、SM4-CTR:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp sm4-ctr
    echo "7、SM4-OFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp sm4-ofb
    echo "8、SM4-OFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp sm4-ofb
    echo "9、SM4-CFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -evp sm4-cfb
    echo "10、SM4-CFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -evp sm4-cfb

    echo "-----------------------------------------------SM4 异步性能测试-----------------------------------------------"
    echo "1、SM4-CBC:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp sm4-cbc
    echo "2、SM4-CBC:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp sm4-cbc
    echo "3、SM4-ECB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp sm4-ecb
    echo "4、SM4-ECB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp sm4-ecb
    echo "5、SM4-CTR:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp sm4-ctr
    echo "6、SM4-CTR:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp sm4-ctr
    echo "7、SM4-OFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp sm4-ofb
    echo "8、SM4-OFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -async_jobs 16 -multi 1 -elapsed -evp sm4-ofb
    echo "9、SM4-CFB:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 -evp sm4-cfb
    echo "10、SM4-CFB:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 -evp sm4-cfb
}


function sm3_test()
{
    echo "-----------------------------------------------SM3 同步性能测试-----------------------------------------------"
    echo "1、SM3:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -multi 1 -evp sm3
    echo "2、SM3:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -multi 1 -evp sm3

    echo "-----------------------------------------------SM3 异步性能测试-----------------------------------------------"
    echo "1、SM3:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 36 -multi 1 -evp sm3
    echo "2、SM3:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 36 -multi 1 -evp sm3
}

function sm2_test()
{
    echo "-----------------------------------------------SM2 同步性能测试-----------------------------------------------"
    echo "1、SM2:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -multi 1 sm2
    echo "2、SM2:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -multi 1 sm2

    echo "-----------------------------------------------SM2 异步性能测试-----------------------------------------------"
    echo "1、SM2:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 sm2
    echo "2、SM2:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 sm2
}

function rsa_test()
{
    echo "-----------------------------------------------RSA 同步性能测试-----------------------------------------------"
    echo "1、RSA2048:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -multi 1 rsa2048
    echo "2、RSA2048:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -multi 1 rsa2048
    echo "3、RSA4096:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -multi 1 rsa4096
    echo "4、RSA4096:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -multi 1 rsa4096

    echo "-----------------------------------------------RSA 异步性能测试-----------------------------------------------"
    echo "1、RSA2048:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 rsa2048
    echo "2、RSA2048:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 rsa2048
    echo "3、RSA4096:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 16 -multi 1 rsa4096
    echo "4、RSA4096:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 16 -multi 1 rsa4096
}

function md5_test()
{
    echo "-----------------------------------------------MD5 同步性能测试-----------------------------------------------"
    echo "1、MD5:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -multi 1 -evp md5
    echo "2、MD5:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -multi 1 -evp md5

    echo "-----------------------------------------------MD5 异步性能测试-----------------------------------------------"
    echo "1、MD5:软算===========================================>"
    taskset -c 0-63 openssl speed -elapsed -async_jobs 36 -multi 1 -evp md5
    echo "2、MD5:硬算===========================================>"
    taskset -c 0-63 openssl speed -engine kae -elapsed -async_jobs 36 -multi 1 -evp md5
}

function help()
{
    echo "test kae algs performance"
	echo "sh performance.sh all"
	echo "sh performance.sh AES"
	echo "sh performance.sh SM4"
	echo "sh performance.sh SM2"
	echo "sh performance.sh SM3"
	echo "sh performance.sh RSA"
	echo "sh performance.sh MD5"
}

function main()
{
	if [ "$1" = "all" ];then
        date
        aes_test
        sm4_test
        sm3_test
        sm2_test
        rsa_test
        md5_test
    elif [ "$1" = "AES" ];then
        date
        aes_test
    elif [ "$1" = "SM4" ];then
        date
        sm4_test
    elif [ "$1" = "SM3" ];then
        date
        sm3_test
    elif [ "$1" = "SM2" ];then
        date
        sm2_test
    elif [ "$1" = "RSA" ];then
        date
        rsa_test
    elif [ "$1" = "MD5" ];then
       date
       md5_test 
    else
        help
    fi
}
main "$@"
exit $?