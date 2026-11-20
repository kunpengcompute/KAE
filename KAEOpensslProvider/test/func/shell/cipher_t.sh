#!/bin/bash
set -e

export KAE_CONF_ENV=/var/log/
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
echo -e "[LogSection]\ndebug_level=debug" > /var/log/kae.cnf


# 16进制
key="0123456789abcdef0123456789abcde1"
iv="0123456789abcdef0123456789abcde2"


# tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16384 > plain.txt
# openssl enc -sm4-cbc -in plain.txt -out cipher.bin -K 0123456789abcdef0123456789abcde1 -iv 0123456789abcdef0123456789abcde2 -provider kae_provider -provider default
# openssl enc -d -sm4-cbc -in cipher.bin -out decrypt.txt -K 0123456789abcdef0123456789abcde1 -iv 0123456789abcdef0123456789abcde2 -provider kae_provider -provider default


# 封装测试函数
run_cipher_test() {
    local algo=$1
    local size=$2
    local label=$3

    local log_threshold=192

    # 硬算加密、硬算解密
    rm -rf /var/log/kae.log plain.txt cipher.bin decrypt.txt
    echo "(${label}) character data"
    #dd if=/dev/urandom of=plain.txt bs=${size} count=1 2>/dev/null
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c ${size} > plain.txt
    openssl enc -${algo} -in plain.txt -out cipher.bin -K ${key} -iv ${iv} -provider kae_provider -provider default 2>/dev/null
    if [ "${size}" -ge "${log_threshold}" ]; then
        if ! grep -qE "sec cipher success" /var/log/kae.log 2>/dev/null; then
            echo "Neither of the two messages found!"
            exit 1
        fi
    fi
    rm -rf /var/log/kae.log
    openssl enc -d -${algo} -in cipher.bin -out decrypt.txt -K ${key} -iv ${iv} -provider kae_provider -provider default 2>/dev/null
    if [ "${size}" -ge "${log_threshold}" ]; then
        if ! grep -qE "sec cipher success" /var/log/kae.log 2>/dev/null; then
            echo "Neither of the two messages found!"
            exit 1
        fi
    fi
    if ! diff plain.txt decrypt.txt >/dev/null; then
        echo -e "${algo} kae enc and kae dec failed!\n"
        exit 1
    fi

    # 软算加密、硬算解密
    rm -rf /var/log/kae.log plain.txt cipher.bin decrypt.txt
    #dd if=/dev/urandom of=plain.txt bs=${size} count=1 2>/dev/null
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c ${size} > plain.txt
    openssl enc -${algo} -in plain.txt -out cipher.bin -K ${key} -iv ${iv} -provider default 2>/dev/null
    openssl enc -d -${algo} -in cipher.bin -out decrypt.txt -K ${key} -iv ${iv} -provider kae_provider -provider default 2>/dev/null
    if [ "${size}" -ge "${log_threshold}" ]; then
        if ! grep -qE "sec cipher success" /var/log/kae.log 2>/dev/null; then
            echo "Neither of the two messages found!"
            exit 1
        fi
    fi
    if ! diff plain.txt decrypt.txt >/dev/null; then
        echo -e "${algo} soft enc and kae dec failed!\n"
        exit 1
    fi

    # 硬算加密、软算解密
    rm -rf /var/log/kae.log plain.txt cipher.bin decrypt.txt
    #dd if=/dev/urandom of=plain.txt bs=${size} count=1 2>/dev/null
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c ${size} > plain.txt
    openssl enc -${algo} -in plain.txt -out cipher.bin -K ${key} -iv ${iv} -provider kae_provider -provider default 2>/dev/null
    if [ "${size}" -ge "${log_threshold}" ]; then
        if ! grep -qE "sec cipher success" /var/log/kae.log 2>/dev/null; then
            echo "Neither of the two messages found!"
            exit 1
        fi
    fi
    openssl enc -d -${algo} -in cipher.bin -out decrypt.txt -K ${key} -iv ${iv} -provider default 2>/dev/null

    if ! diff plain.txt decrypt.txt >/dev/null; then
        echo -e "${algo} kae enc and soft dec failed!\n"
        exit 1
    fi
}

# 测试不同文件大小 (md5 / sm3)
for algo in sm4-cbc aes-128-cbc sm4-ecb aes-128-ecb sm4-ctr aes-128-ctr sm4-ofb aes-128-ofb sm4-cfb aes-128-cfb; do
    echo "=====(${algo}) test======"
    run_cipher_test $algo 64    "64B"
    run_cipher_test $algo 254    "254B"
    run_cipher_test $algo 256    "256B"
    run_cipher_test $algo 4096    "4K"
    run_cipher_test $algo 16384  "16K"
    run_cipher_test $algo 524288 "512K"
    echo -e "${algo} cipher success!\n"
done

rm -rf /var/log/kae.log 
rm -rf plain.txt
rm -rf cipher.bin 
rm -rf decrypt.txt