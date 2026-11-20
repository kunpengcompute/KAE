#!/bin/bash
set -e

export KAE_CONF_ENV=/var/log/
export OPENSSL_MODULES="${OPENSSL_MODULES:-/usr/local/lib/provider}"
echo -e "[LogSection]\ndebug_level=debug" > /var/log/kae.cnf

# 封装测试函数
run_digest_test() {
    local algo=$1
    local size=$2
    local label=$3

    local log_threshold=0
    if [ "$algo" = "md5" ]; then
        log_threshold=8196
    elif [ "$algo" = "sm3" ]; then
        log_threshold=512
    fi


    rm -rf /var/log/kae.log msg.txt
    echo "(${label}) character data"
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c ${size} > msg.txt
    kae_val=$(openssl dgst -${algo} -provider kae_provider msg.txt | awk '{print $2}')
    if [ "${size}" -ge "${log_threshold}" ]; then
        if ! grep -qE "sec digest final success|sec digest update success" /var/log/kae.log 2>/dev/null; then
            echo "Neither of the two messages found!"
            exit 1
        fi
    fi
    def_val=$(openssl dgst -${algo} -provider default msg.txt | awk '{print $2}')
    if [ "$kae_val" = "$def_val" ]; then
        echo "success"
    else
        echo "failed"
    fi


    rm -rf /var/log/kae.log msg.txt
    echo "(${label}) bin data"
    dd if=/dev/urandom of=msg.txt bs=${size} count=1 2>/dev/null
    kae_val=$(openssl dgst -${algo} -provider kae_provider msg.txt | awk '{print $2}')
    if [ "${size}" -ge "${log_threshold}" ]; then
        if ! grep -qE "sec digest final success|sec digest update success" /var/log/kae.log 2>/dev/null; then
            echo "Neither of the two messages found!"
            exit 1
        fi
    fi
    def_val=$(openssl dgst -${algo} -provider default msg.txt | awk '{print $2}')
    if [ "$kae_val" = "$def_val" ]; then
        echo "success"
    else
        echo "failed"
    fi
}

# 测试不同文件大小 (md5 / sm3)
for algo in md5 sm3; do
    echo "=====(${algo}) test======"
    run_digest_test $algo 256    "256B"
    run_digest_test $algo 1024   "1K"
    run_digest_test $algo 8192   "8K"
    run_digest_test $algo 16384  "16K"
    run_digest_test $algo 524288 "512K"
    run_digest_test $algo 525312 "513K"
    echo -e ""
done

rm -rf /var/log/kae.log
rm -rf msg.txt