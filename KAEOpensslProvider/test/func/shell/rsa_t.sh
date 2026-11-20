#!/bin/bash
set -e

export KAE_CONF_ENV=/var/log/
export OPENSSL_MODULES="${OPENSSL_MODULES:-/usr/local/lib/provider}"
echo -e "[LogSection]\ndebug_level=debug" > /var/log/kae.cnf

# 准备消息和hash
echo "The journey of a thousand miles begins with a single step." > msg.txt
openssl dgst -sha256 -binary msg.txt > hash.bin

# 生成RSA key（硬算）
echo -e "==== Testing Keygen ====\n"
rm -rf /var/log/kae.log
openssl genpkey -algorithm RSA -out rsa_priv.pem -pkeyopt rsa_keygen_bits:2048 -provider kae_provider 2>/dev/null
if ! grep -q "hpre rsa keygen success" /var/log/kae.log 2>/dev/null; then
    echo "RSA KeyGen NOT accelerated by HPRE!"
    exit 1
fi
openssl rsa -in rsa_priv.pem -pubout -out rsa_pub.pem
echo "RSA KAE gen key success!"

# 需要测试的模式（按适用场景分类）
SIGN_PADDINGS=("pkcs1" "pss" "x931" "no")
ENC_PADDINGS=("pkcs1" "oaep" "none")

############################
# 签名/验证测试
############################
for PADDING_MODE in "${SIGN_PADDINGS[@]}"; do
    echo -e "\n==== Testing Signature rsa_padding_mode:${PADDING_MODE} ====\n"

    # 1. 硬算签名 + 硬算验证
    rm -rf /var/log/kae.log sig.bin
    openssl pkeyutl -sign -inkey rsa_priv.pem -in hash.bin -out sig.bin -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa priv encrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Sign NOT accelerated by HPRE!"
        exit 1
    fi
    openssl pkeyutl -verify -pubin -inkey rsa_pub.pem -in hash.bin -sigfile sig.bin -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa public decrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Verify NOT accelerated by HPRE!"
        exit 1
    fi
    echo -e "rsa kae sign and kae verify done!\n"

    # 2. 硬算签名 + 软算验证
    rm -rf /var/log/kae.log sig.bin
    openssl pkeyutl -sign -inkey rsa_priv.pem -in hash.bin -out sig.bin -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa priv encrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Sign NOT accelerated by HPRE!"
        exit 1
    fi
    openssl pkeyutl -verify -pubin -inkey rsa_pub.pem -in hash.bin -sigfile sig.bin -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider default
    echo -e "rsa kae sign and soft verify done!\n"

    # 3. 软算签名 + 硬算验证
    rm -rf /var/log/kae.log sig.bin
    openssl pkeyutl -sign -inkey rsa_priv.pem -in hash.bin -out sig.bin -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider default
    openssl pkeyutl -verify -pubin -inkey rsa_pub.pem -in hash.bin -sigfile sig.bin -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa public decrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Verify NOT accelerated by HPRE!"
        exit 1
    fi
    echo -e "rsa soft sign and kae verify done!\n"
done

############################
# 加密/解密测试
############################
for PADDING_MODE in "${ENC_PADDINGS[@]}"; do
    echo -e "\n==== Testing Encryption rsa_padding_mode:${PADDING_MODE} ====\n"

    if [ "$PADDING_MODE" = "none" ]; then
        tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 256 > msg.txt
    fi

    # 4. 硬算加密 + 硬算解密
    rm -rf /var/log/kae.log msg.enc msg.dec
    openssl pkeyutl -encrypt -pubin -inkey rsa_pub.pem -in msg.txt -out msg.enc -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa public encrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Sign NOT accelerated by HPRE!"
        exit 1
    fi
    openssl pkeyutl -decrypt -inkey rsa_priv.pem -in msg.enc -out msg.dec -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa priv decrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Sign NOT accelerated by HPRE!"
        exit 1
    fi
    if diff msg.txt msg.dec >/dev/null; then
        echo -e "rsa kae public encrypt and kae private decrypt success!\n"
    else
        echo "Decrypted data mismatch!"
        exit 1
    fi

    # 5. 硬算加密 + 软算解密
    rm -rf /var/log/kae.log msg.enc msg.dec
    openssl pkeyutl -encrypt -pubin -inkey rsa_pub.pem -in msg.txt -out msg.enc -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa public encrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Sign NOT accelerated by HPRE!"
        exit 1
    fi
    openssl pkeyutl -decrypt -inkey rsa_priv.pem -in msg.enc -out msg.dec -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider default
    if diff msg.txt msg.dec >/dev/null; then
        echo -e "rsa kae public encrypt and soft private decrypt success!\n"
    else
        echo "Decrypted data mismatch!"
        exit 1
    fi

    # 6. 软算加密 + 硬算解密
    rm -rf /var/log/kae.log msg.enc msg.dec
    openssl pkeyutl -encrypt -pubin -inkey rsa_pub.pem -in msg.txt -out msg.enc -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider default
    openssl pkeyutl -decrypt -inkey rsa_priv.pem -in msg.enc -out msg.dec -pkeyopt rsa_padding_mode:${PADDING_MODE} -provider kae_provider -provider default
    if ! grep -q "hpre rsa priv decrypt success" /var/log/kae.log 2>/dev/null; then
        echo "RSA Sign NOT accelerated by HPRE!"
        exit 1
    fi
    if diff msg.txt msg.dec >/dev/null; then
        echo -e "rsa soft public encrypt and kae private decrypt success!\n"
    else
        echo "Decrypted data mismatch!"
        exit 1
    fi
done


rm -rf /var/log/kae.log
rm -rf hash.bin
rm -rf msg.dec
rm -rf msg.enc
rm -rf msg.txt
rm -rf rsa_priv.pem
rm -rf rsa_pub.pem
rm -rf sig.bin