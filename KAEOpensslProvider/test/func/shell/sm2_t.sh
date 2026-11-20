#!/bin/bash

# 定义变量
SM2_PRIVATE_PEM="private.key"
PUBLIC_KEY="public.key"
DATA_FILE="data.txt"
SIGNATURE_FILE="signature.bin"
PROVIDER="kae_provider"

# 要签名的数据
DATA="待签名的数据内容"

echo "=================================="
echo "KAE Provider SM2 签名与验证测试脚本"
echo "=================================="


echo -e "\n生成 SM2 私钥..."
openssl ecparam -name SM2 -genkey -out "$SM2_PRIVATE_PEM" -provider "$PROVIDER"
if [ $? -ne 0 ]; then
    echo "错误：生成私钥失败"
    exit 1
fi
echo "导出 SM2 公钥..."
openssl ec -in "$SM2_PRIVATE_PEM" -pubout -out "$PUBLIC_KEY"
if [ $? -ne 0 ]; then
    echo "错误：生成公钥失败"
    exit 1
fi
# 创建数据文件
echo "$DATA" > "$DATA_FILE"
if [ $? -ne 0 ]; then
    echo "错误：创建数据文件失败"
    exit 1
fi

echo -e "\n硬算签名、硬算验证"
echo "[1/2] 使用私钥进行 SM3 签名..."
openssl dgst -sm3 -sign "$SM2_PRIVATE_PEM" -out "$SIGNATURE_FILE" -provider "$PROVIDER" "$DATA_FILE"
if [ $? -ne 0 ]; then
    echo "错误：签名失败"
    exit 1
fi
echo "[2/2] 验证签名..."
openssl dgst -sm3 -verify "$PUBLIC_KEY" -signature "$SIGNATURE_FILE" -provider "$PROVIDER" "$DATA_FILE"


echo -e "\n软算签名、硬算验证"
echo "[1/2] 使用私钥进行 SM3 签名..."
openssl dgst -sm3 -sign "$SM2_PRIVATE_PEM" -out "$SIGNATURE_FILE" "$DATA_FILE"
if [ $? -ne 0 ]; then
    echo "错误：签名失败"
    exit 1
fi
echo "[2/2] 验证签名..."
openssl dgst -sm3 -verify "$PUBLIC_KEY" -signature "$SIGNATURE_FILE" -provider "$PROVIDER" "$DATA_FILE"


# 会失败。。
echo -e "\n硬算签名、软算验证"
echo "[1/2] 使用私钥进行 SM3 签名..."
openssl dgst -sm3 -sign "$SM2_PRIVATE_PEM" -out "$SIGNATURE_FILE" -provider "$PROVIDER" "$DATA_FILE"
if [ $? -ne 0 ]; then
    echo "错误：签名失败"
    exit 1
fi
echo "[2/2] 验证签名..."
openssl dgst -sm3 -verify "$PUBLIC_KEY" -signature "$SIGNATURE_FILE" "$DATA_FILE"