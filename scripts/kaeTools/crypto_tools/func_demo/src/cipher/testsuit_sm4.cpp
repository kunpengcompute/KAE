/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: 
 * @Author: nwq
 * @Date: 2025-01-16
 * @LastEditTime: 2025-01-16
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <gtest/gtest.h>

#include "demo_utils.h"
#include "demo_cipher.h"

/* ARIA key */
const unsigned char cipher_256_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

/* Unique initialisation vector */
const unsigned char cipher_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
    0x99, 0xaa, 0x3e, 0x68,
};

class SM4TestSuit:public testing::Test
{
protected:
    virtual void SetUp()
    {
        // init_openssl();
    }
    virtual void TearDown()
    {
 
    }

};

// SM4_CBC数据硬算加解密
TEST_F(SM4TestSuit, cbc_mode)
{

    int keylen = 32;
    int ivlen = 16;
    int ptlen = 16*1024;
    char *data = (char *)malloc(ptlen + 1);
    generateRandomASCII(data, ptlen);
    const char *plaintext = data;

    // 测试数据
    int ciphertext_len;
    int decryptedtext_len;
    int padded_len = ((ptlen / 16) + 1) * 16;
    unsigned char ciphertext[padded_len];
    unsigned char decryptedtext[ptlen + 1];

    // 配置SM4-CBC参数
    CipherParams sm4_params_cbc = {
        .cipher = EVP_sm4_cbc(),
        .key = cipher_256_key, // 应该是随机生成的安全密钥
        .iv = cipher_iv, // 应该是随机生成的IV
        .key_len = keylen,
        .iv_len = ivlen,
        .op = ENCRYPT
    };

    // 加载 KAE 引擎
    ENGINE* engine = ENGINE_by_id("kae");
    ENGINE_init(engine);
    ASSERT_FALSE(engine == NULL);

    // 加密
    if (!cipher_encrypt_decrypt((const unsigned char *)plaintext, ptlen, ciphertext, &ciphertext_len, &sm4_params_cbc, engine)) {
        fprintf(stderr, "Encryption failed.\n");
    }
    // 修改为解密模式并尝试解密
    sm4_params_cbc.op = DECRYPT;
    if (!cipher_encrypt_decrypt(ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len, &sm4_params_cbc, engine)) {
        fprintf(stderr, "Decryption failed.\n");
    }

    EXPECT_EQ(memcmp(plaintext, decryptedtext, ptlen) , 0);

    free(data);
    ENGINE_free(engine);
}


// SM4_CTR数据硬算加解密
TEST_F(SM4TestSuit, ctr_mode)
{

    int keylen = 32;
    int ivlen = 16;
    int ptlen = 16*1024;
    char *data = (char *)malloc(ptlen + 1);
    generateRandomASCII(data, ptlen);
    const char *plaintext = data;

    // 测试数据
    int ciphertext_len;
    int decryptedtext_len;
    int padded_len = ((ptlen / 16) + 1) * 16;
    unsigned char ciphertext[padded_len];
    unsigned char decryptedtext[ptlen + 1];

    // 配置SM4-CTR参数
    CipherParams sm4_params_ctr = {
        .cipher = EVP_sm4_ctr(),
        .key = cipher_256_key, // 应该是随机生成的安全密钥
        .iv = cipher_iv, // 应该是随机生成的IV
        .key_len = keylen,
        .iv_len = ivlen,
        .op = ENCRYPT
    };

    // 加载 KAE 引擎
    ENGINE* engine = ENGINE_by_id("kae");
    ENGINE_init(engine);
    ASSERT_FALSE(engine == NULL);

    // 软算加密
    if (!cipher_encrypt((const unsigned char *)plaintext, ptlen, ciphertext, &ciphertext_len, &sm4_params_ctr, NULL)) {
        fprintf(stderr, "Encryption failed.\n");
    }
    // 硬算解密
    if (!cipher_decrypt(ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len, &sm4_params_ctr, engine)) {
        fprintf(stderr, "Decryption failed.\n");
    }

    EXPECT_EQ(memcmp(plaintext, decryptedtext, ptlen) , 0);

    free(data);
    ENGINE_free(engine);
}


// SM4_OFB数据硬算加解密
TEST_F(SM4TestSuit, ofb_mode)
{

    int keylen = 32;
    int ivlen = 16;
    int ptlen = 16*1024;
    char *data = (char *)malloc(ptlen + 1);
    generateRandomASCII(data, ptlen);
    const char *plaintext = data;

    // 测试数据
    int ciphertext_len;
    int decryptedtext_len;
    int padded_len = ((ptlen / 16) + 1) * 16;
    unsigned char ciphertext[padded_len];
    unsigned char decryptedtext[ptlen + 1];

    // 配置SM4-OFB参数
    CipherParams sm4_params_ofb = {
        .cipher = EVP_sm4_ofb(),
        .key = cipher_256_key, // 应该是随机生成的安全密钥
        .iv = cipher_iv, // 应该是随机生成的IV
        .key_len = keylen,
        .iv_len = ivlen,
        .op = ENCRYPT
    };

    // 加载 KAE 引擎
    ENGINE* engine = ENGINE_by_id("kae");
    ENGINE_init(engine);
    ASSERT_FALSE(engine == NULL);

    // 硬算加密
    if (!cipher_encrypt((const unsigned char *)plaintext, ptlen, ciphertext, &ciphertext_len, &sm4_params_ofb, engine)) {
        fprintf(stderr, "Encryption failed.\n");
    }
    // 软算解密
    if (!cipher_decrypt(ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len, &sm4_params_ofb, NULL)) {
        fprintf(stderr, "Decryption failed.\n");
    }

    EXPECT_EQ(memcmp(plaintext, decryptedtext, ptlen) , 0);

    free(data);
    ENGINE_free(engine);
}