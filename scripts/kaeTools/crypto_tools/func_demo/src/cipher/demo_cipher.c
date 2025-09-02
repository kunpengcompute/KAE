/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: 
 * @Author: nwq
 * @Date: 2025-01-16
 * @LastEditTime: 2025-01-16
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/engine.h>

#include "demo_cipher.h"

// 通用的cipher加解密函数
bool cipher_encrypt_decrypt(const unsigned char *input, int input_len, unsigned char *output, int *output_len, const CipherParams *params, ENGINE* engine)
{
    EVP_CIPHER_CTX *ctx = NULL;
    bool ret = false;

    if (!(ctx = EVP_CIPHER_CTX_new())) goto end;

    // 初始化上下文
    if (1 != EVP_CipherInit_ex(ctx, params->cipher, engine, params->key, params->iv, params->op == ENCRYPT)) goto end;

    // 更新数据
    int len;
    if (1 != EVP_CipherUpdate(ctx, output, &len, input, input_len)) goto end;
    *output_len = len;

    // 最终化操作
    if (1 != EVP_CipherFinal_ex(ctx, output + len, &len)) goto end;
    *output_len += len;

    ret = true;

end:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}


bool cipher_encrypt(const unsigned char *input, int input_len, unsigned char *output, int *output_len, const CipherParams *params, ENGINE* engine)
{
    EVP_CIPHER_CTX *ctx = NULL;
    bool ret = false;

    if (!(ctx = EVP_CIPHER_CTX_new())) goto end;


    // 初始化上下文
    if (1 != EVP_EncryptInit_ex(ctx, params->cipher, engine, params->key, params->iv)) goto end;

    // 更新数据
    int len;
    if (1 != EVP_EncryptUpdate(ctx, output, &len, input, input_len)) goto end;
    *output_len = len;

    // 最终化操作
    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) goto end;
    *output_len += len;

    ret = true;

end:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

bool cipher_decrypt(const unsigned char *input, int input_len, unsigned char *output, int *output_len, const CipherParams *params, ENGINE* engine)
{
    EVP_CIPHER_CTX *ctx = NULL;
    bool ret = false;

    if (!(ctx = EVP_CIPHER_CTX_new())) goto end;


    // 初始化上下文
    if (1 != EVP_DecryptInit_ex(ctx, params->cipher, engine, params->key, params->iv)) goto end;

    // 更新数据
    int len;
    if (1 != EVP_DecryptUpdate(ctx, output, &len, input, input_len)) goto end;
    *output_len = len;

    // 最终化操作
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) goto end;
    *output_len += len;

    ret = true;

end:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}