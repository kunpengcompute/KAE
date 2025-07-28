/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/modes.h>
#include "ce_sm4.h"


int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    int mode = EVP_CIPHER_CTX_mode(ctx);
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY, ctx);

    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
        sm4_v8_set_decrypt_key(key, &dat->ks.ks);
        dat->block = (block128_f)sm4_v8_decrypt;
        dat->stream.cbc = NULL;

        if (mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f)sm4_v8_cbc_encrypt;
        if (mode == EVP_CIPH_ECB_MODE)
            dat->stream.ecb = (ecb128_f)sm4_v8_ecb_encrypt;
    } else {
        sm4_v8_set_encrypt_key(key, &dat->ks.ks);
        dat->block = (block128_f)sm4_v8_encrypt;
        dat->stream.cbc = NULL;

        if (mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f)sm4_v8_cbc_encrypt;
        else if (mode == EVP_CIPH_ECB_MODE)
            dat->stream.ecb = (ecb128_f)sm4_v8_ecb_encrypt;
        else if (mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f)sm4_v8_ctr32_encrypt_blocks;
    }

    return 1;
}

static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    size_t bl = EVP_CIPHER_CTX_block_size(ctx);
    size_t i;
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);

    if (len < bl){
        return 1;
    }
    if (dat->stream.ecb != NULL)
        (*dat->stream.ecb) (in, out, len, &dat->ks.ks,
                            EVP_CIPHER_CTX_encrypting(ctx));
    else
        for (i = 0, len -= bl; i <= len; i += bl)
            (*dat->block) (in + i, out + i, &dat->ks.ks);
    return 1;
}

static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);

    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, &dat->ks.ks, ctx->iv,
                            EVP_CIPHER_CTX_encrypting(ctx));
    else if (EVP_CIPHER_CTX_encrypting(ctx))
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks.ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks.ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);
    return 1;
}

static int sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);
    int num = EVP_CIPHER_CTX_num(ctx);

    CRYPTO_ofb128_encrypt(in, out, len, &dat->ks.ks,
                          ctx->iv, &num, dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int sm4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);
    int num = EVP_CIPHER_CTX_num(ctx);

    CRYPTO_cfb128_encrypt(in, out, len, &dat->ks.ks,
                          ctx->iv, &num,
                          EVP_CIPHER_CTX_encrypting(ctx), dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);

    return 1;
}

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int n = EVP_CIPHER_CTX_num(ctx);
    unsigned int num;
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);

    if (n < 0)
        return 0;
    num = (unsigned int)n;

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks,
                                    ctx->iv,
                                    EVP_CIPHER_CTX_buf_noconst(ctx),
                                    &num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, &dat->ks.ks,
                                ctx->iv,
                                EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                                dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

int ossl_do_sm4_cipher_armv8(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len)
{
    int nid = EVP_CIPHER_CTX_nid(ctx);

    switch (nid) {
        case NID_sm4_ecb:
            sm4_ecb_cipher(ctx, out, in, len);
            break;
        case NID_sm4_cbc:
            sm4_cbc_cipher(ctx, out, in, len);
            break;
        case NID_sm4_ofb128:
            sm4_ofb_cipher(ctx, out, in, len);
            break;
        case NID_sm4_cfb128:
            sm4_cfb_cipher(ctx, out, in, len);
            break;
        case NID_sm4_ctr:
            sm4_ctr_cipher(ctx, out, in, len);
            break;
        default:
            break;
    }

    return 1;
}