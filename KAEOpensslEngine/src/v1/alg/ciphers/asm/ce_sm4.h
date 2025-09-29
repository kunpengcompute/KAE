/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef CE_SM4_H
#define CE_SM4_H

#include "sm4-armv8.h"

#define EVP_C_DATA(kstruct, ctx) \
        ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx));

typedef void (*block128_f) (const unsigned char in[16],
                            unsigned char out[16], const void *key);

typedef void (*cbc128_f) (const unsigned char *in, unsigned char *out,
                          size_t len, const void *key,
                          unsigned char ivec[16], int enc);

typedef void (*ecb128_f) (const unsigned char *in, unsigned char *out,
                          size_t len, const void *key,
                          int enc);

typedef void (*ctr128_f) (const unsigned char *in, unsigned char *out,
                          size_t blocks, const void *key,
                          const unsigned char ivec[16]);

typedef struct {
    union {
        double align;
        SM4_KEY ks;
    } ks;
    block128_f block;
    union {
        ecb128_f ecb;
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_SM4_KEY;

struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVP_CIPHER_CTX */ ;


int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);

int ossl_do_sm4_cipher_armv8(EVP_CIPHER_CTX *ctx, unsigned char *out,
                        const unsigned char *in, size_t len);

#endif