/*
 * Copyright 2025 Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KAE_PROV_CIPHER_H
#define KAE_PROV_CIPHER_H

#include <openssl/evp.h>
#include "../../adapter/nosva/algorithm/cipher/sec_ciphers.h"

#define PROV_CIPHER_FLAG_CUSTOM_IV 0x0002

static OSSL_FUNC_cipher_encrypt_init_fn kae_cipher_einit;
static OSSL_FUNC_cipher_decrypt_init_fn kae_cipher_dinit;
static OSSL_FUNC_cipher_update_fn kae_cipher_block_update;
static OSSL_FUNC_cipher_update_fn kae_cipher_stream_update;
static OSSL_FUNC_cipher_final_fn kae_cipher_block_final;
static OSSL_FUNC_cipher_final_fn kae_cipher_stream_final;
static OSSL_FUNC_cipher_cipher_fn kae_cipher_cipher;
static OSSL_FUNC_cipher_freectx_fn kae_cipher_freectx;
static OSSL_FUNC_cipher_gettable_params_fn kae_cipher_gettable_params;
static OSSL_FUNC_cipher_get_ctx_params_fn kae_cipher_get_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn kae_cipher_gettable_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn kae_cipher_set_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn kae_cipher_settable_ctx_params;
static OSSL_FUNC_cipher_cipher_fn kae_cipher_cipher;

int prov_cipher_generic_get_params(
    OSSL_PARAM params[], unsigned int md, uint64_t flags, size_t kbits, size_t blkbits, size_t ivbits);

#define KAE_CIPHER_DESCR(nm, blksize, keylen, ivlen, flags, e_nid, algnm, mode, typ)                            \
    static OSSL_FUNC_cipher_newctx_fn kae_##nm##_newctx;                                                        \
    static void *kae_##nm##_newctx(void *provctx)                                                               \
    {                                                                                                           \
        cipher_priv_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));                                                    \
        if (ctx == NULL)                                                                                        \
            return NULL;                                                                                        \
                                                                                                                \
        ctx->blk_size = blksize;                                                                                \
        ctx->key_len = keylen;                                                                                  \
        ctx->iv_len = ivlen;                                                                                    \
        ctx->nid = e_nid;                                                                                       \
        strncpy(ctx->alg_name, #algnm, ALG_NAME_SIZE - 1);                                                      \
        if (strcmp(#typ, "block") == 0)                                                                         \
            ctx->pad = 1;                                                                                       \
        return ctx;                                                                                             \
    }                                                                                                           \
    static OSSL_FUNC_cipher_get_params_fn kae_##nm##_get_params;                                                \
    static int kae_##nm##_get_params(OSSL_PARAM params[])                                                       \
    {                                                                                                           \
        return prov_cipher_generic_get_params(params, mode, flags, keylen, blksize, ivlen);                     \
    }                                                                                                           \
    const OSSL_DISPATCH kae_##nm##_functions[] = {{OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))kae_##nm##_newctx}, \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))kae_cipher_freectx},                                         \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))kae_cipher_einit},                                      \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))kae_cipher_dinit},                                      \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))kae_cipher_##typ##_update},                                   \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))kae_cipher_##typ##_final},                                     \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))kae_cipher_cipher},                                           \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))kae_##nm##_get_params},                                   \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))kae_cipher_gettable_params},                         \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))kae_cipher_get_ctx_params},                           \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))kae_cipher_gettable_ctx_params},                 \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))kae_cipher_set_ctx_params},                           \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))kae_cipher_settable_ctx_params},                 \
        {0, NULL}}

KAE_CIPHER_DESCR(aes_128_cbc, 16, 16, 16, 0, NID_aes_128_cbc, cbc(aes), EVP_CIPH_CBC_MODE, block);
KAE_CIPHER_DESCR(aes_192_cbc, 16, 24, 16, 0, NID_aes_192_cbc, cbc(aes), EVP_CIPH_CBC_MODE, block);
KAE_CIPHER_DESCR(aes_256_cbc, 16, 32, 16, 0, NID_aes_256_cbc, cbc(aes), EVP_CIPH_CBC_MODE, block);
KAE_CIPHER_DESCR(aes_128_ecb, 16, 16, 0, 0, NID_aes_128_ecb, ecb(aes), EVP_CIPH_ECB_MODE, block);
KAE_CIPHER_DESCR(aes_192_ecb, 16, 24, 0, 0, NID_aes_192_ecb, ecb(aes), EVP_CIPH_ECB_MODE, block);
KAE_CIPHER_DESCR(aes_256_ecb, 16, 32, 0, 0, NID_aes_256_ecb, ecb(aes), EVP_CIPH_ECB_MODE, block);
KAE_CIPHER_DESCR(
    aes_128_xts, 1, 32, 16, PROV_CIPHER_FLAG_CUSTOM_IV, NID_aes_128_xts, xts(aes), EVP_CIPH_XTS_MODE, stream);
KAE_CIPHER_DESCR(
    aes_256_xts, 1, 64, 16, PROV_CIPHER_FLAG_CUSTOM_IV, NID_aes_256_xts, xts(aes), EVP_CIPH_XTS_MODE, stream);
KAE_CIPHER_DESCR(sm4_cbc, 16, 16, 16, 0, NID_sm4_cbc, cbc(sm4), EVP_CIPH_CBC_MODE, block);
KAE_CIPHER_DESCR(sm4_ecb, 16, 16, 0, 0, NID_sm4_ecb, ecb(sm4), EVP_CIPH_ECB_MODE, block);

/* v3 */
KAE_CIPHER_DESCR(aes_128_ctr, 1, 16, 16, 0, NID_aes_128_ctr, ctr(aes), EVP_CIPH_CTR_MODE, stream);
KAE_CIPHER_DESCR(aes_192_ctr, 1, 24, 16, 0, NID_aes_192_ctr, ctr(aes), EVP_CIPH_CTR_MODE, stream);
KAE_CIPHER_DESCR(aes_256_ctr, 1, 32, 16, 0, NID_aes_256_ctr, ctr(aes), EVP_CIPH_CTR_MODE, stream);
KAE_CIPHER_DESCR(aes_128_ofb128, 1, 16, 16, 0, NID_aes_128_ofb128, ofb(aes), EVP_CIPH_OFB_MODE, stream);
KAE_CIPHER_DESCR(aes_192_ofb128, 1, 24, 16, 0, NID_aes_192_ofb128, ofb(aes), EVP_CIPH_OFB_MODE, stream);
KAE_CIPHER_DESCR(aes_256_ofb128, 1, 32, 16, 0, NID_aes_256_ofb128, ofb(aes), EVP_CIPH_OFB_MODE, stream);
KAE_CIPHER_DESCR(aes_128_cfb128, 1, 16, 16, 0, NID_aes_128_cfb128, cfb(aes), EVP_CIPH_CFB_MODE, stream);
KAE_CIPHER_DESCR(aes_192_cfb128, 1, 24, 16, 0, NID_aes_192_cfb128, cfb(aes), EVP_CIPH_CFB_MODE, stream);
KAE_CIPHER_DESCR(aes_256_cfb128, 1, 32, 16, 0, NID_aes_256_cfb128, cfb(aes), EVP_CIPH_CFB_MODE, stream);
KAE_CIPHER_DESCR(sm4_ofb128, 1, 16, 16, 0, NID_sm4_ofb128, ofb(sm4), EVP_CIPH_OFB_MODE, stream);
KAE_CIPHER_DESCR(sm4_cfb128, 1, 16, 16, 0, NID_sm4_cfb128, cfb(sm4), EVP_CIPH_CFB_MODE, stream);
KAE_CIPHER_DESCR(sm4_ctr, 1, 16, 16, 0, NID_sm4_ctr, ctr(sm4), EVP_CIPH_CTR_MODE, stream);

#endif