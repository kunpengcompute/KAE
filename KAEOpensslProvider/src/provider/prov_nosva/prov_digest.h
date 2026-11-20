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

#ifndef KAE_PROV_PKEY_H
#define KAE_PROV_PKEY_H

#include "../../adapter/nosva/algorithm/digest/sec_digests.h"

/* copied form openssl/include/internal/sm3.h
 * OpenSSL 3.0 has no <openssl/sm3.h>
 */
#define SM3_DIGEST_LENGTH 32
#define SM3_WORD unsigned int
#define SM3_CBLOCK 64
#define SM3_LBLOCK (SM3_CBLOCK / 4)
typedef struct SM3state_st {
    SM3_WORD A, B, C, D, E, F, G, H;
    SM3_WORD Nl, Nh;
    SM3_WORD data[SM3_LBLOCK];
    unsigned int num;
} SM3_CTX;

// static OSSL_FUNC_digest_init_fn kae_digest_init;
// static OSSL_FUNC_digest_update_fn kae_digest_update;
// static OSSL_FUNC_digest_final_fn kae_digest_final;
// static OSSL_FUNC_digest_digest_fn kae_digest_digest;
// static OSSL_FUNC_digest_freectx_fn kae_digest_freectx;
// static OSSL_FUNC_digest_dupctx_fn kae_digest_dupctx;
// static OSSL_FUNC_digest_get_params_fn kae_digest_get_params;
// static OSSL_FUNC_digest_set_ctx_params_fn kae_digest_set_ctx_params;
// static OSSL_FUNC_digest_get_ctx_params_fn kae_digest_get_ctx_params;
// static OSSL_FUNC_digest_gettable_params_fn kae_gettable_params;
// static OSSL_FUNC_digest_settable_ctx_params_fn kae_settable_ctx_params;
// static OSSL_FUNC_digest_gettable_ctx_params_fn kae_gettable_ctx_params;

static OSSL_FUNC_digest_init_fn kae_digest_init;
static OSSL_FUNC_digest_update_fn kae_digest_update;
static OSSL_FUNC_digest_final_fn kae_digest_final;
static int kae_digest_oneshot(void *dctx, const unsigned char *in, size_t inl,
    unsigned char *out, size_t *outl, size_t outsz);
static OSSL_FUNC_digest_freectx_fn kae_digest_freectx;
static OSSL_FUNC_digest_dupctx_fn kae_digest_dupctx;
static OSSL_FUNC_digest_gettable_params_fn kae_digest_gettable_params;

static int kae_digest_default_get_params(OSSL_PARAM params[], size_t blksz, size_t paramsz);

#define KAE_PROVIDER_IMPLEMENTATION(name, nid, mdsize, blksize)                                                     \
    static OSSL_FUNC_digest_newctx_fn kae_##name##_newctx;                                                          \
    static void *kae_##name##_newctx(void *provctx)                                                                 \
    {                                                                                                               \
        sec_digest_priv *ctx = OPENSSL_zalloc(sizeof(*ctx));                                                        \
        if (!ctx)                                                                                                   \
            return NULL;                                                                                            \
                                                                                                                    \
        ctx->e_nid = nid;                                                                                           \
        ctx->md_size = mdsize;                                                                                      \
        ctx->blk_size = blksize;                                                                                    \
        return ctx;                                                                                                 \
    }                                                                                                               \
    static int kae_##name##_digest(void *provctx, const unsigned char *in, size_t inl,                               \
        unsigned char *out, size_t *outl, size_t outsz)                                                            \
    {                                                                                                            \
        void *ctx = kae_##name##_newctx(provctx);                                                                  \
        int ret = ctx != NULL && kae_digest_oneshot(ctx, in, inl, out, outl, outsz);                                \
        kae_digest_freectx(ctx);                                                                                  \
        return ret;                                                                                              \
    }                                                                                                            \
    static OSSL_FUNC_digest_get_params_fn kae_##name##_get_params;                                                  \
    static int kae_##name##_get_params(OSSL_PARAM params[])                                                         \
    {                                                                                                               \
        return kae_digest_default_get_params(params, blksize, mdsize);                                              \
    }                                                                                                               \
    const OSSL_DISPATCH kae_##name##_functions[] = {{OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))kae_##name##_newctx}, \
        {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))kae_digest_freectx},                                             \
        {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))kae_digest_dupctx},                                               \
        {OSSL_FUNC_DIGEST_INIT, (void (*)(void))kae_digest_init},                                                   \
        {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))kae_digest_update},                                               \
        {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))kae_digest_final},                                                 \
        {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))kae_##name##_digest},                                              \
        {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))kae_##name##_get_params},                                     \
        {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))kae_digest_gettable_params},                             \
        {0, NULL}}

KAE_PROVIDER_IMPLEMENTATION(md5, NID_md5, MD5_DIGEST_LENGTH, MD5_CBLOCK);
KAE_PROVIDER_IMPLEMENTATION(sm3, NID_sm3, SM3_DIGEST_LENGTH, SM3_CBLOCK);

#endif
