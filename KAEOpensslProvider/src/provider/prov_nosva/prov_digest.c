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

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "prov.h"
#include "prov_digest.h"
#include "../../adapter/common/kae_log.h"

static int sec_digests_soft_md(sec_digest_priv *priv)
{
    int app_datasize = 0;

    if (priv->soft_md)
        return 1;

    switch (priv->e_nid) {
        case NID_sm3:
            // priv->soft_md = EVP_sm3();
            priv->soft_md = EVP_MD_fetch(NULL, "SM3", "provider=default");
            break;
        case NID_md5:
            // priv->soft_md = EVP_md5();
            priv->soft_md = EVP_MD_fetch(NULL, "MD5", "provider=default");
            break;
        default:
            US_ERR("invalid: kae unsupport digest nid.");
            break;
    }

    if (unlikely(priv->soft_md == NULL))
        return OPENSSL_FAIL;

    app_datasize = EVP_MD_meth_get_app_datasize(priv->soft_md);
    if (app_datasize == 0) {
        /* OpenSSL 3.0 has no app_datasize, need set manually
         * check crypto/evp/legacy_md5.c: md5_md as example
         */
        switch (priv->e_nid) {
            case NID_sm3:
                app_datasize = sizeof(EVP_MD *) + sizeof(SM3_CTX);
                break;
            case NID_md5:
                app_datasize = sizeof(EVP_MD *) + sizeof(MD5_CTX);
                break;
            default:
                break;
        }
    }

    if (priv->soft_ctx == NULL) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        if (ctx == NULL) {
            US_WARN("failed to alloc md ctx.");
            return OPENSSL_FAIL;
        }

        ctx->md_data = OPENSSL_malloc(app_datasize);
        if (ctx->md_data == NULL) {
            US_ERR("failed to alloc md data.");
            return OPENSSL_FAIL;
        }

        priv->soft_ctx = ctx;
        priv->app_datasize = app_datasize;
    }
    return OPENSSL_SUCCESS;
}

int sec_digests_soft_init(sec_digest_priv *priv)
{
    if (sec_digests_soft_md(priv) == 0) {
        US_ERR("failed to init soft digest.");
        return OPENSSL_FAIL;
    }

    return EVP_DigestInit_ex(priv->soft_ctx, priv->soft_md, NULL);
}

int sec_digests_soft_update(sec_digest_priv *priv, const void *data, size_t len)
{
    return EVP_DigestUpdate(priv->soft_ctx, data, len);
}

int sec_digests_soft_final(sec_digest_priv *priv, unsigned char *digest)
{
    unsigned int digest_length;

    return EVP_DigestFinal_ex(priv->soft_ctx, digest, &digest_length);
}

void sec_digests_soft_cleanup(sec_digest_priv *priv)
{
    EVP_MD_CTX *ctx = priv->soft_ctx;
    // if (priv->copy)
    // 	return;
    if (ctx != NULL) {
        if (ctx->md_data) {
            OPENSSL_free(ctx->md_data);
            ctx->md_data = NULL;
        }
        EVP_MD_CTX_free(ctx);
        priv->soft_ctx = NULL;
        priv->app_datasize = 0;
    }

    if (priv->soft_md) {
        EVP_MD_free(priv->soft_md);
        priv->soft_md = NULL;
    }
}

int sec_digests_soft_work(sec_digest_priv *md_ctx, int len, unsigned char *digest)
{
    int ret;
    ret = sec_digests_soft_init(md_ctx);
    if (len != 0)
        ret |= sec_digests_soft_update(md_ctx, md_ctx->last_update_buff, len);
    ret |= sec_digests_soft_final(md_ctx, digest);
    sec_digests_soft_cleanup(md_ctx);
    return ret;
}

int sec_digests_soft_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    sec_digest_priv *to_ctx = (sec_digest_priv *)EVP_MD_CTX_md_data(to);
    sec_digest_priv *from_ctx = (sec_digest_priv *)EVP_MD_CTX_md_data(from);
    int ret;

    if (!to_ctx)
        return 1;

    if (!from_ctx) {
        US_ERR("priv get from digest ctx is NULL.");
        return 0;
    }
    // 需要重新给目的上下文分配ctx
    if (to_ctx->soft_ctx) {
        to_ctx->soft_ctx = NULL;
        ret = sec_digests_soft_init(to_ctx);
        if (ret != OPENSSL_SUCCESS) {
            US_ERR("soft digest init failed.");
            return OPENSSL_FAIL;
        }

        memcpy(to_ctx->soft_ctx->md_data, from_ctx->soft_ctx->md_data, to_ctx->app_datasize);
    }

    return OPENSSL_SUCCESS;
}

static int kae_digest_init(void *dctx, const OSSL_PARAM params[])
{
    sec_digest_priv *priv = (sec_digest_priv *)dctx;

    if (!priv) {
        US_ERR("invalid: digest ctx is NULL.");
        return KAE_P_FAIL;
    }

    if (!sec_digests_soft_md(priv)) {
        US_ERR("soft digest md init failed.");
        return KAE_P_FAIL;
    }

    if (!sec_digests_init(priv)) {
        US_ERR("soft digest init failed.");
        return KAE_P_FAIL;
    }
    priv->switch_flag = 0;

    return OPENSSL_SUCCESS;
}

static int kae_digest_update(void *dctx, const unsigned char *in, size_t inl)
{
    sec_digest_priv *priv = (sec_digest_priv *)dctx;
    int ret;
    if (!dctx || !in) {
        US_ERR("invalid: digest ctx or input data is NULL.");
        return KAE_P_FAIL;
    }

    ret = sec_digests_update(priv, in, inl);
    if (ret == KAE_CRYPTO_FAIL) {
        goto soft;
    }

    return ret;

soft:
    US_WARN("sec digest update failed, switch to soft.");
    if (sec_digests_soft_init(priv) != OPENSSL_SUCCESS) {
        US_ERR("do sec digest soft init failed");
        return OPENSSL_FAIL;
    }

    return sec_digests_soft_update(priv, in, inl);
}

static int kae_digest_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz)
{
    sec_digest_priv *priv = (sec_digest_priv *)dctx;
    int ret;

    if (!dctx || !out) {
        US_ERR("invalid: digest ctx or out is NULL.");
        return KAE_P_FAIL;
    }

    if (outsz > 0) {
        ret = sec_digests_final(priv, out);

        if (ret == KAE_CRYPTO_FAIL) {
            if (priv->switch_flag == 1)
                goto soft_final;
            goto soft;
        }
        if (!ret)
            return ret;
    }

    if (outl)
        *outl = priv->md_size;

    return KAE_P_SUCCESS;

soft_final:
    US_WARN("sec digest final failed, switch to soft.");
    ret = sec_digests_soft_final(priv, out);
    sec_digests_soft_cleanup(priv);

    if (!ret) {
        return ret;
    }
    if (outl)
        *outl = priv->md_size;

    return ret;

soft:
    US_WARN("sec digest final failed, switch to soft.");
    if (priv->state == SEC_DIGEST_INIT) {
        ret = sec_digests_soft_work(priv, priv->last_update_bufflen, out);
        if (!ret)
            return ret;
    } else {
        US_ERR("do sec digest failed");
        ret = OPENSSL_FAIL;
    }

    if (outl)
        *outl = priv->md_size;
    return ret;
}

static int kae_digest_digest(
    void *dctx, const unsigned char *in, size_t inl, unsigned char *out, size_t *outl, size_t outsz)
{
    sec_digest_priv *priv = (sec_digest_priv *)dctx;
    int ret;

    if (!dctx || !in || !out) {
        US_ERR("invalid: digest ctx or in or out is NULL.");
        return KAE_P_FAIL;
    }

    if (outsz > 0) {
        ret = kae_digest_init(priv, NULL);
        if (!ret) {
            US_ERR("kae digest init failed.");
            return ret;
        }

        ret = kae_digest_update(priv, in, inl);
        if (!ret) {
            US_ERR("kae digest update failed.");
            return ret;
        }

        ret = kae_digest_final(priv, out, outl, outsz);
        if (!ret) {
            US_WARN("kae digest final failed.");
            return ret;
        }
    }

    return KAE_P_SUCCESS;
}

static void *kae_digest_dupctx(void *dctx)
{
    sec_digest_priv *priv = (sec_digest_priv *)dctx;
    sec_digest_priv *dst_ctx;
    int ret;

    dst_ctx = OPENSSL_zalloc(sizeof(*dst_ctx));
    dst_ctx->e_nid = priv->e_nid;
    dst_ctx->md_size = priv->md_size;
    dst_ctx->switch_flag = priv->switch_flag;

    if (!sec_digests_soft_md(dst_ctx)) {
        US_ERR("sec soft digest md init failed.");
        return KAE_P_FAIL;
    }

    ret = sec_digests_copy(dst_ctx, priv);
    if (!ret) {
        US_ERR("sec digest copy failed.");
        return NULL;
    }
    return dst_ctx;
}

static void kae_digest_freectx(void *dctx)
{
    sec_digest_priv *priv = (sec_digest_priv *)dctx;

    if (!dctx) {
        US_WARN("invalid: digest ctx is NULL.");
        return;
    }

    if (priv->soft_ctx) {
        sec_digests_soft_cleanup(priv);
    }

    sec_digests_cleanup(priv);
    OPENSSL_clear_free(priv, sizeof(*priv));
}

/* some params related code is copied from OpenSSL v3.0 prov/digestcommon.h */
static const OSSL_PARAM kae_digest_default_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *kae_digest_gettable_params(void *provctx)
{
    return kae_digest_default_known_gettable_params;
}

static int kae_digest_default_get_params(OSSL_PARAM params[], size_t blksz, size_t paramsz)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p != NULL && !OSSL_PARAM_set_int(p, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p != NULL && !OSSL_PARAM_set_int(p, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}
