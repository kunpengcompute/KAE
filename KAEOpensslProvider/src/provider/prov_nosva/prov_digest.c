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
    if (priv->soft_md == NULL) {
        const char *name = priv->e_nid == NID_sm3 ? "SM3" : "MD5";

        priv->soft_md = EVP_MD_fetch(kae_soft_libctx(), name, "provider=default");
        if (priv->soft_md == NULL)
            return OPENSSL_FAIL;
    }
    if (priv->soft_ctx == NULL)
        priv->soft_ctx = EVP_MD_CTX_new();
    return priv->soft_ctx != NULL;
}

static int sec_digests_soft_init(sec_digest_priv *priv)
{
    return sec_digests_soft_md(priv)
        && EVP_DigestInit_ex(priv->soft_ctx, priv->soft_md, NULL);
}

static void sec_digests_soft_cleanup(sec_digest_priv *priv)
{
    EVP_MD_CTX_free(priv->soft_ctx);
    EVP_MD_free(priv->soft_md);
    priv->soft_ctx = NULL;
    priv->soft_md = NULL;
}

static int sec_digests_soft_work(sec_digest_priv *priv, const unsigned char *data,
    size_t len, unsigned char *digest)
{
    unsigned int outlen;

    return sec_digests_soft_init(priv)
        && (len == 0 || EVP_DigestUpdate(priv->soft_ctx, data, len))
        && EVP_DigestFinal_ex(priv->soft_ctx, digest, &outlen);
}

static int kae_digest_init(void *dctx, const OSSL_PARAM params[])
{
    sec_digest_priv *priv = dctx;

    (void)params;
    if (priv == NULL || !sec_digests_init(priv))
        return OPENSSL_FAIL;
    priv->switch_flag = 0;
    priv->small_len = 0;
    return OPENSSL_SUCCESS;
}

static int kae_digest_hw_update(sec_digest_priv *priv, const unsigned char *in, size_t inl)
{
    int ret = sec_digests_update(priv, in, inl);

    if (ret != KAE_CRYPTO_FAIL)
        return ret;
    /* Queue acquisition failed before any input reached the device. */
    if (priv->switch_flag == 1 && priv->state == SEC_DIGEST_INIT) {
        if (sec_digests_soft_init(priv))
            return EVP_DigestUpdate(priv->soft_ctx, in, inl);
    }
    /* A partially submitted hardware stream cannot be replayed from its tail. */
    priv->state = SEC_DIGEST_FINAL;
    return OPENSSL_FAIL;
}

static int kae_digest_update(void *dctx, const unsigned char *in, size_t inl)
{
    sec_digest_priv *priv = dctx;
    size_t threshold;

    if (priv == NULL || (in == NULL && inl != 0) || priv->state == SEC_DIGEST_FINAL)
        return OPENSSL_FAIL;
    if (inl == 0)
        return OPENSSL_SUCCESS;
    if (priv->switch_flag == 1)
        return EVP_DigestUpdate(priv->soft_ctx, in, inl);

    threshold = sec_digests_sw_get_threshold(priv->e_nid);
    if (priv->e_digest_ctx == NULL && inl < threshold - priv->small_len) {
        size_t needed = priv->small_len + inl;

        if (needed > priv->small_capacity) {
            size_t capacity = needed > priv->small_capacity * 2 ? needed : priv->small_capacity * 2;
            unsigned char *buffer;

            if (capacity > threshold)
                capacity = threshold;
            buffer = OPENSSL_malloc(capacity);
            if (buffer == NULL)
                return OPENSSL_FAIL;
            if (priv->small_len != 0)
                memcpy(buffer, priv->small_buf, priv->small_len);
            OPENSSL_clear_free(priv->small_buf, priv->small_capacity);
            priv->small_buf = buffer;
            priv->small_capacity = capacity;
        }
        memcpy(priv->small_buf + priv->small_len, in, inl);
        priv->small_len += inl;
        return OPENSSL_SUCCESS;
    }

    if (priv->small_len != 0) {
        if (!kae_digest_hw_update(priv, priv->small_buf, priv->small_len))
            return OPENSSL_FAIL;
        priv->small_len = 0;
    }
    if (priv->switch_flag == 1)
        return EVP_DigestUpdate(priv->soft_ctx, in, inl);
    return kae_digest_hw_update(priv, in, inl);
}

static int kae_digest_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz)
{
    sec_digest_priv *priv = dctx;
    unsigned int len = 0;
    int ret;

    if (priv == NULL || out == NULL || outl == NULL || outsz < priv->md_size
        || priv->state == SEC_DIGEST_FINAL)
        return OPENSSL_FAIL;
    if (priv->switch_flag == 1) {
        ret = EVP_DigestFinal_ex(priv->soft_ctx, out, &len);
    } else if (priv->e_digest_ctx == NULL) {
        ret = sec_digests_soft_work(priv, priv->small_buf, priv->small_len, out);
    } else {
        ret = sec_digests_final(priv, out);
        if (ret == KAE_CRYPTO_FAIL) {
            ret = priv->state == SEC_DIGEST_INIT
                && sec_digests_soft_work(priv, priv->last_update_buff,
                    priv->last_update_bufflen, out);
        }
    }
    priv->state = SEC_DIGEST_FINAL;
    if (ret != OPENSSL_SUCCESS)
        return OPENSSL_FAIL;
    *outl = priv->md_size;
    return OPENSSL_SUCCESS;
}

static int kae_digest_oneshot(void *dctx, const unsigned char *in, size_t inl,
    unsigned char *out, size_t *outl, size_t outsz)
{
    return kae_digest_init(dctx, NULL)
        && kae_digest_update(dctx, in, inl)
        && kae_digest_final(dctx, out, outl, outsz);
}

static void *kae_digest_dupctx(void *dctx)
{
    const sec_digest_priv *src = dctx;
    sec_digest_priv *dst;

    if (src == NULL)
        return NULL;
    dst = OPENSSL_memdup(src, sizeof(*src));
    if (dst == NULL)
        return NULL;
    dst->soft_md = NULL;
    dst->soft_ctx = NULL;
    dst->e_digest_ctx = NULL;
    dst->last_update_buff = NULL;
    dst->small_buf = NULL;
    dst->small_capacity = src->small_len;
    if (src->small_len != 0) {
        dst->small_buf = OPENSSL_malloc(src->small_len);
        if (dst->small_buf == NULL)
            goto err;
        memcpy(dst->small_buf, src->small_buf, src->small_len);
    }
    if (src->switch_flag == 1) {
        if (!sec_digests_soft_md(dst) || !EVP_MD_CTX_copy_ex(dst->soft_ctx, src->soft_ctx))
            goto err;
    }
    if (!sec_digests_copy(dst, src))
        goto err;
    return dst;

err:
    kae_digest_freectx(dst);
    return NULL;
}

static void kae_digest_freectx(void *dctx)
{
    sec_digest_priv *priv = dctx;

    if (priv == NULL)
        return;
    sec_digests_soft_cleanup(priv);
    sec_digests_cleanup(priv);
    OPENSSL_clear_free(priv->small_buf, priv->small_capacity);
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
