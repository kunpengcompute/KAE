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

#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>
#include <openssl/types.h>

#include "prov.h"
#include "prov_pkey.h"
#include "internal/prov_packet.h"
#include "internal/prov_der_writer.h"
#include "../../adapter/common/kae_log.h"
#include "../../adapter/common/kae_types.h"
#include "../../adapter/nosva/algorithm/pkey/hpre_sm2.h"

#define SM2_KEY_BYTES 		32
#define SM2_GET_SIGNLEN 	1
#define SM3_DIGEST_LENGTH 	32

KAE_PKEY_KEYMGMT_DESCR(sm2, SM2);
KAE_PKEY_SIGNATURE_DESCR(sm2, SM2);
KAE_PKEY_ASYM_CIPHER_DESCR(sm2, SM2);

static const OSSL_PARAM sm2_asym_cipher_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_ENGINE, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM sm2_asym_cipher_known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0), OSSL_PARAM_END};

static const OSSL_PARAM sm2_sig_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM sm2_sig_known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END};

enum { CTX_INIT_FAIL = -1, CTX_UNINIT, CTX_INIT_SUCC };

static void *kae_keymgmt_sm2_new(void *provctx)
{
    if (!get_default_sm2_keymgmt().new_fun) {
        US_WARN("failed to get sm2 keymgmt new function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().new_fun(provctx);
}

static void kae_keymgmt_sm2_free(void *keydata)
{
    if (!get_default_sm2_keymgmt().free) {
        US_WARN("failed to get sm2 keymgmt free function.");
        return;
    }

    get_default_sm2_keymgmt().free(keydata);
}

static int kae_keymgmt_sm2_get_params(void *key, OSSL_PARAM params[])
{
    if (!get_default_sm2_keymgmt().get_params) {
        US_WARN("failed to get sm2 keymgmt get_params function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().get_params(key, params);
}

static const OSSL_PARAM *kae_keymgmt_sm2_gettable_params(void *provctx)
{
    if (!get_default_sm2_keymgmt().gettable_params) {
        US_WARN("failed to get sm2 keymgmt gettable_params function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().gettable_params(provctx);
}

static int kae_keymgmt_sm2_set_params(void *key, const OSSL_PARAM params[])
{
    if (!get_default_sm2_keymgmt().set_params) {
        US_WARN("failed to get sm2 keymgmt set_params function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().set_params(key, params);
}

static const OSSL_PARAM *kae_keymgmt_sm2_settable_params(ossl_unused void *provctx)
{
    if (!get_default_sm2_keymgmt().settable_params) {
        US_WARN("failed to get sm2 keymgmt settable_params function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().settable_params(provctx);
}

static void *kae_keymgmt_sm2_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    if (!get_default_sm2_keymgmt().gen_init) {
        US_WARN("failed to get sm2 keymgmt gen_init function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().gen_init(provctx, selection, params);
}

static int kae_keymgmt_sm2_gen_set_template(void *genctx, void *templates)
{
    if (!get_default_sm2_keymgmt().gen_set_template) {
        US_WARN("failed to get sm2 keymgmt gen_set_template function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().gen_set_template(genctx, templates);
}

static int kae_keymgmt_sm2_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    if (!get_default_sm2_keymgmt().gen_set_params) {
        US_WARN("failed to get sm2 keymgmt gen_set_params function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().gen_set_params(genctx, params);
}

static const OSSL_PARAM *kae_keymgmt_sm2_gen_settable_params(ossl_unused void *genctx, ossl_unused void *provctx)
{
    if (!get_default_sm2_keymgmt().gen_settable_params) {
        US_WARN("failed to get sm2 keymgmt gen_settable_params function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().gen_settable_params(genctx, provctx);
}

static void *kae_keymgmt_sm2_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    // todo; use hardware?
    if (!get_default_sm2_keymgmt().gen) {
        US_WARN("failed to get sm2 keymgmt gen function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().gen(genctx, osslcb, cbarg);
}

static void kae_keymgmt_sm2_gen_cleanup(void *genctx)
{
    if (!get_default_sm2_keymgmt().gen_cleanup) {
        US_WARN("failed to get sm2 keymgmt gen_cleanup function.");
        return;
    }

    get_default_sm2_keymgmt().gen_cleanup(genctx);
}

static void *kae_keymgmt_sm2_load(const void *reference, size_t reference_sz)
{
    if (!get_default_sm2_keymgmt().load) {
        US_WARN("failed to get sm2 keymgmt load function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().load(reference, reference_sz);
}

static int kae_keymgmt_sm2_has(const void *keydata, int selection)
{
    if (!get_default_sm2_keymgmt().has) {
        US_WARN("failed to get sm2 keymgmt has function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().has(keydata, selection);
}

static int kae_keymgmt_sm2_validate(const void *keydata, int selection, int checktype)
{
    if (!get_default_sm2_keymgmt().validate) {
        US_WARN("failed to get sm2 keymgmt validate function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().validate(keydata, selection, checktype);
}

static int kae_keymgmt_sm2_match(const void *keydata1, const void *keydata2, int selection)
{
    if (!get_default_sm2_keymgmt().match) {
        US_WARN("failed to get sm2 keymgmt validate function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().match(keydata1, keydata2, selection);
}

static int kae_keymgmt_sm2_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    if (!get_default_sm2_keymgmt().import) {
        US_WARN("failed to get sm2 keymgmt import function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().import(keydata, selection, params);
}

static const OSSL_PARAM *kae_keymgmt_sm2_import_types(int selection)
{
    if (!get_default_sm2_keymgmt().import_types) {
        US_WARN("failed to get sm2 keymgmt import_types function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().import_types(selection);
}

static int kae_keymgmt_sm2_export(void *keydata, int selection, OSSL_CALLBACK *param_callback, void *cbarg)
{
    if (!get_default_sm2_keymgmt().export_fun) {
        US_WARN("failed to get sm2 keymgmt export function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_keymgmt().export_fun(keydata, selection, param_callback, cbarg);
}

static const OSSL_PARAM *kae_keymgmt_sm2_export_types(int selection)
{
    if (!get_default_sm2_keymgmt().export_types) {
        US_WARN("failed to get sm2 keymgmt export_types function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().export_types(selection);
}

static void *kae_keymgmt_sm2_dup(const void *keydata_from, int selection)
{
    if (!get_default_sm2_keymgmt().dup) {
        US_WARN("failed to get sm2 keymgmt dup function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().dup(keydata_from, selection);
}

static const char *kae_keymgmt_sm2_query_operation_name(int operation_id)
{
    if (!get_default_sm2_keymgmt().query_operation_name) {
        US_WARN("failed to get sm2 keymgmt query_operation_name function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().query_operation_name(operation_id);
}

static void *kae_asym_cipher_sm2_newctx(void *provctx)
{
    PROV_SM2_ASYM_CTX *psm2ctx = OPENSSL_zalloc(sizeof(PROV_SM2_ASYM_CTX));
    SM2_PROV_CTX *smctx;

    if (psm2ctx == NULL) {
        US_WARN("failed to alloc PROV_SM2_ASYM_CTX.");
        return NULL;
    }

    psm2ctx->libctx = prov_libctx_of(provctx);

    smctx = OPENSSL_zalloc(sizeof(SM2_PROV_CTX));
    if (smctx == NULL) {
        US_WARN("failed to alloc sm2 prov ctx.");
        goto free_psm2ctx;
    }

    smctx->sm2_md = OPENSSL_zalloc(sizeof(SM2_MD_DATA));
    if (smctx->sm2_md == NULL) {
        US_WARN("failed to alloc sm2 md data.");
        goto free_smctx;
    }

    /* Use SM3 in default, other digest can be set with set_ctx_params API. */
    smctx->sm2_md->mdsize = SM3_DIGEST_LENGTH;

    smctx->sm2_pd = OPENSSL_zalloc(sizeof(SM2_PKEY_DATA));
    if (smctx->sm2_pd == NULL) {
        US_WARN("failed to alloc sm2 pkey data.");
        goto free_sm2_md;
    }

    psm2ctx->sm2_pctx = smctx;

    US_DEBUG("kae prov sm2 new ctx success!");
    return psm2ctx;

free_sm2_md:
    OPENSSL_free(smctx->sm2_md);
free_smctx:
    OPENSSL_free(smctx);
free_psm2ctx:
    OPENSSL_free(psm2ctx);

    return NULL;
}

static void kae_prov_sm2_set_default_md(PROV_SM2_ASYM_CTX *psm2ctx)
{
    SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
    SM2_MD_DATA *smd = smctx->sm2_md;

    /* Set SM3 as default digest method */
    if (smd->alloc_md)
        EVP_MD_free(smd->alloc_md);
    smd->md = smd->alloc_md = EVP_MD_fetch(psm2ctx->libctx, "SM3", NULL);
    smd->md_nid = NID_sm3;
}

static int kae_asym_cipher_sm2_encrypt_init_sw(void *vpsm2ctx, void *vkey, const OSSL_PARAM params[])
{
    if (!get_default_sm2_asym_cipher().encrypt_init) {
        US_WARN("failed to get sm2 keymgmt encrypt init function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_asym_cipher().encrypt_init(vpsm2ctx, vkey, params);
}

static int kae_asym_cipher_sm2_encrypt_init(void *vpsm2ctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    if (vkey == NULL || !EC_KEY_up_ref(vkey)) {
        US_WARN("invalid: vkey is NULL.");
        return KAE_P_FAIL;
    }
    EC_KEY_free(psm2ctx->ec_key);
    psm2ctx->ec_key = vkey;

    /* Set default digest method as SM3 */
    kae_prov_sm2_set_default_md(psm2ctx);

    ret = kae_asym_cipher_sm2_set_ctx_params(psm2ctx, params);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to set_ctx_params.");
        goto do_soft;
    }

    // smctx->hsmctx = calloc(1, sizeof(smctx->hsmctx)); // 不同于cipher的自动申请和回收pkey需要自己申请的
    if (!smctx->hsmctx) {
        US_WARN("failed to alloc sm2 ctx.");
        return OPENSSL_FAIL;
    }

    ret = hpre_sm2_update_sess(smctx);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to update sess.");
        goto do_soft;
    }

    smctx->init_status = CTX_INIT_SUCC;
    smctx->hsmctx->init_status = HPRE_SM2_INIT_SUCC;

    US_DEBUG("kae prov sm2 encrypt init success!");
    return KAE_P_SUCCESS;

do_soft:
    US_WARN("kae prov sm2 encrypt init failed, switch to soft.");
    return kae_asym_cipher_sm2_encrypt_init_sw(vpsm2ctx, vkey, params);
}

static int kae_prov_sm2_encrypt_check(
    PROV_SM2_ASYM_CTX *psm2ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
    const EVP_MD *md;

    if (smctx == NULL || smctx->hsmctx == NULL) {
        US_WARN("smctx or hsmctx NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->init_status != CTX_INIT_SUCC) {
        US_WARN("sm2 ctx init failed.");
        return KAE_P_FAIL;
    }

    /*
     * As we have already set md method in init, if not set, will use default digest.
     * The md is unlikey to be NULL here, so if the md is still NULL when encrypt start,
     * just return fail.
     */
    md = smctx->sm2_md->md;
    if (md == NULL) {
        US_WARN("failed to get md method.");
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static int kae_prov_sm2_encrypt_sw(
    PROV_SM2_ASYM_CTX *vpsm2ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    if (!get_default_sm2_asym_cipher().encrypt) {
        US_WARN("fail to get sm2 asym encrypt function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_asym_cipher().encrypt(vpsm2ctx, out, outlen, 0, in, inlen);
}

static int kae_asym_cipher_sm2_encrypt(
    void *vpsm2ctx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    ret = kae_prov_sm2_encrypt_check(psm2ctx, out, outlen, in, inlen);
    if (ret == KAE_P_FAIL)
        return ret;

    ret = hpre_sm2_encrypt(psm2ctx, out, outlen, in, inlen);
    if (ret == KAE_CRYPTO_FAIL) {
        return kae_prov_sm2_encrypt_sw(psm2ctx, out, outlen, in, inlen);
    }

    US_DEBUG("kae prov sm2 encrypt success!");
    return OPENSSL_SUCCESS;
}

static int kae_asym_cipher_sm2_decrypt_init(void *vpsm2ctx, void *vkey, const OSSL_PARAM params[])
{
    return kae_asym_cipher_sm2_encrypt_init(vpsm2ctx, vkey, params);
}

static int kae_prov_sm2_decrypt_check(
    SM2_PROV_CTX *smctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    if (smctx == NULL || smctx->hsmctx == NULL) {
        US_WARN("smctx or sess NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->init_status != CTX_INIT_SUCC) {
        US_WARN("sm2 ctx init failed.");
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static int kae_asym_cipher_sm2_decrypt(
    void *vpsm2ctx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    smctx = psm2ctx->sm2_pctx;
    ret = kae_prov_sm2_decrypt_check(smctx, out, outlen, in, inlen);
    if (ret == KAE_P_FAIL)
        return ret;

    return hpre_sm2_decrypt(psm2ctx, out, outlen, in, inlen);
}

static void kae_asym_cipher_sm2_freectx(void *vpsm2ctx)
{
    PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;

    if (psm2ctx == NULL)
        return;

    smctx = psm2ctx->sm2_pctx;
    if (smctx) {
        if (smctx->sm2_md)
            OPENSSL_free(smctx->sm2_md);

        if (smctx->sm2_pd)
            OPENSSL_free(smctx->sm2_pd);
        OPENSSL_free(smctx);

        if (smctx->sm2_md->mdctx)
            EVP_MD_CTX_free(smctx->sm2_md->mdctx);
    }

    if (psm2ctx->ec_key)
        EC_KEY_free(psm2ctx->ec_key);

    OPENSSL_free(psm2ctx);
}

static void *kae_asym_cipher_sm2_dupctx(void *vpsm2ctx)
{
    PROV_SM2_ASYM_CTX *srcctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
    SM2_PROV_CTX *dst_smctx, *src_smctx;
    PROV_SM2_ASYM_CTX *dstctx;

    if (srcctx == NULL) {
        US_WARN("src ctx is NULL.");
        return NULL;
    }

    src_smctx = srcctx->sm2_pctx;
    if (src_smctx == NULL) {
        US_WARN("src_smctx is NULL.");
        return NULL;
    }

    if (src_smctx->sm2_md == NULL) {
        US_WARN("src_smctx is NULL.");
        return NULL;
    }

    dstctx = OPENSSL_zalloc(sizeof(PROV_SM2_ASYM_CTX));
    if (dstctx == NULL) {
        US_WARN("failed to alloc dst ctx.");
        return NULL;
    }
    *dstctx = *srcctx;

    dst_smctx = OPENSSL_zalloc(sizeof(SM2_PROV_CTX));
    if (dst_smctx == NULL) {
        US_WARN("failed to alloc dst_smctx.");
        goto free;
    }

    dst_smctx->sm2_md = OPENSSL_zalloc(sizeof(SM2_MD_DATA));
    if (dst_smctx->sm2_md == NULL) {
        US_WARN("failed to alloc dst_smd.");
        goto free;
    }

    if (dstctx->ec_key != NULL && !EC_KEY_up_ref(dstctx->ec_key)) {
        US_WARN("failed to check dstctx key reference.");
        goto free;
    }

    if (dst_smctx->sm2_md->alloc_md && !EVP_MD_up_ref(dst_smctx->sm2_md->alloc_md)) {
        US_WARN("failed to check alloc_md reference.");
        goto free;
    }

    dst_smctx->sm2_md->md = src_smctx->sm2_md->md;
    dst_smctx->sm2_md->alloc_md = src_smctx->sm2_md->alloc_md;

    dstctx->sm2_pctx = dst_smctx;

    return dstctx;

free:
    kae_asym_cipher_sm2_freectx(dstctx);
    return NULL;
}

static int kae_asym_cipher_sm2_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
    PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;
    SM2_MD_DATA *smd;
    OSSL_PARAM *p;
    EVP_MD *md;

    if (psm2ctx == NULL) {
        US_WARN("failed to get psm2ctx.");
        return KAE_P_FAIL;
    }

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("failed to get smctx.");
        return KAE_P_FAIL;
    }

    smd = smctx->sm2_md;
    if (smd == NULL) {
        US_WARN("failed to get sm2 md.");
        return KAE_P_FAIL;
    }

    if (params == NULL) {
        US_WARN("params is NULL.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
    if (p != NULL) {
        md = smd->md;
        if (!OSSL_PARAM_set_utf8_string(p, md == NULL ? "" : EVP_MD_get0_name(md))) {
            US_WARN("failed to set utf8 string.");
            return KAE_P_FAIL;
        }
        smd->md_nid = EVP_MD_type(md);
    } else {
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static const OSSL_PARAM *kae_asym_cipher_sm2_gettable_ctx_params(ossl_unused void *vpsm2ctx, ossl_unused void *provctx)
{
    return sm2_asym_cipher_known_gettable_ctx_params;
}

static EVP_MD *kae_prov_load_digest_from_params(SM2_MD_DATA *smd, const OSSL_PARAM params[], OSSL_LIB_CTX *ctx)
{
    const char *propquery = NULL;
    const OSSL_PARAM *p;

    /* Load common param properties, p can be NULL */
    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
    if (p) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            US_WARN("data_type != OSSL_PARAM_UTF8_STRING.");
            return NULL;
        }
        propquery = p->data;
    }

    /* Load digest related params */
    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
    if (p) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            US_WARN("data_type != OSSL_PARAM_UTF8_STRING.");
            return NULL;
        }
    } else {
        /* If digest related params is NULL, no need to set digest */
        return NULL;
    }

    /* Fetch digest */
    EVP_MD_free(smd->alloc_md);
    smd->md = smd->alloc_md = EVP_MD_fetch(ctx, p->data, propquery);
    if (smd->md == NULL) {
        US_WARN("failed to fetch MD method.");
        return NULL;
    }

    return smd->md;
}

static int kae_asym_cipher_sm2_set_ctx_params_sw(void *vpsm2ctx, const OSSL_PARAM params[])
{
    if (!get_default_sm2_asym_cipher().set_ctx_params) {
        US_WARN("fail to get sm2 asym set_ctx_params function.");
        return KAE_P_FAIL;
    }
    return get_default_sm2_asym_cipher().set_ctx_params(vpsm2ctx, params);
}

static int kae_asym_cipher_sm2_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
    PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;
    SM2_MD_DATA *smd;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: sm2 ctx is NULL.");
        return KAE_P_FAIL;
    }

    /* No need to set */
    if (params == NULL)
        return KAE_P_SUCCESS;

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    /* Set digest method */
    smd = smctx->sm2_md;
    if (smd == NULL) {
        US_WARN("invalid: sm2 md is NULL.");
        return KAE_P_FAIL;
    }

    smd->md = kae_prov_load_digest_from_params(smctx->sm2_md, params, psm2ctx->libctx);
    if (smd->md == NULL) {
        US_WARN("failed to set digest with set_ctx_params.");
        return KAE_P_FAIL;
    }
    smd->md_nid = EVP_MD_type(smd->md);

    /* If not init, do not need to update session, just set the data before */
    if (smctx->init_status == CTX_INIT_SUCC) {
        ret = hpre_sm2_update_sess(smctx);
        if (ret == KAE_P_FAIL) {
            US_WARN("failed to update sess.");
            goto do_soft;
        }
    }

    return KAE_P_SUCCESS;

do_soft:
    return kae_asym_cipher_sm2_set_ctx_params_sw(vpsm2ctx, params);
}

static const OSSL_PARAM *kae_asym_cipher_sm2_settable_ctx_params(ossl_unused void *vpsm2ctx, ossl_unused void *provctx)
{
    return sm2_asym_cipher_known_settable_ctx_params;
}

static void *kae_signature_sm2_newctx(void *provctx, const char *propq)
{
    PROV_SM2_SIGN_CTX *psm2ctx = OPENSSL_zalloc(sizeof(PROV_SM2_SIGN_CTX));
    SM2_PROV_CTX *smctx;

    if (psm2ctx == NULL) {
        US_WARN("failed to alloc sm2 signature ctx.");
        return NULL;
    }
    /* The libctx maybe NULL, if libctx is NULL, will use default ctx. */
    psm2ctx->libctx = prov_libctx_of(provctx);

    smctx = OPENSSL_zalloc(sizeof(SM2_PROV_CTX));
    if (smctx == NULL) {
        US_WARN("failed to alloc sm2 prov ctx.");
        goto free_ctx;
    }

    smctx->sm2_pd = OPENSSL_zalloc(sizeof(SM2_PKEY_DATA));
    if (smctx->sm2_pd == NULL) {
        US_WARN("failed to alloc sm2 pkey data.");
        goto free_smctx;
    }

    smctx->sm2_md = OPENSSL_zalloc(sizeof(SM2_MD_DATA));
    if (smctx->sm2_md == NULL) {
        US_WARN("failed to alloc sm2 md data.");
        goto free_pd;
    }

    /*
     * Use SM3 for digest method in default, other digest algs
     * can be set with set_ctx_params API.
     */
    smctx->sm2_md->mdsize = SM3_DIGEST_LENGTH;
    smctx->sm2_md->md_nid = NID_sm3;
    strcpy(psm2ctx->mdname, OSSL_DIGEST_NAME_SM3);
    smctx->sm2_md->mdctx = EVP_MD_CTX_new();
    if (smctx->sm2_md->mdctx == NULL) {
        US_WARN("failed to alloc sm2 mdctx.");
        goto free_md;
    }

    psm2ctx->sm2_pctx = smctx;

    if (propq) {
        psm2ctx->propq = OPENSSL_strdup(propq);
        if (psm2ctx->propq == NULL) {
            US_WARN("failed to dup propq.");
            goto free_mdctx;
        }
    }

    return psm2ctx;

free_mdctx:
    EVP_MD_CTX_free(smctx->sm2_md->mdctx);
free_md:
    OPENSSL_free(smctx->sm2_md);
free_pd:
    OPENSSL_free(smctx->sm2_pd);
free_smctx:
    OPENSSL_free(smctx);
free_ctx:
    OPENSSL_free(psm2ctx);
    return NULL;
}

static int kae_signature_sm2_sign_init_sw(void *vpsm2ctx, void *ec, const OSSL_PARAM params[])
{
    if (!get_default_sm2_signature().sign_init) {
        US_WARN("fail to get sm2 sign_init function.");
        return KAE_P_FAIL;
    }
    return get_default_sm2_signature().sign_init(vpsm2ctx, ec, params);
}

static int kae_signature_sm2_sign_init(void *vpsm2ctx, void *ec, const OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: vpsm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    if (ec == NULL && psm2ctx->ec_key == NULL) {
        US_WARN("invalid: sm2 key is NULL.");
        return KAE_P_FAIL;
    }

    if (ec) {
        if (!EC_KEY_up_ref(ec)) {
            US_WARN("failed to EC_KEY_up_ref.");
            return KAE_P_FAIL;
        }
        EC_KEY_free(psm2ctx->ec_key);
        psm2ctx->ec_key = (EC_KEY *)ec;
    }

    if (psm2ctx->sm2_pctx == NULL) {
        US_WARN("failed to get smctx.");
        return KAE_P_FAIL;
    }

    /* openssl dgst tool will call sign_init twice, avoid repeated initialization */
    if (psm2ctx->sm2_pctx->init_status == CTX_INIT_SUCC)
        return KAE_P_SUCCESS;

    ret = kae_signature_sm2_set_ctx_params((void *)psm2ctx, params);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to set sm2 sig ctx params.");
        goto do_soft;
    }

    // ret = kae_prov_signature_get_support_state(SIGNATURE_SM2);
    // if (ret == KAE_P_FAIL) {
    // 	US_WARN("failed to get hardware sm2 signature support.");
    // 	goto do_soft;
    // }

    // /* Init with KAE */
    // ret = kae_prov_ecc_init("sm2");
    // if (ret == KAE_P_FAIL) {
    // 	US_WARN("failed to init sm2.");
    // 	goto do_soft;
    // }

    ret = hpre_sm2_update_sess(psm2ctx->sm2_pctx);

    if (ret == KAE_P_FAIL) {
        US_WARN("failed to update sess in sign init.");
        goto do_soft;
    }

    psm2ctx->sm2_pctx->init_status = CTX_INIT_SUCC;
    psm2ctx->sm2_pctx->hsmctx->init_status = HPRE_SM2_INIT_SUCC;
    return KAE_P_SUCCESS;

do_soft:
    return kae_signature_sm2_sign_init_sw(vpsm2ctx, ec, params);
}

static int kae_signature_sm2_verify_init(void *vpsm2ctx, void *ec, const OSSL_PARAM params[])
{
    return kae_signature_sm2_sign_init(vpsm2ctx, ec, params);
}

static int kae_prov_sm2_check_tbs_params(PROV_SM2_SIGN_CTX *psm2ctx, const unsigned char *tbs, size_t tbslen)
{
    SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;

    if (smctx == NULL) {
        US_WARN("invalid: ctx is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->hsmctx == NULL) {
        US_WARN("invalid: smctx->sess is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->init_status != CTX_INIT_SUCC) {
        US_WARN("sm2 ctx init did not init.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md == NULL) {
        US_WARN("invalid: sm2_md is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->mdsize != 0 && tbslen != smctx->sm2_md->mdsize) {
        US_WARN("invalid: tbslen(%zu) != mdsize(%zu).", tbslen, smctx->sm2_md->mdsize);
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static int kae_signature_sm2_sign_sw(
    void *vpsm2ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    if (!get_default_sm2_signature().sign) {
        US_WARN("fail to get sm2 sign function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_signature().sign(vpsm2ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int kae_signature_sm2_sign(
    void *vpsm2ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    int ret, ecsize;
    size_t sltmp;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    if (psm2ctx->ec_key == NULL) {
        US_WARN("invalid: sm2 ec is NULL.");
        return KAE_P_FAIL;
    }

    ecsize = ECDSA_size(psm2ctx->ec_key);
    if (ecsize <= 0) {
        US_WARN("ecsize error %d.", ecsize);
        return KAE_P_FAIL;
    }

    /*
     * If 'sig' is NULL, users can use sm2_decrypt API to obtain the valid 'siglen' first,
     * then users use the value of 'signlen' to alloc the memory of 'sig' and call the
     * sm2_decrypt API a second time to do the decryption task.
     */
    if (sig == NULL) {
        *siglen = (size_t)ecsize;
        return SM2_GET_SIGNLEN;
    }

    if (sigsize < (size_t)ecsize) {
        US_WARN("sigsize(%zu) < ecsize(%d).", sigsize, ecsize);
        goto do_soft;
    }

    ret = kae_prov_sm2_check_tbs_params(psm2ctx, tbs, tbslen);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to check sm2 signature params.");
        goto do_soft;
    }

    ret = hpre_sm2_sign(psm2ctx, sig, &sltmp, tbs, tbslen);
    if (ret == KAE_CRYPTO_FAIL) {
        US_WARN("failed to do sm2 sign.");
        goto do_soft;
    }

    *siglen = sltmp;

    return KAE_P_SUCCESS;

do_soft:

    return kae_signature_sm2_sign_sw(vpsm2ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int kae_signature_sm2_verify_sw(
    void *vpsm2ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    if (!get_default_sm2_signature().verify) {
        US_WARN("fail to get sm2 verify function.");
        return KAE_P_FAIL;
    }
    return get_default_sm2_signature().verify(vpsm2ctx, sig, siglen, tbs, tbslen);
}

static int kae_signature_sm2_verify(
    void *vpsm2ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    ret = kae_prov_sm2_check_tbs_params(psm2ctx, tbs, tbslen);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to check sm2 verify params.");
        goto do_soft;
    }

    ret = hpre_sm2_verify(psm2ctx, sig, siglen, tbs, tbslen);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to do sm2 verify.");
        goto do_soft;
    }

    return KAE_P_SUCCESS;

do_soft:
    return kae_signature_sm2_verify_sw(vpsm2ctx, sig, siglen, tbs, tbslen);
}

static int kae_signature_sm2_verify_recover_init(void *vpsm2ctx, void *vsm2, const OSSL_PARAM params[])
{
    // 软算的也没有实现
    return KAE_P_SUCCESS;
}

static int kae_signature_sm2_verify_recover(
    void *vpsm2ctx, unsigned char *rout, size_t *routlen, size_t routsize, const unsigned char *sig, size_t siglen)
{
    return KAE_P_SUCCESS;
}

static int kae_prov_sm2_sig_set_mdname(PROV_SM2_SIGN_CTX *psm2ctx, const char *mdname)
{
    SM2_PROV_CTX *smctx;

    /* If mdname is NULL, no need to set, just return */
    if (mdname == NULL)
        return KAE_P_SUCCESS;

    /* 'psm2ctx' has already been checked when call this function, no need to check again */
    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md == NULL) {
        US_WARN("invalid: smctx->sm2_md is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->md == NULL) {
        // smctx->sm2_md->md = EVP_MD_fetch(psm2ctx->libctx, psm2ctx->mdname, psm2ctx->propq);
        smctx->sm2_md->md = EVP_MD_fetch(NULL, "SM3", "provider=default");
        if (smctx->sm2_md->md == NULL) {
            US_WARN("failed to fetch digest method.");
            return KAE_P_FAIL;
        }
    }

    if (strlen(mdname) >= sizeof(psm2ctx->mdname) || !EVP_MD_is_a(smctx->sm2_md->md, mdname)) {
        US_WARN("failed to check mdname, digest=%s.", mdname);
        return KAE_P_FAIL;
    }

    OPENSSL_strlcpy(psm2ctx->mdname, mdname, sizeof(psm2ctx->mdname));

    return KAE_P_SUCCESS;
}

static int kae_signature_sm2_digest_sign_init(void *vpsm2ctx, const char *mdname, void *ec, const OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;
    int md_nid;
    WPACKET pkt;

    if (!kae_signature_sm2_sign_init(vpsm2ctx, ec, params) || !kae_prov_sm2_sig_set_mdname(psm2ctx, mdname))
        return KAE_P_FAIL;

    smctx = psm2ctx->sm2_pctx;

    if (smctx->sm2_md->mdctx == NULL) {
        smctx->sm2_md->mdctx = EVP_MD_CTX_new();
        if (unlikely(smctx->sm2_md->mdctx == NULL)) {
            US_WARN("failed to EVP_MD_CTX_new.");
            return KAE_P_FAIL;
        }
    }

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    md_nid = EVP_MD_get_type(smctx->sm2_md->md);
    smctx->sm2_md->md_nid = md_nid;
    psm2ctx->aid_len = 0;
    if (WPACKET_init_der(&pkt, psm2ctx->aid_buf, sizeof(psm2ctx->aid_buf)) &&
        ossl_DER_w_algorithmIdentifier_SM2_with_MD(&pkt, -1, psm2ctx->ec_key, md_nid) && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &psm2ctx->aid_len);
        psm2ctx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);

    if (!EVP_DigestInit_ex2(smctx->sm2_md->mdctx, smctx->sm2_md->md, params)) {
        US_WARN("failed to do digest init.");
        EVP_MD_CTX_free(smctx->sm2_md->mdctx);
        return KAE_P_FAIL;
    }

    psm2ctx->flag_compute_z_digest = 1;

    return KAE_P_SUCCESS;
}

static int kae_prov_sm2_check_md_params(SM2_PROV_CTX *smctx)
{
    if (smctx->sm2_md == NULL) {
        US_WARN("invalid: sm2_md is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->md == NULL) {
        US_WARN("invalid: md is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->mdctx == NULL) {
        US_WARN("invalid: mdctx is NULL.");
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}
#  define SM2_R_ID_TOO_LARGE                               111

OSSL_LIB_CTX *ossl_ec_key_get_libctx(const EC_KEY *key)
{
    return key->libctx;
}


int ossl_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              const size_t id_len,
                              const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pubkey = EC_KEY_get0_public_key(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    /* SM2 Signatures require a public key, check for it */
    if (pubkey == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto done;
    }

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(key));
    if (hash == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        ERR_raise(ERR_LIB_SM2, SM2_R_ID_TOO_LARGE);
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(b, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_GROUP_get0_generator(group),
                                                xG, yG, ctx)
            || BN_bn2binpad(xG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                pubkey,
                                                xA, yA, ctx)
            || BN_bn2binpad(xA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EVP_DigestFinal(hash, out, NULL)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

 done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}

static int sm2_sig_compute_z_digest(PROV_SM2_SIGN_CTX *psm2ctx)
{
    SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
    uint8_t *z = NULL;
    int ret;

    if (psm2ctx->flag_compute_z_digest) {
        /* Only do this once */
        psm2ctx->flag_compute_z_digest = 0;

        z = OPENSSL_zalloc(smctx->sm2_md->mdsize);
        if (z == NULL) {
            US_WARN("failed to alloc z.");
            return KAE_P_FAIL;
        }

        /* get hashed prefix 'z' of tbs message */
        ret = ossl_sm2_compute_z_digest(z, smctx->sm2_md->md, psm2ctx->id, psm2ctx->id_len, psm2ctx->ec_key);
        if (ret == KAE_P_FAIL) {
            US_WARN("failed to kae_prov_sm2_compute_z_digest.");
            goto free_z;
        }

        ret = EVP_DigestUpdate(smctx->sm2_md->mdctx, z, smctx->sm2_md->mdsize);
        if (ret == KAE_P_FAIL) {
            US_WARN("failed to EVP_DigestUpdate.");
            goto free_z;
        }
        OPENSSL_free(z);
    }

    return KAE_P_SUCCESS;

free_z:
    OPENSSL_free(z);
    return KAE_P_FAIL;
}

static int kae_signature_sm2_digest_sign_update(void *vpsm2ctx, const unsigned char *data, size_t datalen)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL in digest sign update.");
        return KAE_P_FAIL;
    }

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL in compute z digest.");
        return KAE_P_FAIL;
    }

    ret = kae_prov_sm2_check_md_params(smctx);
    if (ret == KAE_P_FAIL)
        return ret;

    ret = sm2_sig_compute_z_digest(psm2ctx);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to compute z digest.");
        return ret;
    }

    ret = EVP_DigestUpdate(smctx->sm2_md->mdctx, data, datalen);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to EVP_DigestUpdate.");
        return ret;
    }

    return KAE_P_SUCCESS;
}

static int kae_signature_sm2_digest_sign_final(void *vpsm2ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    SM2_PROV_CTX *smctx;
    int ret;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    ret = kae_prov_sm2_check_md_params(smctx);
    if (ret == KAE_P_FAIL)
        return ret;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to sm2sig_sign.
     */
    if (sig != NULL) {
        ret = sm2_sig_compute_z_digest(psm2ctx);
        if (ret == KAE_P_FAIL)
            return ret;

        ret = EVP_DigestFinal_ex(smctx->sm2_md->mdctx, digest, &dlen);
        if (ret == KAE_P_FAIL) {
            US_WARN("failed to do EVP_DigestFinal_ex.");
            return ret;
        }
    }

    return kae_signature_sm2_sign(vpsm2ctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int kae_signature_sm2_digest_verify_init(void *vpsm2ctx, const char *mdname, void *ec, const OSSL_PARAM params[])
{
    return kae_signature_sm2_digest_sign_init(vpsm2ctx, mdname, ec, params);
}

static int kae_signature_sm2_digest_verify_update(void *vpsm2ctx, const unsigned char *data, size_t datalen)
{
    return kae_signature_sm2_digest_sign_update(vpsm2ctx, data, datalen);
}

static int kae_signature_sm2_digest_verify_final(void *vpsm2ctx, const unsigned char *sig, size_t siglen)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    SM2_PROV_CTX *smctx;
    int ret, size;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    ret = kae_prov_sm2_check_md_params(smctx);
    if (ret == KAE_P_FAIL)
        return ret;

    size = EVP_MD_get_size(smctx->sm2_md->md);
    if (size > EVP_MAX_MD_SIZE) {
        US_WARN("invalid: md size(%d) > %d.", size, EVP_MAX_MD_SIZE);
        return KAE_P_FAIL;
    }

    ret = sm2_sig_compute_z_digest(psm2ctx);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to do sm2_sig_compute_z_digest.");
        return ret;
    }

    ret = EVP_DigestFinal_ex(smctx->sm2_md->mdctx, digest, &dlen);
    if (ret == KAE_P_FAIL) {
        US_WARN("failed to do EVP_DigestFinal_ex, dlen = %u.", dlen);
        return ret;
    }

    return kae_signature_sm2_verify(vpsm2ctx, sig, siglen, digest, (size_t)dlen);
}

static void kae_signature_sm2_freectx(void *vpsm2ctx)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;

    if (psm2ctx == NULL)
        return;

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL)
        goto free_psm2ctx;

    /*
     * Pkey and md related data in smctx->sm2_md and smctx->sm2_pd will
     * release by some openssl tools, such as dgst, after call freectx.
     * Free pkey and md related data in our provider will cause double-free
     * with openssl dgst tool, maybe it is an openssl bug, fix it later.
     */

    if (smctx->sm2_md->mdctx)
        EVP_MD_CTX_free(smctx->sm2_md->mdctx);
    OPENSSL_free(smctx);

free_psm2ctx:
    if (psm2ctx->propq)
        OPENSSL_free(psm2ctx->propq);
    if (psm2ctx->ec_key)
        EC_KEY_free(psm2ctx->ec_key);
    if (psm2ctx->id)
        OPENSSL_free(psm2ctx->id);

    OPENSSL_free(psm2ctx);
    return;
}

static int check_signature_src_ctx(PROV_SM2_SIGN_CTX *srcctx)
{
    SM2_PROV_CTX *src_smctx;

    if (srcctx == NULL) {
        US_WARN("invalid: src ctx is NULL.");
        return KAE_P_FAIL;
    }

    if (srcctx->ec_key != NULL && !EC_KEY_up_ref(srcctx->ec_key)) {
        US_WARN("failed to check srcctx key reference.");
        return KAE_P_FAIL;
    }

    src_smctx = srcctx->sm2_pctx;
    if (src_smctx == NULL) {
        US_WARN("invalid: src_smctx is NULL.");
        return KAE_P_FAIL;
    }

    if (src_smctx->sm2_md == NULL) {
        US_WARN("invalid: sm2_md is NULL.");
        return KAE_P_FAIL;
    }

    if (src_smctx->sm2_md->md != NULL && !EVP_MD_up_ref(src_smctx->sm2_md->md)) {
        US_WARN("failed to check srcctx md reference.");
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static int create_dst_ctx_data(SM2_PROV_CTX *dst_smctx)
{
    dst_smctx->sm2_md = OPENSSL_zalloc(sizeof(SM2_MD_DATA));
    if (dst_smctx->sm2_md == NULL) {
        US_WARN("failed to alloc dst_smctx->sm2_md.");
        return KAE_P_FAIL;
    }

    dst_smctx->sm2_pd = OPENSSL_zalloc(sizeof(SM2_PKEY_DATA));
    if (dst_smctx->sm2_pd == NULL) {
        US_WARN("failed to alloc dst_smctx->sm2_pd.");
        OPENSSL_free(dst_smctx->sm2_md);
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static void copy_ctx_data(SM2_PROV_CTX *dst_smctx, SM2_PROV_CTX *src_smctx)
{
    dst_smctx->sm2_md->md = src_smctx->sm2_md->md;
    dst_smctx->sm2_md->mdsize = src_smctx->sm2_md->mdsize;
    dst_smctx->sm2_md->md_nid = src_smctx->sm2_md->md_nid;
    dst_smctx->sm2_pd = src_smctx->sm2_pd;
    dst_smctx->hsmctx = src_smctx->hsmctx;
    dst_smctx->init_status = src_smctx->init_status;
}

static void release_dst_ctx_data(SM2_PROV_CTX *dst_smctx)
{
    if (dst_smctx->sm2_md)
        OPENSSL_free(dst_smctx->sm2_md);

    if (dst_smctx->sm2_pd)
        OPENSSL_free(dst_smctx->sm2_pd);
}

static void *kae_signature_sm2_dupctx(void *vpsm2ctx)
{
    PROV_SM2_SIGN_CTX *srcctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *dst_smctx, *src_smctx;
    PROV_SM2_SIGN_CTX *dstctx;

    if (check_signature_src_ctx(srcctx) == KAE_P_FAIL)
        return NULL;
    src_smctx = srcctx->sm2_pctx;

    dstctx = OPENSSL_zalloc(sizeof(PROV_SM2_SIGN_CTX));
    if (dstctx == NULL) {
        US_WARN("failed to alloc dst ctx.");
        return NULL;
    }

    memcpy(dstctx, srcctx, sizeof(PROV_SM2_SIGN_CTX));
    dstctx->ec_key = srcctx->ec_key;

    dst_smctx = OPENSSL_zalloc(sizeof(SM2_PROV_CTX));
    if (dst_smctx == NULL) {
        US_WARN("failed to alloc dst_smctx.");
        goto free_dstctx;
    }
    dstctx->sm2_pctx = dst_smctx;

    if (create_dst_ctx_data(dst_smctx) == KAE_P_FAIL)
        goto free_dst_smctx;

    if (src_smctx->sm2_md->mdctx != NULL) {
        dst_smctx->sm2_md->mdctx = EVP_MD_CTX_new();
        if (dst_smctx->sm2_md->mdctx == NULL ||
            EVP_MD_CTX_copy_ex(dst_smctx->sm2_md->mdctx, src_smctx->sm2_md->mdctx) == 0) {
            US_WARN("failed to new dst mdctx or copy src mdctx.");
            goto free_dst_ctx_data;
        }
    }

    copy_ctx_data(dst_smctx, src_smctx);

    if (srcctx->id != NULL) {
        dstctx->id = OPENSSL_malloc(srcctx->id_len);
        if (dstctx->id == NULL) {
            US_WARN("failed to alloc id.");
            goto free_dst_mdctx;
        }
        dstctx->id_len = srcctx->id_len;
        memcpy(dstctx->id, srcctx->id, srcctx->id_len);
    }

    return dstctx;

free_dst_mdctx:
    EVP_MD_CTX_free(dst_smctx->sm2_md->mdctx);
free_dst_ctx_data:
    release_dst_ctx_data(dst_smctx);
free_dst_smctx:
    OPENSSL_free(dst_smctx);
free_dstctx:
    OPENSSL_free(dstctx);
    return NULL;
}

static int kae_signature_sm2_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    OSSL_PARAM *p;

    if (psm2ctx == NULL) {
        US_WARN("invalid: psm2ctx is NULL.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, psm2ctx->aid, psm2ctx->aid_len)) {
        US_WARN("failed to locate algorithm id.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, psm2ctx->sm2_pctx->sm2_md->mdsize)) {
        US_WARN("failed to locate digest size.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p,
                         psm2ctx->sm2_pctx->sm2_md->md == NULL ? psm2ctx->mdname
                                                               : EVP_MD_get0_name(psm2ctx->sm2_pctx->sm2_md->md))) {
        US_WARN("failed to locate digest.");
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static const OSSL_PARAM *kae_signature_sm2_gettable_ctx_params(ossl_unused void *vpsm2ctx, ossl_unused void *provctx)
{
    return sm2_sig_known_gettable_ctx_params;
}

static int kae_prov_sm2_locate_id_digest(PROV_SM2_SIGN_CTX *psm2ctx, const OSSL_PARAM params[])
{
    size_t tmp_idlen = 0;
    const OSSL_PARAM *p;
    void *tmp_id = NULL;
    char *mdname = NULL;
    size_t mdsize;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p) {
        /*If the 'z' digest has already been computed, the ID is set too late */
        if (psm2ctx->flag_compute_z_digest == 0) {
            US_WARN("invalid: should set ID param before z digest.");
            return KAE_P_FAIL;
        }

        if (p->data_size != 0 && !OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_idlen)) {
            US_WARN("failed to OSSL_PARAM_get_octet_string.");
            return KAE_P_FAIL;
        }
        if (psm2ctx->id != NULL)
            OPENSSL_free(psm2ctx->id);
        psm2ctx->id = tmp_id;
        psm2ctx->id_len = tmp_idlen;
    }

    /*
     * The following code checks that the size is the same as the SM3 digest
     * size returning an error otherwise.
     * If there is ever any different digest algorithm allowed with SM2
     * this needs to be adjusted accordingly.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &mdsize) || mdsize != psm2ctx->sm2_pctx->sm2_md->mdsize)) {
        US_WARN("failed to locate digest size.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0)) {
            US_WARN("failed to OSSL_PARAM_get_utf8_string.");
            return KAE_P_FAIL;
        }

        if (!kae_prov_sm2_sig_set_mdname(psm2ctx, mdname)) {
            OPENSSL_free(mdname);
            US_WARN("failed to OSSL_PARAM_get_utf8_string.");
            return KAE_P_FAIL;
        }

        if (mdname != NULL)
            OPENSSL_free(mdname);
    }

    return KAE_P_SUCCESS;
}

static int kae_signature_sm2_set_ctx_params_sw(void *vpsm2ctx, const OSSL_PARAM params[])
{
    if (!get_default_sm2_signature().set_ctx_params) {
        US_WARN("fail to get sm2 set_ctx_params function.");
        return KAE_P_FAIL;
    }

    return get_default_sm2_signature().set_ctx_params(vpsm2ctx, params);
}

static int kae_signature_sm2_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;
    int ret;

    /*
     * 'set_ctx_param' function can be called independently,
     * so check 'psm2ctx' again here.
     */
    if (psm2ctx == NULL) {
        US_WARN("invalid: sm2 ctx is NULL.");
        return KAE_P_FAIL;
    }

    /* If params is NULL, no need to set ctx params, just return */
    if (params == NULL)
        return KAE_P_SUCCESS;

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    ret = kae_prov_sm2_locate_id_digest(psm2ctx, params);
    if (ret == KAE_P_FAIL)
        return ret;

    /* If not init, do not need to update session, just set the data before */
    if (smctx->init_status == CTX_INIT_SUCC) {
        ret = hpre_sm2_update_sess(psm2ctx->sm2_pctx);
        if (ret == KAE_P_FAIL) {
            US_WARN("failed to update sess in set_ctx.");
            goto do_soft;
        }
    }

    return KAE_P_SUCCESS;

do_soft:
    return kae_signature_sm2_set_ctx_params_sw(vpsm2ctx, params);
}

static const OSSL_PARAM *kae_signature_sm2_settable_ctx_params(ossl_unused void *vpsm2ctx, ossl_unused void *provctx)
{
    return sm2_sig_known_settable_ctx_params;
}

static int kae_signature_sm2_get_ctx_md_params(void *vpsm2ctx, OSSL_PARAM *params)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->mdctx == NULL) {
        US_WARN("invalid: mdctx is NULL.");
        return KAE_P_FAIL;
    }

    return EVP_MD_CTX_get_params(smctx->sm2_md->mdctx, params);
}

static const OSSL_PARAM *kae_signature_sm2_gettable_ctx_md_params(void *vpsm2ctx)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->md == NULL) {
        US_WARN("invalid: md is NULL.");
        return KAE_P_FAIL;
    }

    return EVP_MD_gettable_ctx_params(smctx->sm2_md->md);
}

static int kae_signature_sm2_set_ctx_md_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->mdctx == NULL) {
        US_WARN("invalid: mdctx is NULL.");
        return KAE_P_FAIL;
    }

    return EVP_MD_CTX_set_params(smctx->sm2_md->mdctx, params);
}

static const OSSL_PARAM *kae_signature_sm2_settable_ctx_md_params(void *vpsm2ctx)
{
    PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
    SM2_PROV_CTX *smctx;

    smctx = psm2ctx->sm2_pctx;
    if (smctx == NULL) {
        US_WARN("invalid: smctx is NULL.");
        return KAE_P_FAIL;
    }

    if (smctx->sm2_md->md == NULL) {
        US_WARN("invalid: md is NULL.");
        return KAE_P_FAIL;
    }

    return EVP_MD_settable_ctx_params(smctx->sm2_md->md);
}