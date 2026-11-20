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
#define KAE_PKEY_PUBLIC_DISPATCH
#include "prov_pkey.h"
#include <openssl/provider.h>
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

    return get_default_sm2_keymgmt().new_fun(OSSL_PROVIDER_get0_provider_ctx(get_default_sm2_keymgmt().prov));
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

    return get_default_sm2_keymgmt().gettable_params(OSSL_PROVIDER_get0_provider_ctx(get_default_sm2_keymgmt().prov));
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

    return get_default_sm2_keymgmt().settable_params(OSSL_PROVIDER_get0_provider_ctx(get_default_sm2_keymgmt().prov));
}

static void *kae_keymgmt_sm2_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    if (!get_default_sm2_keymgmt().gen_init) {
        US_WARN("failed to get sm2 keymgmt gen_init function.");
        return NULL;
    }

    return get_default_sm2_keymgmt().gen_init(OSSL_PROVIDER_get0_provider_ctx(get_default_sm2_keymgmt().prov), selection, params);
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

    return get_default_sm2_keymgmt().gen_settable_params(genctx, OSSL_PROVIDER_get0_provider_ctx(get_default_sm2_keymgmt().prov));
}

static int sm2_normalize_public_key(EC_KEY *key)
{
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *public = EC_KEY_get0_public_key(key);
    BN_CTX *bnctx = NULL;
    BIGNUM *x, *y;
    EC_POINT *affine = NULL;
    int ret = 0;

    if (public == NULL)
        return 1;
    bnctx = BN_CTX_new();
    affine = EC_POINT_new(group);
    if (bnctx == NULL || affine == NULL)
        goto end;
    BN_CTX_start(bnctx);
    x = BN_CTX_get(bnctx);
    y = BN_CTX_get(bnctx);
    /* Normalize once at key creation, not on every Z hash / hardware import. */
    ret = y != NULL && EC_POINT_get_affine_coordinates(group, public, x, y, bnctx) &&
        EC_POINT_set_affine_coordinates(group, affine, x, y, bnctx) &&
        EC_KEY_set_public_key(key, affine);
    BN_CTX_end(bnctx);
end:
    EC_POINT_free(affine);
    BN_CTX_free(bnctx);
    return ret;
}

static void *kae_keymgmt_sm2_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    EC_KEY *key;
    // todo; use hardware?
    if (!get_default_sm2_keymgmt().gen) {
        US_WARN("failed to get sm2 keymgmt gen function.");
        return NULL;
    }

    key = get_default_sm2_keymgmt().gen(genctx, osslcb, cbarg);
    if (key != NULL && !sm2_normalize_public_key(key)) {
        get_default_sm2_keymgmt().free(key);
        key = NULL;
    }
    return key;
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

    return get_default_sm2_keymgmt().import(keydata, selection, params) &&
        sm2_normalize_public_key(keydata);
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

static SM2_PROV_CTX *sm2_ctx_new(void)
{
    SM2_PROV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    ctx->libctx = kae_soft_libctx();
    if (ctx->libctx == NULL)
        goto err;
    ctx->sm2_md = OPENSSL_zalloc(sizeof(*ctx->sm2_md));
    if (ctx->sm2_md == NULL)
        goto err;
    ctx->sm2_md->md = ctx->sm2_md->alloc_md = EVP_MD_fetch(kae_soft_libctx(), "SM3", "provider=default");
    ctx->sm2_md->mdctx = EVP_MD_CTX_new();
    if (ctx->sm2_md->md == NULL || ctx->sm2_md->mdctx == NULL)
        goto err;
    ctx->sm2_md->md_nid = NID_sm3;
    ctx->sm2_md->mdsize = SM3_DIGEST_LENGTH;
    return ctx;
err:
    if (ctx->sm2_md != NULL) {
        EVP_MD_free(ctx->sm2_md->alloc_md);
        EVP_MD_CTX_free(ctx->sm2_md->mdctx);
        OPENSSL_free(ctx->sm2_md);
    }
    OPENSSL_free(ctx);
    return NULL;
}

static void sm2_ctx_free(SM2_PROV_CTX *ctx)
{
    if (ctx == NULL)
        return;
    hpre_sm2_cleanup(ctx);
    if (ctx->sm2_md != NULL) {
        EVP_MD_CTX_free(ctx->sm2_md->mdctx);
        EVP_MD_free(ctx->sm2_md->alloc_md);
        OPENSSL_free(ctx->sm2_md);
    }
    OPENSSL_free(ctx);
}

static int sm2_prepare(SM2_PROV_CTX *ctx)
{
    extern int sm2_switch_soft;

    if (sm2_switch_soft || ctx->do_soft)
        return 0;
    if (ctx->hsmctx != NULL && ctx->hsmctx->init_status == HPRE_SM2_INIT_SUCC)
        return 1;
    if (!hpre_sm2_update_sess(ctx)) {
        hpre_sm2_cleanup(ctx);
        ctx->do_soft = 1;
        return 0;
    }
    ctx->init_status = CTX_INIT_SUCC;
    ctx->hsmctx->init_status = HPRE_SM2_INIT_SUCC;
    return 1;
}

static SM2_PROV_CTX *sm2_ctx_dup(SM2_PROV_CTX *src)
{
    SM2_PROV_CTX *dst = sm2_ctx_new();

    if (dst == NULL)
        return NULL;
    if (!EVP_MD_up_ref(src->sm2_md->alloc_md))
        goto err;
    EVP_MD_free(dst->sm2_md->alloc_md);
    dst->sm2_md->md = dst->sm2_md->alloc_md = src->sm2_md->alloc_md;
    dst->sm2_md->md_nid = src->sm2_md->md_nid;
    dst->sm2_md->mdsize = src->sm2_md->mdsize;
    if (EVP_MD_CTX_get0_md(src->sm2_md->mdctx) != NULL &&
        !EVP_MD_CTX_copy_ex(dst->sm2_md->mdctx, src->sm2_md->mdctx))
        goto err;
    dst->do_soft = src->do_soft;
    /* A duplicated operation owns its session; it must not share a queue. */
    return dst;
err:
    sm2_ctx_free(dst);
    return NULL;
}

static void *kae_asym_cipher_sm2_newctx(void *provctx)
{
    KAE_PKEY_ASYM_CIPHER method = get_default_sm2_asym_cipher();
    PROV_SM2_ASYM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    if (method.newctx == NULL ||
        (ctx->soft_ctx = method.newctx(OSSL_PROVIDER_get0_provider_ctx(method.prov))) == NULL ||
        (ctx->sm2_pctx = sm2_ctx_new()) == NULL) {
        kae_asym_cipher_sm2_freectx(ctx);
        return NULL;
    }
    return ctx;
}

static int kae_asym_cipher_sm2_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_SM2_ASYM_CTX *ctx = vctx;
    KAE_PKEY_ASYM_CIPHER method = get_default_sm2_asym_cipher();
    const OSSL_PARAM *p;
    EVP_MD *md;

    if (params == NULL)
        return 1;
    if (!method.set_ctx_params(ctx->soft_ctx, params))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
    if (p == NULL)
        return 1;
    md = EVP_MD_fetch(kae_soft_libctx(), p->data, "provider=default");
    if (md == NULL)
        return 0;
    hpre_sm2_cleanup(ctx->sm2_pctx);
    EVP_MD_free(ctx->sm2_pctx->sm2_md->alloc_md);
    ctx->sm2_pctx->sm2_md->md = ctx->sm2_pctx->sm2_md->alloc_md = md;
    ctx->sm2_pctx->sm2_md->md_nid = EVP_MD_get_type(md);
    ctx->sm2_pctx->sm2_md->mdsize = EVP_MD_get_size(md);
    ctx->sm2_pctx->do_soft = 0;
    return 1;
}

static int sm2_asym_init(PROV_SM2_ASYM_CTX *ctx, EC_KEY *key, const OSSL_PARAM params[], int decrypt)
{
    KAE_PKEY_ASYM_CIPHER method = get_default_sm2_asym_cipher();
    OSSL_FUNC_asym_cipher_encrypt_init_fn *init = decrypt ? method.decrypt_init : method.encrypt_init;

    if (ctx == NULL || (key == NULL && ctx->ec_key == NULL))
        return 0;
    if (!init(ctx->soft_ctx, key, params))
        return 0;
    if (key != NULL) {
        if (!EC_KEY_up_ref(key))
            return 0;
        EC_KEY_free(ctx->ec_key);
        ctx->ec_key = key;
    }
    hpre_sm2_cleanup(ctx->sm2_pctx);
    ctx->sm2_pctx->do_soft = 0;
    ctx->operation = decrypt;
    return kae_asym_cipher_sm2_set_ctx_params(ctx, params);
}

static int kae_asym_cipher_sm2_encrypt_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return sm2_asym_init(ctx, key, params, 0);
}

static int kae_asym_cipher_sm2_decrypt_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return sm2_asym_init(ctx, key, params, 1);
}

static int sm2_asym_crypt(PROV_SM2_ASYM_CTX *ctx, unsigned char *out, size_t *outlen,
    size_t outsize, const unsigned char *in, size_t inlen, int decrypt)
{
    KAE_PKEY_ASYM_CIPHER method = get_default_sm2_asym_cipher();
    OSSL_FUNC_asym_cipher_encrypt_fn *soft = decrypt ? method.decrypt : method.encrypt;
    size_t required = 0;
    int ret;

    if (ctx == NULL || ctx->ec_key == NULL || outlen == NULL || ctx->operation != decrypt)
        return 0;
    if (out == NULL)
        return soft(ctx->soft_ctx, NULL, outlen, 0, in, inlen);
    if (!soft(ctx->soft_ctx, NULL, &required, 0, in, inlen) || outsize < required)
        return 0;
    if (sm2_prepare(ctx->sm2_pctx)) {
        ret = decrypt ? hpre_sm2_decrypt(ctx, out, outlen, in, inlen) :
            hpre_sm2_encrypt(ctx, out, outlen, in, inlen);
        if (ret == 1)
            return 1;
    }
    return soft(ctx->soft_ctx, out, outlen, outsize, in, inlen);
}

static int kae_asym_cipher_sm2_encrypt(void *ctx, unsigned char *out, size_t *outlen,
    size_t outsize, const unsigned char *in, size_t inlen)
{
    return sm2_asym_crypt(ctx, out, outlen, outsize, in, inlen, 0);
}

static int kae_asym_cipher_sm2_decrypt(void *ctx, unsigned char *out, size_t *outlen,
    size_t outsize, const unsigned char *in, size_t inlen)
{
    return sm2_asym_crypt(ctx, out, outlen, outsize, in, inlen, 1);
}

static void kae_asym_cipher_sm2_freectx(void *vctx)
{
    PROV_SM2_ASYM_CTX *ctx = vctx;
    if (ctx == NULL)
        return;
    if (ctx->soft_ctx != NULL)
        get_default_sm2_asym_cipher().freectx(ctx->soft_ctx);
    sm2_ctx_free(ctx->sm2_pctx);
    EC_KEY_free(ctx->ec_key);
    OPENSSL_free(ctx);
}

static void *kae_asym_cipher_sm2_dupctx(void *vctx)
{
    PROV_SM2_ASYM_CTX *src = vctx, *dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    dst->operation = src->operation;
    dst->soft_ctx = get_default_sm2_asym_cipher().dupctx(src->soft_ctx);
    dst->sm2_pctx = sm2_ctx_dup(src->sm2_pctx);
    if (dst->soft_ctx == NULL || dst->sm2_pctx == NULL)
        goto err;
    if (src->ec_key != NULL) {
        if (!EC_KEY_up_ref(src->ec_key))
            goto err;
        dst->ec_key = src->ec_key;
    }
    return dst;
err:
    kae_asym_cipher_sm2_freectx(dst);
    return NULL;
}

static int kae_asym_cipher_sm2_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_SM2_ASYM_CTX *ctx = vctx;
    return get_default_sm2_asym_cipher().get_ctx_params(ctx->soft_ctx, params);
}

static const OSSL_PARAM *kae_asym_cipher_sm2_gettable_ctx_params(void *ctx, void *provctx)
{
    return sm2_asym_cipher_known_gettable_ctx_params;
}

static const OSSL_PARAM *kae_asym_cipher_sm2_settable_ctx_params(void *ctx, void *provctx)
{
    return sm2_asym_cipher_known_settable_ctx_params;
}

static void *kae_signature_sm2_newctx(void *provctx, const char *propq)
{
    PROV_SM2_SIGN_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    if ((ctx->sm2_pctx = sm2_ctx_new()) == NULL) {
        kae_signature_sm2_freectx(ctx);
        return NULL;
    }
    ctx->flag_compute_z_digest = 1;
    OPENSSL_strlcpy(ctx->mdname, "SM3", sizeof(ctx->mdname));
    return ctx;
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
        ret = hpre_sm2_compute_z_digest(z, smctx->sm2_md->md, psm2ctx->id, psm2ctx->id_len, psm2ctx->ec_key);
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

static void kae_signature_sm2_freectx(void *vctx)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    if (ctx == NULL)
        return;
    if (ctx->soft_ctx != NULL)
        get_default_sm2_signature().freectx(ctx->soft_ctx);
    EVP_MD_CTX_free(ctx->message_mdctx);
    sm2_ctx_free(ctx->sm2_pctx);
    EC_KEY_free(ctx->ec_key);
    OPENSSL_free(ctx->id);
    OPENSSL_free(ctx->propq);
    OPENSSL_free(ctx);
}

static void *kae_signature_sm2_dupctx(void *vctx)
{
    PROV_SM2_SIGN_CTX *src = vctx, *dst = OPENSSL_zalloc(sizeof(*dst));

    if (dst == NULL)
        return NULL;
    dst->operation = src->operation;
    dst->flag_compute_z_digest = src->flag_compute_z_digest;
    dst->z_digest_valid = src->z_digest_valid;
    memcpy(dst->z_digest, src->z_digest, sizeof(dst->z_digest));
    dst->id_set = src->id_set;
    dst->id_len = src->id_len;
    dst->aid_len = src->aid_len;
    memcpy(dst->aid_buf, src->aid_buf, sizeof(dst->aid_buf));
    dst->aid = dst->aid_buf;
    memcpy(dst->mdname, src->mdname, sizeof(dst->mdname));
    if (src->soft_ctx != NULL &&
        (dst->soft_ctx = get_default_sm2_signature().dupctx(src->soft_ctx)) == NULL)
        goto err;
    dst->sm2_pctx = sm2_ctx_dup(src->sm2_pctx);
    if (dst->sm2_pctx == NULL)
        goto err;
    if (src->ec_key != NULL) {
        if (!EC_KEY_up_ref(src->ec_key))
            goto err;
        dst->ec_key = src->ec_key;
    }
    if (src->id_len != 0 && (dst->id = OPENSSL_memdup(src->id, src->id_len)) == NULL)
        goto err;
    return dst;
err:
    kae_signature_sm2_freectx(dst);
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

static int kae_signature_sm2_get_ctx_md_params(void *vctx, OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    return EVP_MD_CTX_get_params(ctx->sm2_pctx->sm2_md->mdctx, params);
}

static const OSSL_PARAM *kae_signature_sm2_gettable_ctx_md_params(void *vctx)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    return EVP_MD_gettable_ctx_params(ctx->sm2_pctx->sm2_md->md);
}

static int kae_signature_sm2_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    return EVP_MD_CTX_set_params(ctx->sm2_pctx->sm2_md->mdctx, params);
}

static const OSSL_PARAM *kae_signature_sm2_settable_ctx_md_params(void *vctx)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    return EVP_MD_settable_ctx_params(ctx->sm2_pctx->sm2_md->md);
}
