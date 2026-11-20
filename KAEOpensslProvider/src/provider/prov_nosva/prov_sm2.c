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
static OSSL_FUNC_signature_digest_sign_fn kae_signature_sm2_digest_sign;
static OSSL_FUNC_signature_digest_verify_fn kae_signature_sm2_digest_verify;
KAE_PKEY_SIGNATURE_DESCR_EX(sm2, SM2,
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))kae_signature_sm2_digest_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))kae_signature_sm2_digest_verify},);
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

static int kae_signature_sm2_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    const OSSL_PARAM *p;
    void *id = NULL;
    size_t idlen = 0, mdsize;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && (p->data_type != OSSL_PARAM_UTF8_STRING ||
        !EVP_MD_is_a(ctx->sm2_pctx->sm2_md->md, p->data)))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &mdsize) || mdsize != SM3_DIGEST_LENGTH))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p != NULL) {
        if (!ctx->flag_compute_z_digest || p->data_size >= UINT16_MAX / 8 ||
            !OSSL_PARAM_get_octet_string(p, &id, 0, &idlen))
            return 0;
        OPENSSL_free(ctx->id);
        ctx->id = id;
        ctx->id_len = idlen;
        ctx->id_set = 1;
        ctx->z_digest_valid = 0;
    }
    return 1;
}

static int sm2_sign_init(PROV_SM2_SIGN_CTX *ctx, EC_KEY *key, const OSSL_PARAM params[], int verify)
{
    if (ctx == NULL || (key == NULL && ctx->ec_key == NULL))
        return 0;
    if (key != NULL) {
        if (!EC_KEY_up_ref(key))
            return 0;
        hpre_sm2_cleanup(ctx->sm2_pctx);
        EC_KEY_free(ctx->ec_key);
        ctx->ec_key = key;
    }
    if (ctx->soft_ctx != NULL) {
        get_default_sm2_signature().freectx(ctx->soft_ctx);
        ctx->soft_ctx = NULL;
    }
    ctx->sm2_pctx->do_soft = 0;
    ctx->flag_compute_z_digest = 1;
    ctx->z_digest_valid = 0;
    ctx->operation = verify;
    return kae_signature_sm2_set_ctx_params(ctx, params);
}

static int kae_signature_sm2_sign_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return sm2_sign_init(ctx, key, params, 0);
}

static int kae_signature_sm2_verify_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return sm2_sign_init(ctx, key, params, 1);
}

/* Raw fallback consumes the digest already computed with the caller's SM2 ID. */
static int sm2_signature_prepare_soft(PROV_SM2_SIGN_CTX *ctx)
{
    KAE_PKEY_SIGNATURE method = get_default_sm2_signature();
    OSSL_FUNC_signature_sign_init_fn *init = ctx->operation ? method.verify_init : method.sign_init;

    if (ctx->soft_ctx != NULL)
        return 1;
    if (method.newctx == NULL || init == NULL ||
        (ctx->soft_ctx = method.newctx(OSSL_PROVIDER_get0_provider_ctx(method.prov), "provider=default")) == NULL)
        return 0;
    if (!init(ctx->soft_ctx, ctx->ec_key, NULL)) {
        method.freectx(ctx->soft_ctx);
        ctx->soft_ctx = NULL;
        return 0;
    }
    return 1;
}

static int kae_signature_sm2_sign(void *vctx, unsigned char *sig, size_t *siglen,
    size_t sigsize, const unsigned char *digest, size_t digestlen)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    int size;

    if (ctx == NULL || ctx->ec_key == NULL || siglen == NULL || ctx->operation != 0)
        return 0;
    size = ECDSA_size(ctx->ec_key);
    if (size <= 0)
        return 0;
    if (sig == NULL) {
        *siglen = size;
        return 1;
    }
    if (sigsize < (size_t)size || digestlen != SM3_DIGEST_LENGTH)
        return 0;
    if (sm2_prepare(ctx->sm2_pctx) && hpre_sm2_sign(ctx, sig, siglen, digest, digestlen) == 1)
        return 1;
    if (!sm2_signature_prepare_soft(ctx))
        return 0;
    return get_default_sm2_signature().sign(ctx->soft_ctx, sig, siglen, sigsize, digest, digestlen);
}

static int kae_signature_sm2_verify(void *vctx, const unsigned char *sig, size_t siglen,
    const unsigned char *digest, size_t digestlen)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    if (ctx == NULL || ctx->ec_key == NULL || ctx->operation != 1 || digestlen != SM3_DIGEST_LENGTH)
        return 0;
    if (sm2_prepare(ctx->sm2_pctx) && hpre_sm2_verify(ctx, sig, siglen, digest, digestlen) == 1)
        return 1;
    if (!sm2_signature_prepare_soft(ctx))
        return 0;
    return get_default_sm2_signature().verify(ctx->soft_ctx, sig, siglen, digest, digestlen);
}

static int kae_signature_sm2_verify_recover_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return 0;
}

static int kae_signature_sm2_verify_recover(void *ctx, unsigned char *out, size_t *outlen,
    size_t outsize, const unsigned char *sig, size_t siglen)
{
    return 0;
}

static int sm2_digest_init(PROV_SM2_SIGN_CTX *ctx, const char *mdname, EC_KEY *key,
    const OSSL_PARAM params[], int verify)
{
    WPACKET pkt;
    unsigned char *aid;
    if (ctx == NULL || (mdname != NULL && !EVP_MD_is_a(ctx->sm2_pctx->sm2_md->md, mdname)) ||
        !sm2_sign_init(ctx, key, params, verify))
        return 0;
    ctx->aid_len = 0;
    if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf)) &&
        ossl_DER_w_algorithmIdentifier_SM2_with_MD(&pkt, -1, ctx->ec_key, NID_sm3) &&
        WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &ctx->aid_len);
        aid = WPACKET_get_curr(&pkt);
        memmove(ctx->aid_buf, aid, ctx->aid_len);
    }
    WPACKET_cleanup(&pkt);
    ctx->aid = ctx->aid_buf;
    return EVP_DigestInit_ex2(ctx->sm2_pctx->sm2_md->mdctx, ctx->sm2_pctx->sm2_md->md, NULL);
}

static int kae_signature_sm2_digest_sign_init(void *ctx, const char *mdname, void *key,
    const OSSL_PARAM params[])
{
    return sm2_digest_init(ctx, mdname, key, params, 0);
}

static int kae_signature_sm2_digest_verify_init(void *ctx, const char *mdname, void *key,
    const OSSL_PARAM params[])
{
    return sm2_digest_init(ctx, mdname, key, params, 1);
}

static int sm2_get_z_digest(PROV_SM2_SIGN_CTX *ctx)
{
    if (ctx->z_digest_valid)
        return 1;
    if (ctx->ec_key == NULL || !hpre_sm2_compute_z_digest(ctx->z_digest,
        ctx->sm2_pctx->sm2_md->md, ctx->id, ctx->id_len, ctx->ec_key))
        return 0;
    ctx->z_digest_valid = 1;
    return 1;
}

static int sm2_digest_z(PROV_SM2_SIGN_CTX *ctx)
{
    if (!ctx->flag_compute_z_digest)
        return 1;
    if (!sm2_get_z_digest(ctx) || !EVP_DigestUpdate(ctx->sm2_pctx->sm2_md->mdctx,
        ctx->z_digest, sizeof(ctx->z_digest)))
        return 0;
    ctx->flag_compute_z_digest = 0;
    return 1;
}

/* Preserve the message state without duplicating the hardware session. */
static int sm2_message_digest(PROV_SM2_SIGN_CTX *ctx, const unsigned char *data,
    size_t size, unsigned char *digest, unsigned int *digestlen)
{
    if (ctx->message_mdctx == NULL && (ctx->message_mdctx = EVP_MD_CTX_new()) == NULL)
        return 0;
    if (!EVP_MD_CTX_copy_ex(ctx->message_mdctx, ctx->sm2_pctx->sm2_md->mdctx))
        return 0;
    if (ctx->flag_compute_z_digest && (!sm2_get_z_digest(ctx) ||
        !EVP_DigestUpdate(ctx->message_mdctx, ctx->z_digest, sizeof(ctx->z_digest))))
        return 0;
    return EVP_DigestUpdate(ctx->message_mdctx, data, size) &&
        EVP_DigestFinal_ex(ctx->message_mdctx, digest, digestlen);
}

static int kae_signature_sm2_digest_sign(void *vctx, unsigned char *sig, size_t *siglen,
    size_t sigsize, const unsigned char *data, size_t size)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    unsigned char digest[SM3_DIGEST_LENGTH];
    unsigned int digestlen = 0;

    if (sig == NULL)
        return kae_signature_sm2_sign(ctx, NULL, siglen, sigsize, NULL, 0);
    if (ctx == NULL || ctx->operation != 0 ||
        !sm2_message_digest(ctx, data, size, digest, &digestlen))
        return 0;
    return kae_signature_sm2_sign(ctx, sig, siglen, sigsize, digest, digestlen);
}

static int kae_signature_sm2_digest_verify(void *vctx, const unsigned char *sig,
    size_t siglen, const unsigned char *data, size_t size)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    unsigned char digest[SM3_DIGEST_LENGTH];
    unsigned int digestlen = 0;

    if (ctx == NULL || ctx->operation != 1 ||
        !sm2_message_digest(ctx, data, size, digest, &digestlen))
        return 0;
    return kae_signature_sm2_verify(ctx, sig, siglen, digest, digestlen);
}

static int kae_signature_sm2_digest_sign_update(void *vctx, const unsigned char *data, size_t len)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    return sm2_digest_z(ctx) && EVP_DigestUpdate(ctx->sm2_pctx->sm2_md->mdctx, data, len);
}

static int kae_signature_sm2_digest_verify_update(void *ctx, const unsigned char *data, size_t len)
{
    return kae_signature_sm2_digest_sign_update(ctx, data, len);
}

static int kae_signature_sm2_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    unsigned char digest[SM3_DIGEST_LENGTH];
    unsigned int len = 0;
    if (sig == NULL)
        return kae_signature_sm2_sign(ctx, NULL, siglen, sigsize, NULL, 0);
    if (!sm2_digest_z(ctx) || !EVP_DigestFinal_ex(ctx->sm2_pctx->sm2_md->mdctx, digest, &len))
        return 0;
    return kae_signature_sm2_sign(ctx, sig, siglen, sigsize, digest, len);
}

static int kae_signature_sm2_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    unsigned char digest[SM3_DIGEST_LENGTH];
    unsigned int len = 0;
    if (!sm2_digest_z(ctx) || !EVP_DigestFinal_ex(ctx->sm2_pctx->sm2_md->mdctx, digest, &len))
        return 0;
    return kae_signature_sm2_verify(ctx, sig, siglen, digest, len);
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

static int kae_signature_sm2_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_SM2_SIGN_CTX *ctx = vctx;
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SM3"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SM3_DIGEST_LENGTH))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, ctx->aid_buf, ctx->aid_len))
        return 0;
    return 1;
}

static const OSSL_PARAM *kae_signature_sm2_gettable_ctx_params(void *ctx, void *provctx)
{
    return sm2_sig_known_gettable_ctx_params;
}

static const OSSL_PARAM *kae_signature_sm2_settable_ctx_params(void *ctx, void *provctx)
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
