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
#include <openssl/sha.h>

#include "prov.h"
#include "prov_pkey.h"
#include "../../adapter/common/kae_log.h"
#include "../../adapter/common/kae_types.h"
#include "../../adapter/nosva/algorithm/pkey/hpre_rsa.h"

KAE_PKEY_KEYMGMT_DESCR(rsa, RSA);
KAE_PKEY_SIGNATURE_DESCR(rsa, RSA);
KAE_PKEY_ASYM_CIPHER_DESCR(rsa, RSA);

static void kae_rsa_clear_flags(RSA *r, int flags)
{
    r->flags &= ~flags;
}

static int kae_rsa_test_flags(const RSA *r, int flags)
{
    return r->flags & flags;
}

static void kae_rsa_set_flags(RSA *r, int flags)
{
    r->flags |= flags;
}

static int kae_rsa_size(const RSA *r)
{
    return BN_num_bytes(r->n);
}

static int setup_tbuf(PROV_RSA_SIG_CTX *ctx)
{
    if (ctx->tbuf != NULL) {
        return OPENSSL_SUCCESS;
    }

    if ((ctx->tbuf = OPENSSL_malloc(RSA_size(ctx->rsa))) == NULL) {
        US_WARN("failed to alloc tbuf.");
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static void clean_tbuf(PROV_RSA_SIG_CTX *ctx)
{
    if (ctx->tbuf != NULL)
        OPENSSL_cleanse(ctx->tbuf, kae_rsa_size(ctx->rsa));
}

static void free_tbuf(PROV_RSA_SIG_CTX *ctx)
{
    clean_tbuf(ctx);
    OPENSSL_free(ctx->tbuf);
    ctx->tbuf = NULL;
}

static RSA *ossl_rsa_new_with_ctx(OSSL_LIB_CTX *libctx)
{
    RSA *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        US_WARN("failed to alloc rsa.");
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        US_WARN("failed to new crypto thread lock.");
        OPENSSL_free(ret);
        return NULL;
    }

    ret->libctx = libctx;

    return ret;
}

static int rsa_gencb(int p, int n, BN_GENCB *cb)
{
    struct rsa_gen_ctx *gctx = BN_GENCB_get_arg(cb);
    OSSL_PARAM params[] = {OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END};

    params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);
    return gctx->cb(params, gctx->cbarg);
}

static void *kae_keymgmt_rsa_new(void *provctx)
{
    if (!get_default_rsa_keymgmt().new_fun) {
        US_WARN("failed to get rsa keymgmt new function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().new_fun(provctx);
}

static void kae_keymgmt_rsa_free(void *keydata)
{
    if (!get_default_rsa_keymgmt().free) {
        US_WARN("failed to get sm2 keymgmt free function.");
        return;
    }

    get_default_rsa_keymgmt().free(keydata);
}

static int kae_keymgmt_rsa_get_params(void *key, OSSL_PARAM params[])
{
    if (!get_default_rsa_keymgmt().get_params) {
        US_WARN("failed to get rsa keymgmt get params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().get_params(key, params);
}

static const OSSL_PARAM *kae_keymgmt_rsa_gettable_params(void *provctx)
{
    if (!get_default_rsa_keymgmt().gettable_params) {
        US_WARN("failed to get rsa keymgmt gettable params function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().gettable_params(provctx);
}

static int kae_keymgmt_rsa_set_params(void *key, const OSSL_PARAM params[])
{
    if (!get_default_rsa_keymgmt().set_params) {
        US_WARN("failed to get rsa keymgmt set params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().set_params(key, params);
}

static const OSSL_PARAM *kae_keymgmt_rsa_settable_params(ossl_unused void *provctx)
{
    if (!get_default_rsa_keymgmt().settable_params) {
        US_WARN("failed to get rsa keymgmt settable params function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().settable_params(provctx);
}

static void *kae_keymgmt_rsa_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    if (!get_default_rsa_keymgmt().gen_init) {
        US_WARN("failed to get rsa keymgmt gen init function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().gen_init(provctx, selection, params);
}

static int kae_keymgmt_rsa_gen_set_template(void *genctx, void *templates)
{
    if (!get_default_rsa_keymgmt().gen_set_template) {
        US_WARN("failed to get rsa keymgmt gen set template function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().gen_set_template(genctx, templates);
}

static int kae_keymgmt_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    if (!get_default_rsa_keymgmt().gen_set_params) {
        US_WARN("failed to get rsa keymgmt gen set params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().gen_set_params(genctx, params);
}

static const OSSL_PARAM *kae_keymgmt_rsa_gen_settable_params(ossl_unused void *genctx, ossl_unused void *provctx)
{
    if (!get_default_rsa_keymgmt().gen_settable_params) {
        US_WARN("failed to get rsa keymgmt gen settable params function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().gen_settable_params(genctx, provctx);
}

static void *kae_keymgmt_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct rsa_gen_ctx *gctx = genctx;
    RSA *rsa = NULL;
    BN_GENCB *gencb = NULL;
    int ret;

    if (gctx == NULL) {
        US_WARN("invalid: rsa gen gctx is NULL.");
        return NULL;
    }

    rsa = ossl_rsa_new_with_ctx(gctx->libctx);
    if (rsa == NULL)
        return NULL;

    gctx->cb = osslcb;
    gctx->cbarg = cbarg;
    gencb = BN_GENCB_new();
    if (gencb != NULL)
        BN_GENCB_set(gencb, rsa_gencb, genctx);

    ret = hpre_rsa_keygen(rsa, (int)gctx->nbits, gctx->pub_exp, gencb);
    if (ret == KAE_CRYPTO_FAIL) {
        BN_GENCB_free(gencb);
        kae_keymgmt_rsa_free(rsa);
        goto soft;
    }

    kae_rsa_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
    kae_rsa_set_flags(rsa, gctx->rsa_type);
    BN_GENCB_free(gencb);

    return rsa;

soft:
    US_WARN("kae prov rsa keygen failed, switch to execute openssl software calculation.\n");
    if (!get_default_rsa_keymgmt().gen) {
        US_WARN("failed to get rsa keymgmt gen function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().gen(genctx, osslcb, cbarg);
}

static void kae_keymgmt_rsa_gen_cleanup(void *genctx)
{
    if (!get_default_rsa_keymgmt().gen_cleanup) {
        US_WARN("failed to get rsa keymgmt gen cleanup function.");
        return;
    }

    get_default_rsa_keymgmt().gen_cleanup(genctx);
}

static void *kae_keymgmt_rsa_load(const void *reference, size_t reference_sz)
{
    if (!get_default_rsa_keymgmt().load) {
        US_WARN("failed to get rsa keymgmt  function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().load(reference, reference_sz);
}

static int kae_keymgmt_rsa_has(const void *keydata, int selection)
{
    if (!get_default_rsa_keymgmt().has) {
        US_WARN("failed to get rsa keymgmt has function.");
    }
        return KAE_P_FAIL;

    return get_default_rsa_keymgmt().has(keydata, selection);
}

static int kae_keymgmt_rsa_validate(const void *keydata, int selection, int checktype)
{
    if (!get_default_rsa_keymgmt().validate) {
        US_WARN("failed to get rsa keymgmt validate function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().validate(keydata, selection, checktype);
}

static int kae_keymgmt_rsa_match(const void *keydata1, const void *keydata2, int selection)
{
    if (!get_default_rsa_keymgmt().match) {
        US_WARN("failed to get rsa keymgmt match function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().match(keydata1, keydata2, selection);
}

static int kae_keymgmt_rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    if (!get_default_rsa_keymgmt().import) {
        US_WARN("failed to get rsa keymgmt import function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().import(keydata, selection, params);
}

static const OSSL_PARAM *kae_keymgmt_rsa_import_types(int selection)
{
    if (!get_default_rsa_keymgmt().import_types) {
        US_WARN("failed to get rsa keymgmt import types function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().import_types(selection);
}

static int kae_keymgmt_rsa_export(void *keydata, int selection, OSSL_CALLBACK *param_callback, void *cbarg)
{
    if (!get_default_rsa_keymgmt().export_fun) {
        US_WARN("failed to get rsa keymgmt export fun function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_keymgmt().export_fun(keydata, selection, param_callback, cbarg);
}

static const OSSL_PARAM *kae_keymgmt_rsa_export_types(int selection)
{
    if (!get_default_rsa_keymgmt().export_types) {
        US_WARN("failed to get rsa keymgmt  function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().export_types(selection);
}

static void *kae_keymgmt_rsa_dup(const void *keydata_from, int selection)
{
    if (!get_default_rsa_keymgmt().dup) {
        US_WARN("failed to get rsa keymgmt dup function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().dup(keydata_from, selection);
}

static const char *kae_keymgmt_rsa_query_operation_name(int operation_id)
{
    if (!get_default_rsa_keymgmt().query_operation_name) {
        US_WARN("failed to get rsa keymgmt query operation function.");
        return NULL;
    }

    return get_default_rsa_keymgmt().query_operation_name(operation_id);
}

static void *kae_asym_cipher_rsa_newctx(void *provctx)
{
    PROV_RSA_ASYM_CTX *priv = NULL;

    priv = OPENSSL_zalloc(sizeof(*priv));
    if (priv == NULL) {
        US_WARN("failed to alloc rsa asym ctx.");
        return NULL;
    }

    priv->libctx = prov_libctx_of(provctx);

    return priv;
}

static int kae_rsa_asym_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[], int operation)
{
    PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;

    priv->rsa = vrsa;
    priv->operation = operation;

    switch (kae_rsa_test_flags(priv->rsa, RSA_FLAG_TYPE_MASK)) {
        case RSA_FLAG_TYPE_RSA:
            priv->pad_mode = RSA_PKCS1_PADDING;
            break;
        case RSA_FLAG_TYPE_RSASSAPSS:
            priv->pad_mode = RSA_PKCS1_PSS_PADDING;
            break;
        default:
            US_WARN("invalid: unknown rsa flag type.");
            return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int kae_asym_cipher_rsa_encrypt_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
    return kae_rsa_asym_init(vprsactx, vrsa, params, EVP_PKEY_OP_ENCRYPT);
}

static int kae_asym_cipher_rsa_encrypt(
    void *vprsactx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;
    size_t len;
    int ret;

    if (out == NULL) {
        len = kae_rsa_size(priv->rsa);
        if (len == 0) {
            US_WARN("invalid: rsa size is zero.");
            return OPENSSL_FAIL;
        }
        *outlen = len;
        return OPENSSL_SUCCESS;
    }

    ret = hpre_rsa_public_encrypt(inlen, in, out, priv->rsa, priv->pad_mode);
    if (ret == KAE_CRYPTO_FAIL) {
        goto soft;
    }

    *outlen = ret;

    return OPENSSL_SUCCESS;

soft:
    US_WARN("kae prov rsa encrypt failed, switch to execute openssl software calculation.\n");
    if (!get_default_rsa_asym_cipher().encrypt) {
        US_WARN("failed to get rsa asym encrypt function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_asym_cipher().encrypt(vprsactx, out, outlen, outsize, in, inlen);
}

static int kae_asym_cipher_rsa_decrypt_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
    return kae_rsa_asym_init(vprsactx, vrsa, params, EVP_PKEY_OP_DECRYPT);
}

static int kae_asym_cipher_rsa_decrypt(
    void *vprsactx, unsigned char *out, size_t *outlen, size_t outsize, const unsigned char *in, size_t inlen)
{
    PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;
    size_t len = kae_rsa_size(priv->rsa);
    int ret;

    if (out == NULL) {
        if (len == 0) {
            US_WARN("invalid: rsa size is zero.");
            return OPENSSL_FAIL;
        }
        *outlen = len;
        return OPENSSL_SUCCESS;
    }

    if (outsize < len) {
        US_WARN("invalid: outsize is  size is zero.");
        return OPENSSL_FAIL;
    }

    ret = hpre_rsa_private_decrypt(inlen, in, out, priv->rsa, priv->pad_mode);
    if (ret == KAE_CRYPTO_FAIL) {
        goto soft;
    }

    *outlen = ret;

    return OPENSSL_SUCCESS;

soft:
    US_WARN("kae prov rsa decrypt failed, switch to execute openssl software calculation.\n");
    if (!get_default_rsa_asym_cipher().decrypt) {
        US_WARN("failed to get rsa asym decrypt function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_asym_cipher().decrypt(vprsactx, out, outlen, outsize, in, inlen);
}

static void kae_asym_cipher_rsa_freectx(void *vprsactx)
{
    PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;

    if (priv == NULL)
        return;

    OPENSSL_free(priv);
}

static void *kae_asym_cipher_rsa_dupctx(void *vprsactx)
{
    if (!get_default_rsa_asym_cipher().dupctx) {
        US_WARN("failed to get rsa asym dupctx function.");
    }
        return KAE_P_FAIL;
    return get_default_rsa_asym_cipher().dupctx(vprsactx);
}

static int kae_asym_cipher_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
    if (!get_default_rsa_asym_cipher().get_ctx_params) {
        US_WARN("failed to get rsa asym get ctx params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_asym_cipher().get_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *kae_asym_cipher_rsa_gettable_ctx_params(void *vprsactx, void *provctx)
{
    if (!get_default_rsa_asym_cipher().gettable_ctx_params) {
        US_WARN("failed to get rsa asym gettable ctx params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_asym_cipher().gettable_ctx_params(vprsactx, provctx);
}

static int kae_asym_cipher_rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
    if (!get_default_rsa_asym_cipher().set_ctx_params) {
        US_WARN("failed to get rsa asym set ctx params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_asym_cipher().set_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *kae_asym_cipher_rsa_settable_ctx_params(void *vprsactx, void *provctx)
{
    if (!get_default_rsa_asym_cipher().settable_ctx_params) {
        US_WARN("failed to get rsa asym settable ctx params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_asym_cipher().settable_ctx_params(vprsactx, provctx);
}

static void *kae_signature_rsa_newctx(void *provctx, const char *propq)
{
    PROV_RSA_SIG_CTX *priv = OPENSSL_zalloc(sizeof(PROV_RSA_SIG_CTX));
    char *propq_copy = NULL;

    if (priv == NULL) {
        US_WARN("invalid: signature ctx is NULL.");
        goto err;
    }

    if (propq != NULL) {
        propq_copy = OPENSSL_strdup(propq);
        if (propq_copy == NULL) {
            US_WARN("failed to dup propq.");
            goto err;
        }
    }

    priv->libctx = prov_libctx_of(provctx);
    priv->flag_allow_md = 1;
    priv->propq = propq_copy;
    return priv;

err:
    OPENSSL_free(priv);
    return NULL;
}

static int kae_rsa_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[], int operation)
{
    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;

    if (priv == NULL || vrsa == NULL) {
        US_WARN("invalid: sig ctx or rsa is NULL.");
        return OPENSSL_FAIL;
    }

    priv->rsa = vrsa;
    priv->operation = operation;

    /* Maximum for sign, auto for verify */
    priv->saltlen = RSA_PSS_SALTLEN_AUTO;
    priv->min_saltlen = -1;

    switch (kae_rsa_test_flags(priv->rsa, RSA_FLAG_TYPE_MASK)) {
        case RSA_FLAG_TYPE_RSA:
            priv->pad_mode = RSA_PKCS1_PADDING;
            break;
        case RSA_FLAG_TYPE_RSASSAPSS:
            priv->pad_mode = RSA_PKCS1_PSS_PADDING;
            break;
        default:
            US_WARN("invalid: unknown rsa flag type.");
            return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int kae_signature_rsa_sign_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
    return kae_rsa_init(vprsactx, vrsa, params, EVP_PKEY_OP_SIGN);
}

static int kae_signature_rsa_verify_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
    return kae_rsa_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFY);
}

#define KAE_ASN1_SEQUENCE 0x30
#define ASN1_OCTET_STRING_ 0x04
#define ASN1_NULL 0x05
#define ASN1_OID 0x06
/* SHA OIDs are of the form: (2 16 840 1 101 3 4 2 |n|) */
#define ENCODE_DIGESTINFO_SHA(name, n, sz)                                     \
    static const unsigned char digestinfo_##name##_der[] = {KAE_ASN1_SEQUENCE, \
        0x11 + sz,                                                             \
        KAE_ASN1_SEQUENCE,                                                     \
        0x0d,                                                                  \
        ASN1_OID,                                                              \
        0x09,                                                                  \
        2 * 40 + 16,                                                           \
        0x86,                                                                  \
        0x48,                                                                  \
        1,                                                                     \
        101,                                                                   \
        3,                                                                     \
        4,                                                                     \
        2,                                                                     \
        n,                                                                     \
        ASN1_NULL,                                                             \
        0x00,                                                                  \
        ASN1_OCTET_STRING_,                                                    \
        sz};

/* MD2, MD4 and MD5 OIDs are of the form: (1 2 840 113549 2 |n|) */
#define ENCODE_DIGESTINFO_MD(name, n, sz)                                      \
    static const unsigned char digestinfo_##name##_der[] = {KAE_ASN1_SEQUENCE, \
        0x10 + sz,                                                             \
        KAE_ASN1_SEQUENCE,                                                     \
        0x0c,                                                                  \
        ASN1_OID,                                                              \
        0x08,                                                                  \
        1 * 40 + 2,                                                            \
        0x86,                                                                  \
        0x48,                                                                  \
        0x86,                                                                  \
        0xf7,                                                                  \
        0x0d,                                                                  \
        2,                                                                     \
        n,                                                                     \
        ASN1_NULL,                                                             \
        0x00,                                                                  \
        ASN1_OCTET_STRING_,                                                    \
        sz};

/* SHA-1 (1 3 14 3 2 26) */
static const unsigned char digestinfo_sha1_der[] = {KAE_ASN1_SEQUENCE,
    0x0d + SHA_DIGEST_LENGTH,
    KAE_ASN1_SEQUENCE,
    0x09,
    ASN1_OID,
    0x05,
    1 * 40 + 3,
    14,
    3,
    2,
    26,
    ASN1_NULL,
    0x00,
    ASN1_OCTET_STRING_,
    SHA_DIGEST_LENGTH};
ENCODE_DIGESTINFO_SHA(sha256, 0x01, SHA256_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha384, 0x02, SHA384_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha512, 0x03, SHA512_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha224, 0x04, SHA224_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha512_224, 0x05, SHA224_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha512_256, 0x06, SHA256_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_224, 0x07, SHA224_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_256, 0x08, SHA256_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_384, 0x09, SHA384_DIGEST_LENGTH)
ENCODE_DIGESTINFO_SHA(sha3_512, 0x0a, SHA512_DIGEST_LENGTH)

#define MD_CASE(name)                           \
    case NID_##name:                            \
        *len = sizeof(digestinfo_##name##_der); \
        return digestinfo_##name##_der;

#define MD_NID_CASE(name, sz) \
    case NID_##name:          \
        return sz;

const unsigned char *kae_rsa_digestinfo_encoding(int md_nid, size_t *len)
{
    switch (md_nid) {
        MD_CASE(sha1)
        MD_CASE(sha224)
        MD_CASE(sha256)
        MD_CASE(sha384)
        MD_CASE(sha512)
        MD_CASE(sha512_224)
        MD_CASE(sha512_256)
        MD_CASE(sha3_224)
        MD_CASE(sha3_256)
        MD_CASE(sha3_384)
        MD_CASE(sha3_512)
        default:
            return NULL;
    }
}

static int digest_sz_from_nid(int nid)
{
    switch (nid) {
        MD_NID_CASE(sha1, SHA_DIGEST_LENGTH)
        MD_NID_CASE(sha224, SHA224_DIGEST_LENGTH)
        MD_NID_CASE(sha256, SHA256_DIGEST_LENGTH)
        MD_NID_CASE(sha384, SHA384_DIGEST_LENGTH)
        MD_NID_CASE(sha512, SHA512_DIGEST_LENGTH)
        MD_NID_CASE(sha512_224, SHA224_DIGEST_LENGTH)
        MD_NID_CASE(sha512_256, SHA256_DIGEST_LENGTH)
        MD_NID_CASE(sha3_224, SHA224_DIGEST_LENGTH)
        MD_NID_CASE(sha3_256, SHA256_DIGEST_LENGTH)
        MD_NID_CASE(sha3_384, SHA384_DIGEST_LENGTH)
        MD_NID_CASE(sha3_512, SHA512_DIGEST_LENGTH)
        default:
            return 0;
    }
}

int encode_pkcs1(unsigned char **out, size_t *out_len, int type, const unsigned char *m, size_t m_len)
{
    size_t di_prefix_len, dig_info_len;
    const unsigned char *di_prefix;
    unsigned char *dig_info;

    if (type == NID_undef) {
        US_WARN("invalid: unknown nid.");
        return 0;
    }
    di_prefix = kae_rsa_digestinfo_encoding(type, &di_prefix_len);
    if (di_prefix == NULL) {
        US_WARN("invalid: unknown digest info encoding.");
        return 0;
    }
    dig_info_len = di_prefix_len + m_len;
    dig_info = OPENSSL_malloc(dig_info_len);
    if (dig_info == NULL) {
        US_WARN("failed to alloc digest info.");
        return 0;
    }
    memcpy(dig_info, di_prefix, di_prefix_len);
    memcpy(dig_info + di_prefix_len, m, m_len);

    *out = dig_info;
    *out_len = dig_info_len;
    return 1;
}

#define SSL_SIG_LENGTH 36
int KAE_RSA_sign(
    int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
    int encrypt_len, ret = 0;
    size_t encoded_len = 0;
    unsigned char *tmps = NULL;
    const unsigned char *encoded = NULL;

    /* Compute the encoded digest. */
    if (type == NID_md5_sha1) {
        /*
         * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
         * earlier. It has no DigestInfo wrapper but otherwise is
         * RSASSA-PKCS1-v1_5.
         */
        if (m_len != SSL_SIG_LENGTH) {
            US_WARN("invalid: message length is not equal to sig length.");
            return 0;
        }
        encoded_len = SSL_SIG_LENGTH;
        encoded = m;
    } else {
        if (!encode_pkcs1(&tmps, &encoded_len, type, m, m_len))
            goto err;
        encoded = tmps;
    }

    if (encoded_len + RSA_PKCS1_PADDING_SIZE > (size_t)kae_rsa_size(rsa)) {
        goto err;
    }
    encrypt_len = hpre_rsa_private_encrypt((int)encoded_len, encoded, sigret, rsa, RSA_PKCS1_PADDING);
    if (encoded_len == KAE_CRYPTO_FAIL) {
        ret = KAE_CRYPTO_FAIL;
        goto err;
    }
    if (encrypt_len <= 0)
        goto err;

    *siglen = encrypt_len;
    ret = 1;

err:
    OPENSSL_clear_free(tmps, encoded_len);
    return ret;
}
#define rsa_pss_restricted(prsactx) (prsactx->min_saltlen != -1)

int KAE_RSA_sign_ASN1_OCTET_STRING(
    int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
    ASN1_OCTET_STRING sig;
    int i, j, ret = 1;
    unsigned char *p, *s;

    sig.type = V_ASN1_OCTET_STRING;
    sig.length = m_len;
    sig.data = (unsigned char *)m;

    i = i2d_ASN1_OCTET_STRING(&sig, NULL);
    j = kae_rsa_size(rsa);
    if (i > (j - RSA_PKCS1_PADDING_SIZE)) {
        return OPENSSL_FAIL;
    }
    s = OPENSSL_malloc((unsigned int)j + 1);
    if (s == NULL) {
        return OPENSSL_FAIL;
    }
    p = s;
    i2d_ASN1_OCTET_STRING(&sig, &p);
    i = hpre_rsa_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
    if (i == KAE_CRYPTO_FAIL) {
        ret = i;
        goto end;
    }

    if (i <= 0)
        ret = 0;
    else
        *siglen = i;

end:
    OPENSSL_clear_free(s, (unsigned int)j + 1);
    return ret;
}

static size_t rsa_get_md_size(const PROV_RSA_SIG_CTX *priv)
{
    if (priv->md != NULL)
        return EVP_MD_size(priv->md);
    return 0;
}

static int kae_signature_rsa_sign(
    void *vprsactx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
    size_t rsasize = kae_rsa_size(priv->rsa);
    int ret;

    if (sig == NULL) {
        *siglen = rsasize;
        return OPENSSL_SUCCESS;
    }

    if (sigsize < rsasize) {
        US_WARN("invalid: sigsize is less than rsasize.");
        return OPENSSL_FAIL;
    }

    size_t mdsize = rsa_get_md_size(priv);
    if (mdsize == 0) {
        ret = hpre_rsa_private_encrypt(tbslen, tbs, sig, priv->rsa, priv->pad_mode);
        if (ret == KAE_CRYPTO_FAIL) {
            goto soft;
        }
    } else {
        if (tbslen != mdsize) {
            goto err;
        }
        if (EVP_MD_is_a(priv->md, OSSL_DIGEST_NAME_MDC2)) {
            unsigned int sltmp;

            if (priv->pad_mode != RSA_PKCS1_PADDING) {
                goto err;
            }
            ret = KAE_RSA_sign_ASN1_OCTET_STRING(0, tbs, tbslen, sig, &sltmp, priv->rsa);
            if (ret == KAE_CRYPTO_FAIL) {
                goto soft;
            }

            if (ret <= 0) {
                goto err;
            }
            ret = sltmp;
            goto end;
        }

        switch (priv->pad_mode) {
            case RSA_X931_PADDING:
                if ((size_t)kae_rsa_size(priv->rsa) < tbslen + 1) {
                    goto err;
                }
                if (!setup_tbuf(priv)) {
                    goto err;
                }
                memcpy(priv->tbuf, tbs, tbslen);
                priv->tbuf[tbslen] = RSA_X931_hash_id(priv->mdnid);
                ret = hpre_rsa_private_encrypt(tbslen + 1, priv->tbuf, sig, priv->rsa, RSA_X931_PADDING);
                clean_tbuf(priv);
                if (ret == KAE_CRYPTO_FAIL) {
                    goto soft;
                }
                break;

            case RSA_PKCS1_PADDING: {
                unsigned int sltmp;
                ret = KAE_RSA_sign(priv->mdnid, tbs, tbslen, sig, &sltmp, priv->rsa);
                if (ret == KAE_CRYPTO_FAIL) {
                    goto soft;
                }
                if (ret <= 0) {
                    goto err;
                }
                ret = sltmp;
            } break;

            case RSA_PKCS1_PSS_PADDING:
                /* Check PSS restrictions */
                if (rsa_pss_restricted(priv)) {
                    switch (priv->saltlen) {
                        case RSA_PSS_SALTLEN_DIGEST:
                            if (priv->min_saltlen > EVP_MD_size(priv->md)) {
                                goto err;
                            }
                            /* FALLTHRU */
                        default:
                            if (priv->saltlen >= 0 && priv->saltlen < priv->min_saltlen) {
                                goto err;
                            }
                            break;
                    }
                }
                if (!setup_tbuf(priv))
                    goto err;
                if (!RSA_padding_add_PKCS1_PSS_mgf1(
                        priv->rsa, priv->tbuf, tbs, priv->md, priv->mgf1_md, priv->saltlen)) {
                    goto err;
                }
                ret = hpre_rsa_private_encrypt(kae_rsa_size(priv->rsa), priv->tbuf, sig, priv->rsa, RSA_NO_PADDING);
                clean_tbuf(priv);
                if (ret == KAE_CRYPTO_FAIL) {
                    goto soft;
                }
                break;

            default:

                goto err;
        }
    }

    if (ret == KAE_P_FAIL) {
        goto soft;
    }

    if (ret < 0)
        return ret;

    *siglen = ret;

end:
    return OPENSSL_SUCCESS;

err:
    return OPENSSL_FAIL;

soft:
    US_WARN("kae prov rsa sign failed, switch to execute openssl software calculation.\n");
    if (!get_default_rsa_signature().sign) {
        US_WARN("failed to get rsa signature sign function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().sign(vprsactx, sig, siglen, sigsize, tbs, tbslen);
}

int KAE_RSA_verify(int type, const unsigned char *m, unsigned int m_len, unsigned char *rm, size_t *prm_len,
    const unsigned char *sigbuf, size_t siglen, RSA *rsa)
{
    int len, ret = 0;
    size_t decrypt_len, encoded_len = 0;
    unsigned char *decrypt_buf = NULL, *encoded = NULL;

    if (siglen != (size_t)kae_rsa_size(rsa)) {
        US_WARN("invalid: sig len is not equal to rsa size.");
        return ret;
    }

    /* Recover the encoded digest. */
    decrypt_buf = OPENSSL_malloc(siglen);
    if (decrypt_buf == NULL) {
        goto err;
    }

    len = hpre_rsa_public_decrypt((int)siglen, sigbuf, decrypt_buf, rsa, RSA_PKCS1_PADDING);
    if (len == KAE_CRYPTO_FAIL) {
        OPENSSL_clear_free(decrypt_buf, siglen);
        return KAE_CRYPTO_FAIL;
    }
    if (len <= 0)
        goto err;
    decrypt_len = len;

    if (type == NID_md5_sha1) {
        /*
         * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
         * earlier. It has no DigestInfo wrapper but otherwise is
         * RSASSA-PKCS1-v1_5.
         */
        if (decrypt_len != SSL_SIG_LENGTH) {
            goto err;
        }

        if (rm != NULL) {
            memcpy(rm, decrypt_buf, SSL_SIG_LENGTH);
            *prm_len = SSL_SIG_LENGTH;
        } else {
            if (m_len != SSL_SIG_LENGTH) {
                goto err;
            }

            if (memcmp(decrypt_buf, m, SSL_SIG_LENGTH) != 0) {
                goto err;
            }
        }
    } else if (type == NID_mdc2 && decrypt_len == 2 + 16 && decrypt_buf[0] == 0x04 && decrypt_buf[1] == 0x10) {
        /*
         * Oddball MDC2 case: signature can be OCTET STRING. check for correct
         * tag and length octets.
         */
        if (rm != NULL) {
            memcpy(rm, decrypt_buf + 2, 16);
            *prm_len = 16;
        } else {
            if (m_len != 16) {
                goto err;
            }

            if (memcmp(m, decrypt_buf + 2, 16) != 0) {
                goto err;
            }
        }
    } else {
        /*
         * If recovering the digest, extract a digest-sized output from the end
         * of |decrypt_buf| for |encode_pkcs1|, then compare the decryption
         * output as in a standard verification.
         */
        if (rm != NULL) {
            len = digest_sz_from_nid(type);

            if (len <= 0)
                goto err;
            m_len = (unsigned int)len;
            if (m_len > decrypt_len) {
                goto err;
            }
            m = decrypt_buf + decrypt_len - m_len;
        }

        /* Construct the encoded digest and ensure it matches. */
        if (!encode_pkcs1(&encoded, &encoded_len, type, m, m_len))
            goto err;

        if (encoded_len != decrypt_len || memcmp(encoded, decrypt_buf, encoded_len) != 0) {
            goto err;
        }

        /* Output the recovered digest. */
        if (rm != NULL) {
            memcpy(rm, m, m_len);
            *prm_len = m_len;
        }
    }

    ret = 1;

err:
    OPENSSL_clear_free(encoded, encoded_len);
    OPENSSL_clear_free(decrypt_buf, siglen);
    return ret;
}

static int kae_signature_rsa_verify(
    void *vprsactx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
    size_t rslen = 0;
    int ret = 0;

    if (priv->md != NULL) {
        switch (priv->pad_mode) {
            case RSA_PKCS1_PADDING:
                ret = KAE_RSA_verify(priv->mdnid, tbs, tbslen, NULL, NULL, sig, siglen, priv->rsa);
                if (ret == KAE_CRYPTO_FAIL) {
                    US_WARN("kae rsa verify failed.");
                    goto soft;
                }
                if (!ret) {
                    return OPENSSL_FAIL;
                }
                return OPENSSL_SUCCESS;
            case RSA_X931_PADDING:
                if (!setup_tbuf(priv))
                    return OPENSSL_FAIL;
                ret = kae_signature_rsa_verify_recover(priv, priv->tbuf, &rslen, 0, sig, siglen);
                if (ret <= 0)
                    return OPENSSL_FAIL;
                break;
            case RSA_PKCS1_PSS_PADDING: {
                size_t mdsize;

                /*
                 * We need to check this for the RSA_verify_PKCS1_PSS_mgf1()
                 * call
                 */
                mdsize = rsa_get_md_size(priv);
                if (tbslen != mdsize) {
                    US_ERR("RSA verify fail, tbslen is not equal to mdsize");
                    return OPENSSL_FAIL;
                }
                if (!setup_tbuf(priv))
                    return OPENSSL_FAIL;

                ret = hpre_rsa_public_decrypt(siglen, sig, priv->tbuf, priv->rsa, RSA_NO_PADDING);
                if (ret == KAE_CRYPTO_FAIL) {
                    goto soft;
                }
                if (ret <= 0) {
                    return OPENSSL_FAIL;
                }
                ret =
                    RSA_padding_add_PKCS1_PSS_mgf1(priv->rsa, priv->tbuf, tbs, priv->md, priv->mgf1_md, priv->saltlen);
                if (ret <= 0) {
                    return OPENSSL_FAIL;
                }
                return OPENSSL_SUCCESS;
            }
            default:
                US_ERR("RSA verify fail, only X.931, PKCS#1 v1.5 or PSS padding allowed");
                return OPENSSL_FAIL;
        }
    } else {
        if (!setup_tbuf(priv))
            return OPENSSL_FAIL;
        ret = hpre_rsa_public_decrypt(siglen, sig, priv->tbuf, priv->rsa, priv->pad_mode);
        if (ret == KAE_CRYPTO_FAIL) {
            goto soft;
        }
        if (ret <= 0) {
            return OPENSSL_FAIL;
        }
        rslen = (size_t)ret;
    }

    if ((rslen != tbslen) || memcmp(tbs, priv->tbuf, rslen))
        return OPENSSL_FAIL;

    return OPENSSL_SUCCESS;

soft:
    US_DEBUG("kae prov rsa verify failed, switch to execute openssl software calculation");
    if (!get_default_rsa_signature().verify) {
        US_WARN("failed to get rsa signature verify function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().verify(vprsactx, sig, siglen, tbs, tbslen);
}

static int kae_signature_rsa_verify_recover_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
    if (!get_default_rsa_signature().verify_recover_init) {
        US_WARN("failed to get rsa signature verify recover init function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().verify_recover_init(vprsactx, vrsa, params);
}

static int kae_signature_rsa_verify_recover(
    void *vprsactx, unsigned char *rout, size_t *routlen, size_t routsize, const unsigned char *sig, size_t siglen)
{
    // if (!get_default_rsa_signature().verify_recover) {
    //     US_WARN("failed to get rsa signature verify recover function.");
    //     return KAE_P_FAIL;
    // }

    // return get_default_rsa_signature().verify_recover(vprsactx, rout, routlen, routsize, sig, siglen);

    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
    int ret;

    if (rout == NULL) {
        *routlen = RSA_size(priv->rsa);
        return 1;
    }

    if (priv->md != NULL) {
        switch (priv->pad_mode) {
        case RSA_X931_PADDING:
            if (!setup_tbuf(priv))
                return 0;
            ret = hpre_rsa_public_decrypt(siglen, sig, priv->tbuf, priv->rsa,
                                     RSA_X931_PADDING);
            if (ret < 1) {
                return 0;
            }
            ret--;
            if (priv->tbuf[ret] != RSA_X931_hash_id(priv->mdnid)) {
                return 0;
            }
            if (ret != EVP_MD_get_size(priv->md)) {
                return 0;
            }

            *routlen = ret;
            if (rout != priv->tbuf) {
                if (routsize < (size_t)ret) {
                    return 0;
                }
                memcpy(rout, priv->tbuf, ret);
            }
            break;

        case RSA_PKCS1_PADDING:
            {
                size_t sltmp;

                ret = KAE_RSA_verify(priv->mdnid, NULL, 0, rout, &sltmp,
                                      sig, siglen, priv->rsa);
                if (ret <= 0) {
                    return 0;
                }
                ret = sltmp;
            }
            break;

        default:
            US_ERR("rsa verify unsupport padding.");
            return 0;
        }
    } else {
        ret = hpre_rsa_public_decrypt(siglen, sig, rout, priv->rsa,
                                 priv->pad_mode);
        if (ret < 0) {
            return 0;
        }
    }
    *routlen = ret;
    return 1;
}
static int kae_signature_rsa_digest_sign_init(void *vprsactx, const char *mdname, void *vrsa, const OSSL_PARAM params[])
{
    if (!get_default_rsa_signature().digest_sign_init) {
        US_WARN("failed to get rsa signature digest sign init function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().digest_sign_init(vprsactx, mdname, vrsa, params);
}

static int kae_signature_rsa_digest_sign_update(void *vprsactx, const unsigned char *data, size_t datalen)
{
    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;

    if (priv == NULL || priv->mdctx == NULL) {
        US_WARN("invalid: sig ctx or mdctx is NULL.");
        return OPENSSL_FAIL;
    }

    return EVP_DigestUpdate(priv->mdctx, data, datalen);
}

static int kae_signature_rsa_digest_sign_final(void *vprsactx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (priv == NULL || priv->mdctx == NULL) {
        US_WARN("invalid: sig ctx or mdctx is NULL.");
        return OPENSSL_FAIL;
    }

    priv->flag_allow_md = 1;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to rsa_sign.
     */
    if (sig != NULL) {
        /*
         * The digests used here are all known (see rsa_get_md_nid()), so they
         * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
         */
        if (!EVP_DigestFinal_ex(priv->mdctx, digest, &dlen)) {
            US_WARN("rsa sign digest final failed.");
            return OPENSSL_FAIL;
        }
    }

    return kae_signature_rsa_sign(vprsactx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int kae_signature_rsa_digest_verify_init(
    void *vprsactx, const char *mdname, void *vrsa, const OSSL_PARAM params[])
{
    if (!get_default_rsa_signature().digest_verify_init) {
        US_WARN("failed to get rsa signature digest verify init function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().digest_verify_init(vprsactx, mdname, vrsa, params);
}

static int kae_signature_rsa_digest_verify_update(void *vprsactx, const unsigned char *data, size_t datalen)
{
    if (!get_default_rsa_signature().digest_verify_update) {
        US_WARN("failed to get rsa signature digest verify update function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().digest_verify_update(vprsactx, data, datalen);
}

static int kae_signature_rsa_digest_verify_final(void *vprsactx, const unsigned char *sig, size_t siglen)
{
    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (priv == NULL || priv->mdctx == NULL) {
        US_WARN("invalid: sig ctx or md ctx is NULL.");
        return OPENSSL_FAIL;
    }

    priv->flag_allow_md = 1;

    /*
     * The digests used here are all known (see rsa_get_md_nid()), so they
     * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
     */
    if (!EVP_DigestFinal_ex(priv->mdctx, digest, &dlen)) {
        US_WARN("rsa verify digest final failed.");
        return OPENSSL_FAIL;
    }

    return kae_signature_rsa_verify(vprsactx, sig, siglen, digest, (size_t)dlen);
}

static void kae_signature_rsa_freectx(void *vprsactx)
{
    PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;

    if (priv == NULL) {
        US_WARN("invalid: sig ctx is NULL.");
        return;
    }

    free_tbuf(priv);
    OPENSSL_clear_free(priv, sizeof(*priv));
}

static void *kae_signature_rsa_dupctx(void *vprsactx)
{
    if (!get_default_rsa_signature().dupctx) {
        US_WARN("failed to get rsa signature dupctx function.");
        return NULL;
    }

    return get_default_rsa_signature().dupctx(vprsactx);
}

static int kae_signature_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
    if (!get_default_rsa_signature().get_ctx_params) {
        US_WARN("failed to get rsa signature get ctx params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().get_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *kae_signature_rsa_gettable_ctx_params(ossl_unused void *vprsactx, ossl_unused void *provctx)
{
    if (!get_default_rsa_signature().gettable_ctx_params) {
        US_WARN("failed to get rsa signature gettable ctx params function.");
        return NULL;
    }

    return get_default_rsa_signature().gettable_ctx_params(vprsactx, provctx);
}

static int kae_signature_rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{

    if (!get_default_rsa_signature().set_ctx_params) {
        US_WARN("failed to get rsa signature set ctx params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().set_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *kae_signature_rsa_settable_ctx_params(void *vprsactx, void *provctx)
{
    if (!get_default_rsa_signature().settable_ctx_params) {
        US_WARN("failed to get rsa signature settable ctx params function.");
        return NULL;
    }

    return get_default_rsa_signature().settable_ctx_params(vprsactx, provctx);
}

static int kae_signature_rsa_get_ctx_md_params(void *vprsactx, OSSL_PARAM *params)
{
    if (!get_default_rsa_signature().get_ctx_md_params) {
        US_WARN("failed to get rsa signature get ctx md params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().get_ctx_md_params(vprsactx, params);
}

static const OSSL_PARAM *kae_signature_rsa_gettable_ctx_md_params(void *vprsactx)
{
    if (!get_default_rsa_signature().gettable_ctx_md_params) {
        US_WARN("failed to get rsa signature  function.");
        return NULL;
    }

    return get_default_rsa_signature().gettable_ctx_md_params(vprsactx);
}

static int kae_signature_rsa_set_ctx_md_params(void *vprsactx, const OSSL_PARAM params[])
{
    if (!get_default_rsa_signature().set_ctx_md_params) {
        US_WARN("failed to get rsa signature set ctx md params function.");
        return KAE_P_FAIL;
    }

    return get_default_rsa_signature().set_ctx_md_params(vprsactx, params);
}

static const OSSL_PARAM *kae_signature_rsa_settable_ctx_md_params(void *vprsactx)
{
    if (!get_default_rsa_signature().settable_ctx_md_params) {
        US_WARN("failed to get rsa signature settable ctx md params function.");
        return NULL;
    }

    return get_default_rsa_signature().settable_ctx_md_params(vprsactx);
}