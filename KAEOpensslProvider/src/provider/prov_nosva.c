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

#include <stdio.h>
#include <string.h>

#include <uadk/v1/wd.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/types.h>

#include "prov_nosva/prov.h"
#include "prov_nosva/internal/prov_bio.h"
#include "prov_nosva/prov_pkey.h"
#include "prov_nosva/prov_digest.h"
#include "../adapter/nosva/nosva.h"
#include "../adapter/common/kae_log.h"
#include "../adapter/nosva/async/async_poll.h"
#include "../adapter/nosva/async/async_check.h"

static const char KAE_DEFAULT_PROPERTIES[] = "provider=kae_provider";
static OSSL_PROVIDER *prov = NULL;
static OSSL_LIB_CTX *soft_libctx;
static pthread_mutex_t provider_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int provider_users;

OSSL_LIB_CTX *kae_soft_libctx(void)
{
    return soft_libctx;
}

OSSL_PROVIDER *kae_soft_provider(void)
{
    return prov;
}

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
static OSSL_FUNC_core_get_params_fn *c_get_params;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx;

struct kae_provider_params {
    char *enable_soft_offload;
} kae_params;

static int uadk_rsa_nosva;
static int uadk_sm2_nosva;

static int uadk_digest_nosva;
static int uadk_cipher_nosva;

/* offload small packets to sw */
int enable_soft_offload;

// default 0
int rsa_switch_soft = 0;

int sm2_switch_soft = 0;

int dh_switch_soft = 0;

int digest_switch_soft = 0;

int cipher_switch_soft = 0;

const OSSL_ALGORITHM kae_prov_digests[] = {
    {OSSL_DIGEST_NAME_MD5, KAE_DEFAULT_PROPERTIES, kae_md5_functions, "kae_provider md5"},
    {OSSL_DIGEST_NAME_SM3, KAE_DEFAULT_PROPERTIES, kae_sm3_functions, "kae_provider sm3"},
    {NULL, NULL, NULL}};

const OSSL_ALGORITHM kae_prov_ciphers[] = {
    {"AES-128-CBC", KAE_DEFAULT_PROPERTIES, kae_aes_128_cbc_functions, "kae_provider aes-128-cbc"},
    {"AES-192-CBC", KAE_DEFAULT_PROPERTIES, kae_aes_192_cbc_functions, "kae_provider aes-192-cbc"},
    {"AES-256-CBC", KAE_DEFAULT_PROPERTIES, kae_aes_256_cbc_functions, "kae_provider aes-256-cbc"},
    {"AES-128-ECB", KAE_DEFAULT_PROPERTIES, kae_aes_128_ecb_functions, "kae_provider aes-128-ecb"},
    {"AES-192-ECB", KAE_DEFAULT_PROPERTIES, kae_aes_192_ecb_functions, "kae_provider aes-192-ecb"},
    {"AES-256-ECB", KAE_DEFAULT_PROPERTIES, kae_aes_256_ecb_functions, "kae_provider aes-256-ecb"},
    {"AES-128-XTS", KAE_DEFAULT_PROPERTIES, kae_aes_128_xts_functions, "kae_provider aes-128-xts"},
    {"AES-256-XTS", KAE_DEFAULT_PROPERTIES, kae_aes_256_xts_functions, "kae_provider aes-256-xts"},
    {"AES-128-CTR", KAE_DEFAULT_PROPERTIES, kae_aes_128_ctr_functions, "kae_provider aes-128-ctr"},
    {"AES-192-CTR", KAE_DEFAULT_PROPERTIES, kae_aes_192_ctr_functions, "kae_provider aes-192-ctr"},
    {"AES-256-CTR", KAE_DEFAULT_PROPERTIES, kae_aes_256_ctr_functions, "kae_provider aes-256-ctr"},
    {"AES-128-OFB", KAE_DEFAULT_PROPERTIES, kae_aes_128_ofb128_functions, "kae_provider aes-128-ofb"},
    {"AES-192-OFB", KAE_DEFAULT_PROPERTIES, kae_aes_192_ofb128_functions, "kae_provider aes-192-ofb"},
    {"AES-256-OFB", KAE_DEFAULT_PROPERTIES, kae_aes_256_ofb128_functions, "kae_provider aes-256-ofb"},
    {"AES-128-CFB", KAE_DEFAULT_PROPERTIES, kae_aes_128_cfb128_functions, "kae_provider aes-128-cfb"},
    {"AES-192-CFB", KAE_DEFAULT_PROPERTIES, kae_aes_192_cfb128_functions, "kae_provider aes-192-cfb"},
    {"AES-256-CFB", KAE_DEFAULT_PROPERTIES, kae_aes_256_cfb128_functions, "kae_provider aes-256-cfb"},
    {"SM4-CBC", KAE_DEFAULT_PROPERTIES, kae_sm4_cbc_functions, "kae_provider sm4-cbc"},
    {"SM4-ECB", KAE_DEFAULT_PROPERTIES, kae_sm4_ecb_functions, "kae_provider sm4-ecb"},
    {"SM4-OFB", KAE_DEFAULT_PROPERTIES, kae_sm4_ofb128_functions, "kae_provider sm4-ofb"},
    {"SM4-CFB", KAE_DEFAULT_PROPERTIES, kae_sm4_cfb128_functions, "kae_provider sm4-cfb"},
    {"SM4-CTR", KAE_DEFAULT_PROPERTIES, kae_sm4_ctr_functions, "kae_provider sm4-ctr"},
    {NULL, NULL, NULL}};
static const OSSL_ALGORITHM *kae_prov_signature;
static const OSSL_ALGORITHM *kae_prov_keymgmt;
static const OSSL_ALGORITHM *kae_prov_asym_cipher;

static const OSSL_ALGORITHM kae_prov_keyexch[] = {
    {"DH", KAE_DEFAULT_PROPERTIES, kae_dh_keyexch_functions, "KAE DH keyexch implementation"}, {NULL, NULL, NULL}
};

static const OSSL_ALGORITHM *kae_prov_signature_query()
{
    static OSSL_ALGORITHM algs[3];
    int i = 0;

    if (uadk_sm2_nosva) {
        algs[i++] =
            (OSSL_ALGORITHM){"SM2", KAE_DEFAULT_PROPERTIES, kae_sm2_signature_functions, "kae_provider sm2_signature"};
    }
    algs[i++] =
        (OSSL_ALGORITHM){"RSA", KAE_DEFAULT_PROPERTIES, kae_rsa_signature_functions, "kae_provider rsa_signature"};
    algs[i] = (OSSL_ALGORITHM){NULL, NULL, NULL, NULL};

    return algs;
}

static const OSSL_ALGORITHM *kae_prov_keymgmt_query()
{
    static OSSL_ALGORITHM algs[4];
    int i = 0;

    if (uadk_sm2_nosva) {
        algs[i++] = (OSSL_ALGORITHM){
            "SM2", KAE_DEFAULT_PROPERTIES, kae_sm2_keymgmt_functions, "kae SM2 Keymgmt implementation."};
    }
    algs[i++] =
        (OSSL_ALGORITHM){"RSA", KAE_DEFAULT_PROPERTIES, kae_rsa_keymgmt_functions, "kae RSA Keymgmt implementation."};
    algs[i++] =
        (OSSL_ALGORITHM){"DH", KAE_DEFAULT_PROPERTIES, kae_dh_keymgmt_functions, "kae DH Keymgmt implementation."};
    algs[i] = (OSSL_ALGORITHM){NULL, NULL, NULL, NULL};

    return algs;
}

static const OSSL_ALGORITHM *kae_prov_asym_cipher_query()
{
    static OSSL_ALGORITHM algs[3];
    int i = 0;

    if (uadk_sm2_nosva) {
        algs[i++] = (OSSL_ALGORITHM){
            "SM2", KAE_DEFAULT_PROPERTIES, kae_sm2_asym_cipher_functions, "kae SM2 asym cipher implementation."};
    }
    algs[i++] = (OSSL_ALGORITHM){
        "RSA", KAE_DEFAULT_PROPERTIES, kae_rsa_asym_cipher_functions, "kae RSA asym cipher implementation."};
    algs[i] = (OSSL_ALGORITHM){NULL, NULL, NULL, NULL};

    return algs;
}

static const OSSL_ALGORITHM *kae_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
        case OSSL_OP_DIGEST:
            if (!uadk_digest_nosva)
                return NULL;
            return kae_prov_digests;
        case OSSL_OP_CIPHER:
            if (!uadk_cipher_nosva)
                return NULL;
            return kae_prov_ciphers;
        case OSSL_OP_SIGNATURE:
            return kae_prov_signature;
        case OSSL_OP_KEYMGMT:
            return kae_prov_keymgmt;
        case OSSL_OP_ASYM_CIPHER:
            return kae_prov_asym_cipher;
        case OSSL_OP_KEYEXCH:
            return kae_prov_keyexch;
        case OSSL_OP_STORE:
            /* Let the default provider own its STORE callbacks and context. */
            return NULL;
    }
    return NULL;
}

static void kae_teardown(void *provctx)
{
    struct kae_prov_ctx *ctx = (struct kae_prov_ctx *)provctx;
    if (ctx->default_provider != NULL)
        OSSL_PROVIDER_unload(ctx->default_provider);
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
    pthread_mutex_lock(&provider_lock);
    if (--provider_users == 0) {
        async_module_uninit_v1();
        kae_checking_q_sync_destroy();
        /* Free dependencies while their own method store is still alive. */
        OSSL_PROVIDER_unload(prov);
        OSSL_LIB_CTX_free(soft_libctx);
        prov = NULL;
        soft_libctx = NULL;
    }
    pthread_mutex_unlock(&provider_lock);
}

static const OSSL_DISPATCH kae_dispatch_table[] = {{OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))kae_query},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))kae_teardown},
    {0, NULL}};

int kae_get_params_from_core(const OSSL_CORE_HANDLE *handle)
{
    OSSL_PARAM core_params[2], *p = core_params;

    *p++ = OSSL_PARAM_construct_utf8_ptr("enable_soft_offload", (char **)&kae_params.enable_soft_offload, 0);

    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(handle, core_params)) {
        US_WARN("WARN: can not get parameters from core.");
        return 0;
    }

    if (kae_params.enable_soft_offload) {
        enable_soft_offload = atoi(kae_params.enable_soft_offload);
    } else {
        enable_soft_offload = 1;
    }

    return 1;
}

static void provider_init_child_at_fork_handler(void)
{
    async_module_init_v1();
}

static int kae_prov_ctx_set_core_bio_method(struct kae_prov_ctx *ctx)
{
    KAE_BIO_METHOD *core_bio;

    core_bio = ossl_bio_prov_init_bio_method();
    if (core_bio == NULL) {
        US_ERR("failed to set bio from dispatch.");
        return 0;
    }

    ctx->corebiometh = core_bio;

    return 1;
}

static void ossl_prov_core_from_dispatch(const OSSL_DISPATCH *fns)
{
    while (fns && fns->function_id != 0) {
        switch (fns->function_id) {
            case OSSL_FUNC_CORE_GETTABLE_PARAMS:
                c_gettable_params = OSSL_FUNC_core_gettable_params(fns);
                break;
            case OSSL_FUNC_CORE_GET_PARAMS:
                c_get_params = OSSL_FUNC_core_get_params(fns);
                break;
            case OSSL_FUNC_CORE_GET_LIBCTX:
                c_get_libctx = OSSL_FUNC_core_get_libctx(fns);
                break;
            default:
                /* Just ignore anything we don't understand */
                break;
        }
        fns++;
    }
}

static void kae_init_algorithms(void)
{
    int dev_num;

    rsa_switch_soft = sm2_switch_soft = dh_switch_soft = 0;
    cipher_switch_soft = digest_switch_soft = 0;
    uadk_rsa_nosva = uadk_sm2_nosva = uadk_cipher_nosva = uadk_digest_nosva = 0;

    dev_num = wd_get_available_dev_num("rsa");
    if (dev_num > 0) {
        if (!hpre_module_rsa_init()) {
            US_ERR("kae nosva rsa module init fail, switch to soft.");
            rsa_switch_soft = 1;
        } else {
            uadk_rsa_nosva = 1;
            US_DEBUG("kae nosva rsa module init success.");
        }
    } else {
        US_ERR("no available rsa dev, switch to soft.");
        rsa_switch_soft = 1;
    }

    dev_num = wd_get_available_dev_num("dh");
    dh_switch_soft = dev_num <= 0 || !hpre_module_dh_init();
    if (dh_switch_soft)
        US_WARN("no available dh hardware, switch to soft.");

    dev_num = wd_get_available_dev_num("digest");
    if (dev_num > 0) {
        if (!sec_digest_module_init()) {
            US_ERR("kae nosva digest module init fail, switch to soft.");
            digest_switch_soft = 1;
        } else {
            uadk_digest_nosva = 1;
            US_DEBUG("kae nosva digest module init success.");
        }
    } else {
        US_ERR("no available digest dev, switch to soft.");
        digest_switch_soft = 1;
    }

    dev_num = wd_get_available_dev_num("cipher");
    if (dev_num > 0) {
        if (!sec_cipher_module_init()) {
            US_ERR("kae nosva cipher module init fail, switch to soft.");
            cipher_switch_soft = 1;
        } else {
            uadk_cipher_nosva = 1;
            US_DEBUG("kae nosva cipher module init success.");
        }
    } else {
        US_ERR("no available cipher dev, switch to soft.");
        cipher_switch_soft = 1;
    }

    async_module_init_v1();
    kae_prov_signature = kae_prov_signature_query();
    kae_prov_keymgmt = kae_prov_keymgmt_query();
    kae_prov_asym_cipher = kae_prov_asym_cipher_query();
}

static void kae_register_atfork(void)
{
    pthread_atfork(NULL, NULL, provider_init_child_at_fork_handler);
}

static int kae_prefer_in_default_context(struct kae_prov_ctx *ctx)
{
    OSSL_LIB_CTX *appctx = OSSL_LIB_CTX_get0_global_default();
    OPENSSL_CORE_CTX *owner;
    int marked, rand_configured;

    /* Apply the CLI defaults only to the global context that loaded KAE. */
    if (appctx == NULL || c_get_libctx == NULL)
        return 1;
    owner = c_get_libctx(ctx->handle);
    if (owner == NULL)
        owner = (OPENSSL_CORE_CTX *)OSSL_LIB_CTX_set0_default(NULL);
    if (owner != (OPENSSL_CORE_CTX *)appctx ||
        EVP_default_properties_is_fips_enabled(appctx))
        return 1;

    ctx->default_provider = OSSL_PROVIDER_load(appctx, "default");
    if (ctx->default_provider == NULL)
        return 0;

    /*
     * An OpenSSL thread-local DRBG is shared by the ASYNC jobs on that
     * thread. Its cipher must finish without suspending the DRBG operation.
     */
    marked = ERR_set_mark();
    rand_configured = RAND_set_DRBG_type(appctx, NULL, "provider=default", NULL, NULL);
    if (marked)
        ERR_pop_to_mark();
    else if (!rand_configured)
        ERR_clear_error();

    /* If the application's DRBG is already in use, keep implicit selection unchanged. */
    if (!rand_configured)
        return 1;
    return EVP_set_default_properties(appctx, "?provider=kae_provider");
}

int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *oin, const OSSL_DISPATCH **out, void **provctx)
{
    static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;
    struct kae_prov_ctx *ctx;

    if (oin == NULL)
        return 0;
    ossl_prov_bio_from_dispatch(oin);
    kae_debug_init_log();

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        US_ERR("failed to alloc ctx.");
        return 0;
    }

    ctx->handle = handle;
    if (!kae_prov_ctx_set_core_bio_method(ctx))
        goto err;
    pthread_mutex_lock(&provider_lock);
    ossl_prov_core_from_dispatch(oin);
    if (!kae_get_params_from_core(handle))
        goto unlock;
    if (provider_users == 0) {
        soft_libctx = OSSL_LIB_CTX_new();
        if (soft_libctx == NULL || (prov = OSSL_PROVIDER_load(soft_libctx, "default")) == NULL) {
            OSSL_LIB_CTX_free(soft_libctx);
            soft_libctx = NULL;
            goto unlock;
        }
        kae_init_algorithms();
    }
    ctx->libctx = soft_libctx;
    provider_users++;
    if (!kae_prefer_in_default_context(ctx)) {
        pthread_mutex_unlock(&provider_lock);
        kae_teardown(ctx);
        return 0;
    }
    pthread_mutex_unlock(&provider_lock);
    pthread_once(&atfork_once, kae_register_atfork);
    *provctx = (void *)ctx;
    *out = kae_dispatch_table;

    return 1;
unlock:
    pthread_mutex_unlock(&provider_lock);
err:
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
    return 0;
}
