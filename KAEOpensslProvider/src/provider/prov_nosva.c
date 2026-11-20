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
#include <openssl/evp.h>
#include <openssl/provider.h>
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

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
static OSSL_FUNC_core_get_params_fn *c_get_params;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx;

struct kae_provider_params {
    char *enable_soft_offload;
} kae_params;

static int uadk_rsa_nosva;
static int uadk_sm2_nosva;
// static int uadk_dh_nosva;
static int uadk_digest_nosva;
static int uadk_cipher_nosva;

/* offload small packets to sw */
int enable_soft_offload;

// default 0
int rsa_switch_soft = 0;

int sm2_switch_soft = 0;

// int dh_switch_soft = 0;

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
    // algs[i++] =
    //     (OSSL_ALGORITHM){"DH", KAE_DEFAULT_PROPERTIES, kae_dh_keymgmt_functions, "kae DH Keymgmt implementation."};
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
    static int prov_init;

    if (!prov)
        prov = (OSSL_PROVIDER *)OSSL_PROVIDER_load(NULL, "default");
    if (!prov_init) {
        prov_init = 1;
        /* kae_provider takes the highest priority
         * and overwrite the openssl.cnf property.
         */
        EVP_set_default_properties(NULL, "?provider=kae_provider");
    }

    *no_cache = 0;
    switch (operation_id) {
        case OSSL_OP_DIGEST:
            if (!uadk_digest_nosva)
                return prov->query_operation(provctx, operation_id, no_cache);
            return kae_prov_digests;
        case OSSL_OP_CIPHER:
            if (!uadk_cipher_nosva)
                return prov->query_operation(provctx, operation_id, no_cache);
            return kae_prov_ciphers;
        case OSSL_OP_SIGNATURE:
            return kae_prov_signature;
        case OSSL_OP_KEYMGMT:
            return kae_prov_keymgmt;
        case OSSL_OP_ASYM_CIPHER:
            return kae_prov_asym_cipher;
        // case OSSL_OP_KEYEXCH:
        //     return kae_prov_keyexch;
        case OSSL_OP_STORE:
            return prov->query_operation(provctx, operation_id, no_cache);
    }
    return NULL;
}

static void kae_teardown(void *provctx)
{
    struct kae_prov_ctx *ctx = (struct kae_prov_ctx *)provctx;
    OPENSSL_free(ctx);

    BIO_meth_free(ctx->corebiometh);
    kae_checking_q_sync_destroy();
    OSSL_PROVIDER_unload(prov);
    async_poll_task_free_v1();
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

int OSSL_provider_init(
    const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *oin, const OSSL_DISPATCH **out, void **provctx)
{
    struct kae_prov_ctx *ctx;
    int ret;
    int dev_num;

    if (oin == NULL) {
        US_ERR("failed to get dispatch in.");
        return 0;
    }

    ossl_prov_bio_from_dispatch(oin);
    ossl_prov_core_from_dispatch(oin);

    kae_debug_init_log();

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

    // dev_num = wd_get_available_dev_num("sm2");
    // if (dev_num > 0) {
    //     if (!hpre_module_sm2_init()) {
    //         US_ERR("kae nosva sm2 module init fail, switch to soft.");
    //         sm2_switch_soft = 1;
    //     } else {
    //         uadk_sm2_nosva = 1;
    //         US_DEBUG("kae nosva sm2 module init success.\n");
    //     }
    // } else {
    //     US_ERR("no available sm2 dev, switch to soft.");
    //     sm2_switch_soft = 1;
    // }

    // dev_num = wd_get_available_dev_num("dh");
    // if (dev_num > 0) {
    //     if (!hpre_module_dh_init()) {
    //         US_ERR("kae nosva dh module init fail, switch to soft.");
    //         dh_switch_soft = 1;
    //     } else {
    //         uadk_dh_nosva = 1;
    //         US_DEBUG("kae nosva dh module init success.");
    //     }
    // } else {
    //     US_ERR("no available dh dev, switch to soft.");
    //     dh_switch_soft = 1;
    // }

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

    /* get parameters from kae_provider.cnf */
    if (!kae_get_params_from_core(handle))
        return 0;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        US_ERR("failed to alloc ctx.");
        return 0;
    }

    /* Set handle from core to get core functions */
    ctx->handle = handle;
    ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

    ret = kae_prov_ctx_set_core_bio_method(ctx);
    if (!ret)
        return 0;

    async_module_init_v1();

    pthread_atfork(NULL, NULL, provider_init_child_at_fork_handler);

    kae_prov_signature = kae_prov_signature_query();
    kae_prov_keymgmt = kae_prov_keymgmt_query();
    kae_prov_asym_cipher = kae_prov_asym_cipher_query();
    *provctx = (void *)ctx;
    *out = kae_dispatch_table;

    return 1;
}