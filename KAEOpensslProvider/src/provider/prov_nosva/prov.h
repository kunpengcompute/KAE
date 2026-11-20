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

#ifndef KAE_PROVIDER_H
#define KAE_PROVIDER_H
#include <openssl/core_dispatch.h>

#define FUNC_MAX_NUM 32

#define KAE_P_SUCCESS 1
#define KAE_P_FAIL 0

#define OPENSSL_SUCCESS (1)
#define OPENSSL_FAIL (0)

struct ossl_provider_st {
    /* Flag bits */
    unsigned int flag_initialized : 1;
    unsigned int flag_activated : 1;
    unsigned int flag_fallback : 1; /* Can be used as fallback */

    /* Getting and setting the flags require synchronization */
    void *flag_lock;

    /* OpenSSL library side data */
    /* Crypto reference counter */
    int refcnt;
    /* Lock for the ref counter */
    void *refcnt_lock;
    int activatecnt;
    char *name;
    char *path;
    void *module;
    OSSL_provider_init_fn *init_function;

    STACK_OF(INFOPAIR) * parameters;
    OSSL_LIB_CTX *libctx;            /* The library context this instance is in */
    struct provider_store_st *store; /* The store this instance belongs to */
#ifndef FIPS_MODULE
    /*
     * In the FIPS module inner provider, this isn't needed, since the
     * error upcalls are always direct calls to the outer provider.
     */
    int error_lib; /* ERR library number, one for each provider */
#ifndef OPENSSL_NO_ERR
    char *error_strings; /* Copy of what the provider gives us */
#endif
#endif

    /* Provider side functions */
    OSSL_FUNC_provider_teardown_fn *teardown;
    OSSL_FUNC_provider_gettable_params_fn *gettable_params;
    OSSL_FUNC_provider_get_params_fn *get_params;
    OSSL_FUNC_provider_get_capabilities_fn *get_capabilities;
    OSSL_FUNC_provider_self_test_fn *self_test;
    OSSL_FUNC_provider_query_operation_fn *query_operation;
    OSSL_FUNC_provider_unquery_operation_fn *unquery_operation;

    /*
     * Cache of bit to indicate of query_operation() has been called on
     * a specific operation or not.
     */
    unsigned char *operation_bits;
    size_t operation_bits_sz;
    void *opbits_lock;

#ifndef FIPS_MODULE
    /* Whether this provider is the child of some other provider */
    const OSSL_CORE_HANDLE *handle;
    unsigned int ischild : 1;
#endif

    /* Provider side data */
    void *provctx;
    const OSSL_DISPATCH *dispatch;
};

typedef struct bio_method_st {
    int type;
    char *name;
    int (*bwrite)(BIO *bio, const char *data, size_t datal, size_t *written);
    int (*bwrite_old)(BIO *bio, const char *data, int datal);
    int (*bread)(BIO *bio, char *data, size_t datal, size_t *read);
    int (*bread_old)(BIO *bio, char *data, int datal);
    int (*bputs)(BIO *bio, const char *buf);
    int (*bgets)(BIO *bio, char *buf, int size);
    long (*ctrl)(BIO *bio, int cmd, long larg, void *parg);
    int (*create)(BIO *bio);
    int (*destroy)(BIO *bio);
    long (*callback_ctrl)(BIO *bio, int cmd, BIO_info_cb *fp);
} KAE_BIO_METHOD;

typedef struct kae_prov_ctx {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    KAE_BIO_METHOD *corebiometh;
} KAE_PROV_CTX;

static inline OSSL_LIB_CTX *prov_libctx_of(struct kae_prov_ctx *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->libctx;
}

extern const OSSL_DISPATCH kae_md5_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm3_functions[FUNC_MAX_NUM];

extern const OSSL_DISPATCH kae_aes_128_cbc_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_192_cbc_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_256_cbc_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_128_cts_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_192_cts_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_256_cts_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_128_ecb_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_192_ecb_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_256_ecb_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_128_xts_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_256_xts_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_128_ctr_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_192_ctr_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_256_ctr_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_128_ofb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_192_ofb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_256_ofb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_128_cfb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_192_cfb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_aes_256_cfb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm4_cbc_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm4_ecb_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm4_ofb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm4_cfb128_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm4_ctr_functions[FUNC_MAX_NUM];

extern const OSSL_DISPATCH kae_rsa_signature_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_rsa_keymgmt_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_rsa_asym_cipher_functions[FUNC_MAX_NUM];

extern const OSSL_DISPATCH kae_dh_keymgmt_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_dh_keyexch_functions[FUNC_MAX_NUM];

extern const OSSL_DISPATCH kae_sm2_keymgmt_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm2_signature_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH kae_sm2_asym_cipher_functions[FUNC_MAX_NUM];

#endif
