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
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>
#include <openssl/types.h>
#include "prov.h"

enum {
	KEYMGMT_SM2 = 0x0, 
	KEYMGMT_MAX = 0x6 
};

enum {
	SIGNATURE_SM2 = 0x0,
	SIGNATURE_MAX = 0x3
};

struct curve_param {
    /* Prime */
    BIGNUM *p;
    /* ECC coefficient 'a' */
    BIGNUM *a;
    /* ECC coefficient 'b' */
    BIGNUM *b;
    /* Base point */
    const EC_POINT *g;
    /* Order of base point */
    const BIGNUM *order;
};

struct ec_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *group_name;
    char *encoding;
    char *pt_format;
    char *group_check;
    char *field_type;
    BIGNUM *p, *a, *b, *order, *cofactor;
    unsigned char *gen, *seed;
    size_t gen_len, seed_len;
    int selection;
    int ecdh_mode;
    EC_GROUP *gen_group;
};

typedef struct {
    /* libcrypto internal */
    int id;

    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
    void *lock;

    /* Constructor(s), destructor, information */
    OSSL_FUNC_keymgmt_new_fn *new_fun;
    OSSL_FUNC_keymgmt_free_fn *free;
    OSSL_FUNC_keymgmt_get_params_fn *get_params;
    OSSL_FUNC_keymgmt_gettable_params_fn *gettable_params;
    OSSL_FUNC_keymgmt_set_params_fn *set_params;
    OSSL_FUNC_keymgmt_settable_params_fn *settable_params;

    /* Generation, a complex constructor */
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init;
    OSSL_FUNC_keymgmt_gen_set_template_fn *gen_set_template;
    OSSL_FUNC_keymgmt_gen_set_params_fn *gen_set_params;
    OSSL_FUNC_keymgmt_gen_settable_params_fn *gen_settable_params;
    OSSL_FUNC_keymgmt_gen_fn *gen;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup;
    OSSL_FUNC_keymgmt_load_fn *load;

    /* Key object checking */
    OSSL_FUNC_keymgmt_query_operation_name_fn *query_operation_name;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_validate_fn *validate;
    OSSL_FUNC_keymgmt_match_fn *match;

    /* Import and export routines */
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_import_types_fn *import_types;
    OSSL_FUNC_keymgmt_export_fn *export_fun;
    OSSL_FUNC_keymgmt_export_types_fn *export_types;
    OSSL_FUNC_keymgmt_dup_fn *dup;
} KAE_PKEY_KEYMGMT;

#define KAE_PKEY_KEYMGMT_DESCR(nm, alg)                                                                        \
    static OSSL_FUNC_keymgmt_new_fn kae_keymgmt_##nm##_new;                                                    \
    static OSSL_FUNC_keymgmt_free_fn kae_keymgmt_##nm##_free;                                                  \
    static OSSL_FUNC_keymgmt_get_params_fn kae_keymgmt_##nm##_get_params;                                      \
    static OSSL_FUNC_keymgmt_gettable_params_fn kae_keymgmt_##nm##_gettable_params;                            \
    static OSSL_FUNC_keymgmt_set_params_fn kae_keymgmt_##nm##_set_params;                                      \
    static OSSL_FUNC_keymgmt_settable_params_fn kae_keymgmt_##nm##_settable_params;                            \
    static OSSL_FUNC_keymgmt_gen_init_fn kae_keymgmt_##nm##_gen_init;                                          \
    static OSSL_FUNC_keymgmt_gen_set_template_fn kae_keymgmt_##nm##_gen_set_template;                          \
    static OSSL_FUNC_keymgmt_gen_set_params_fn kae_keymgmt_##nm##_gen_set_params;                              \
    static OSSL_FUNC_keymgmt_gen_settable_params_fn kae_keymgmt_##nm##_gen_settable_params;                    \
    static OSSL_FUNC_keymgmt_gen_fn kae_keymgmt_##nm##_gen;                                                    \
    static OSSL_FUNC_keymgmt_gen_cleanup_fn kae_keymgmt_##nm##_gen_cleanup;                                    \
    static OSSL_FUNC_keymgmt_load_fn kae_keymgmt_##nm##_load;                                                  \
    static OSSL_FUNC_keymgmt_has_fn kae_keymgmt_##nm##_has;                                                    \
    static OSSL_FUNC_keymgmt_validate_fn kae_keymgmt_##nm##_validate;                                          \
    static OSSL_FUNC_keymgmt_match_fn kae_keymgmt_##nm##_match;                                                \
    static OSSL_FUNC_keymgmt_import_fn kae_keymgmt_##nm##_import;                                              \
    static OSSL_FUNC_keymgmt_import_types_fn kae_keymgmt_##nm##_import_types;                                  \
    static OSSL_FUNC_keymgmt_export_fn kae_keymgmt_##nm##_export;                                              \
    static OSSL_FUNC_keymgmt_export_types_fn kae_keymgmt_##nm##_export_types;                                  \
    static OSSL_FUNC_keymgmt_dup_fn kae_keymgmt_##nm##_dup;                                                    \
    static OSSL_FUNC_keymgmt_query_operation_name_fn kae_keymgmt_##nm##_query_operation_name;                  \
    static KAE_PKEY_KEYMGMT get_default_##nm##_keymgmt(void)                                                   \
    {                                                                                                          \
        static KAE_PKEY_KEYMGMT s_keymgmt;                                                                     \
        static int initilazed;                                                                                 \
                                                                                                               \
        if (!initilazed) {                                                                                     \
            KAE_PKEY_KEYMGMT *keymgmt = (KAE_PKEY_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, #alg, "provider=default"); \
                                                                                                               \
            if (keymgmt) {                                                                                     \
                s_keymgmt = *keymgmt;                                                                          \
                EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);                                                      \
                initilazed = 1;                                                                                \
            } else {                                                                                           \
                fprintf(stderr, "failed to EVP_KEYMGMT_fetch default provider\n");                             \
            }                                                                                                  \
        }                                                                                                      \
        return s_keymgmt;                                                                                      \
    }                                                                                                          \
    const OSSL_DISPATCH kae_##nm##_keymgmt_functions[] = {                                                     \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))kae_keymgmt_##nm##_new},                                       \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kae_keymgmt_##nm##_free},                                     \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))kae_keymgmt_##nm##_get_params},                         \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))kae_keymgmt_##nm##_gettable_params},               \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))kae_keymgmt_##nm##_set_params},                         \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))kae_keymgmt_##nm##_settable_params},               \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))kae_keymgmt_##nm##_gen_init},                             \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))kae_keymgmt_##nm##_gen_set_template},             \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))kae_keymgmt_##nm##_gen_set_params},                 \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))kae_keymgmt_##nm##_gen_settable_params},       \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kae_keymgmt_##nm##_gen},                                       \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kae_keymgmt_##nm##_gen_cleanup},                       \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kae_keymgmt_##nm##_load},                                     \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kae_keymgmt_##nm##_has},                                       \
        {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))kae_keymgmt_##nm##_validate},                             \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))kae_keymgmt_##nm##_match},                                   \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kae_keymgmt_##nm##_import},                                 \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))kae_keymgmt_##nm##_import_types},                     \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kae_keymgmt_##nm##_export},                                 \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))kae_keymgmt_##nm##_export_types},                     \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))kae_keymgmt_##nm##_dup},                                       \
        {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))kae_keymgmt_##nm##_query_operation_name},     \
        {0, NULL}}

typedef struct {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
    void *lock;

    OSSL_FUNC_asym_cipher_newctx_fn *newctx;
    OSSL_FUNC_asym_cipher_encrypt_init_fn *encrypt_init;
    OSSL_FUNC_asym_cipher_encrypt_fn *encrypt;
    OSSL_FUNC_asym_cipher_decrypt_init_fn *decrypt_init;
    OSSL_FUNC_asym_cipher_decrypt_fn *decrypt;
    OSSL_FUNC_asym_cipher_freectx_fn *freectx;
    OSSL_FUNC_asym_cipher_dupctx_fn *dupctx;
    OSSL_FUNC_asym_cipher_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_FUNC_asym_cipher_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_asym_cipher_settable_ctx_params_fn *settable_ctx_params;
} KAE_PKEY_ASYM_CIPHER;

#define KAE_PKEY_ASYM_CIPHER_DESCR(nm, alg)                                                                      \
    static OSSL_FUNC_asym_cipher_newctx_fn kae_asym_cipher_##nm##_newctx;                                        \
    static OSSL_FUNC_asym_cipher_encrypt_init_fn kae_asym_cipher_##nm##_encrypt_init;                            \
    static OSSL_FUNC_asym_cipher_encrypt_fn kae_asym_cipher_##nm##_encrypt;                                      \
    static OSSL_FUNC_asym_cipher_decrypt_init_fn kae_asym_cipher_##nm##_decrypt_init;                            \
    static OSSL_FUNC_asym_cipher_decrypt_fn kae_asym_cipher_##nm##_decrypt;                                      \
    static OSSL_FUNC_asym_cipher_freectx_fn kae_asym_cipher_##nm##_freectx;                                      \
    static OSSL_FUNC_asym_cipher_dupctx_fn kae_asym_cipher_##nm##_dupctx;                                        \
    static OSSL_FUNC_asym_cipher_get_ctx_params_fn kae_asym_cipher_##nm##_get_ctx_params;                        \
    static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn kae_asym_cipher_##nm##_gettable_ctx_params;              \
    static OSSL_FUNC_asym_cipher_set_ctx_params_fn kae_asym_cipher_##nm##_set_ctx_params;                        \
    static OSSL_FUNC_asym_cipher_settable_ctx_params_fn kae_asym_cipher_##nm##_settable_ctx_params;              \
    static KAE_PKEY_ASYM_CIPHER get_default_##nm##_asym_cipher(void)                                             \
    {                                                                                                            \
        static KAE_PKEY_ASYM_CIPHER s_asym_cipher;                                                               \
        static int initilazed;                                                                                   \
                                                                                                                 \
        if (!initilazed) {                                                                                       \
            KAE_PKEY_ASYM_CIPHER *asym_cipher =                                                                  \
                (KAE_PKEY_ASYM_CIPHER *)EVP_ASYM_CIPHER_fetch(NULL, #alg, "provider=default");                   \
                                                                                                                 \
            if (asym_cipher) {                                                                                   \
                s_asym_cipher = *asym_cipher;                                                                    \
                EVP_ASYM_CIPHER_free((EVP_ASYM_CIPHER *)asym_cipher);                                            \
                initilazed = 1;                                                                                  \
            } else {                                                                                             \
                fprintf(stderr, "failed to EVP_ASYM_CIPHER_fetch default provider\n");                           \
            }                                                                                                    \
        }                                                                                                        \
        return s_asym_cipher;                                                                                    \
    }                                                                                                            \
    const OSSL_DISPATCH kae_##nm##_asym_cipher_functions[] = {                                                   \
        {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))kae_asym_cipher_##nm##_newctx},                           \
        {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))kae_asym_cipher_##nm##_encrypt_init},               \
        {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))kae_asym_cipher_##nm##_encrypt},                         \
        {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))kae_asym_cipher_##nm##_decrypt_init},               \
        {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))kae_asym_cipher_##nm##_decrypt},                         \
        {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))kae_asym_cipher_##nm##_freectx},                         \
        {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))kae_asym_cipher_##nm##_dupctx},                           \
        {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))kae_asym_cipher_##nm##_get_ctx_params},           \
        {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))kae_asym_cipher_##nm##_gettable_ctx_params}, \
        {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))kae_asym_cipher_##nm##_set_ctx_params},           \
        {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))kae_asym_cipher_##nm##_settable_ctx_params}, \
        {0, NULL}}

typedef struct {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;
    void *lock;

    OSSL_FUNC_signature_newctx_fn *newctx;
    OSSL_FUNC_signature_sign_init_fn *sign_init;
    OSSL_FUNC_signature_sign_fn *sign;
    OSSL_FUNC_signature_verify_init_fn *verify_init;
    OSSL_FUNC_signature_verify_fn *verify;
    OSSL_FUNC_signature_verify_recover_init_fn *verify_recover_init;
    OSSL_FUNC_signature_verify_recover_fn *verify_recover;
    OSSL_FUNC_signature_digest_sign_init_fn *digest_sign_init;
    OSSL_FUNC_signature_digest_sign_update_fn *digest_sign_update;
    OSSL_FUNC_signature_digest_sign_final_fn *digest_sign_final;
    OSSL_FUNC_signature_digest_sign_fn *digest_sign;
    OSSL_FUNC_signature_digest_verify_init_fn *digest_verify_init;
    OSSL_FUNC_signature_digest_verify_update_fn *digest_verify_update;
    OSSL_FUNC_signature_digest_verify_final_fn *digest_verify_final;
    OSSL_FUNC_signature_digest_verify_fn *digest_verify;
    OSSL_FUNC_signature_freectx_fn *freectx;
    OSSL_FUNC_signature_dupctx_fn *dupctx;
    OSSL_FUNC_signature_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_signature_gettable_ctx_params_fn *gettable_ctx_params;
    OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_signature_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_signature_get_ctx_md_params_fn *get_ctx_md_params;
    OSSL_FUNC_signature_gettable_ctx_md_params_fn *gettable_ctx_md_params;
    OSSL_FUNC_signature_set_ctx_md_params_fn *set_ctx_md_params;
    OSSL_FUNC_signature_settable_ctx_md_params_fn *settable_ctx_md_params;
} KAE_PKEY_SIGNATURE;

#define KAE_PKEY_SIGNATURE_DESCR(nm, alg)                                                                              \
    static OSSL_FUNC_signature_newctx_fn kae_signature_##nm##_newctx;                                                  \
    static OSSL_FUNC_signature_sign_init_fn kae_signature_##nm##_sign_init;                                            \
    static OSSL_FUNC_signature_verify_init_fn kae_signature_##nm##_verify_init;                                        \
    static OSSL_FUNC_signature_sign_fn kae_signature_##nm##_sign;                                                      \
    static OSSL_FUNC_signature_verify_fn kae_signature_##nm##_verify;                                                  \
    static OSSL_FUNC_signature_verify_recover_init_fn kae_signature_##nm##_verify_recover_init;                        \
    static OSSL_FUNC_signature_verify_recover_fn kae_signature_##nm##_verify_recover;                                  \
    static OSSL_FUNC_signature_digest_sign_init_fn kae_signature_##nm##_digest_sign_init;                              \
    static OSSL_FUNC_signature_digest_sign_update_fn kae_signature_##nm##_digest_sign_update;                          \
    static OSSL_FUNC_signature_digest_sign_final_fn kae_signature_##nm##_digest_sign_final;                            \
    static OSSL_FUNC_signature_digest_verify_init_fn kae_signature_##nm##_digest_verify_init;                          \
    static OSSL_FUNC_signature_digest_verify_update_fn kae_signature_##nm##_digest_verify_update;                      \
    static OSSL_FUNC_signature_digest_verify_final_fn kae_signature_##nm##_digest_verify_final;                        \
    static OSSL_FUNC_signature_freectx_fn kae_signature_##nm##_freectx;                                                \
    static OSSL_FUNC_signature_dupctx_fn kae_signature_##nm##_dupctx;                                                  \
    static OSSL_FUNC_signature_get_ctx_params_fn kae_signature_##nm##_get_ctx_params;                                  \
    static OSSL_FUNC_signature_gettable_ctx_params_fn kae_signature_##nm##_gettable_ctx_params;                        \
    static OSSL_FUNC_signature_set_ctx_params_fn kae_signature_##nm##_set_ctx_params;                                  \
    static OSSL_FUNC_signature_settable_ctx_params_fn kae_signature_##nm##_settable_ctx_params;                        \
    static OSSL_FUNC_signature_get_ctx_md_params_fn kae_signature_##nm##_get_ctx_md_params;                            \
    static OSSL_FUNC_signature_gettable_ctx_md_params_fn kae_signature_##nm##_gettable_ctx_md_params;                  \
    static OSSL_FUNC_signature_set_ctx_md_params_fn kae_signature_##nm##_set_ctx_md_params;                            \
    static OSSL_FUNC_signature_settable_ctx_md_params_fn kae_signature_##nm##_settable_ctx_md_params;                  \
    static KAE_PKEY_SIGNATURE get_default_##nm##_signature(void)                                                       \
    {                                                                                                                  \
        static KAE_PKEY_SIGNATURE s_signature;                                                                         \
        static int initilazed;                                                                                         \
                                                                                                                       \
        if (!initilazed) {                                                                                             \
            KAE_PKEY_SIGNATURE *signature = (KAE_PKEY_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, #alg, "provider=default"); \
                                                                                                                       \
            if (signature) {                                                                                           \
                s_signature = *signature;                                                                              \
                EVP_SIGNATURE_free((EVP_SIGNATURE *)signature);                                                        \
                initilazed = 1;                                                                                        \
            } else {                                                                                                   \
                fprintf(stderr, "failed to EVP_SIGNATURE_fetch default provider\n");                                   \
            }                                                                                                          \
        }                                                                                                              \
        return s_signature;                                                                                            \
    }                                                                                                                  \
    const OSSL_DISPATCH kae_##nm##_signature_functions[] = {                                                           \
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))kae_signature_##nm##_newctx},                                     \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))kae_signature_##nm##_sign_init},                               \
        {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))kae_signature_##nm##_sign},                                         \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))kae_signature_##nm##_verify_init},                           \
        {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))kae_signature_##nm##_verify},                                     \
        {OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, (void (*)(void))kae_signature_##nm##_verify_recover_init},           \
        {OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, (void (*)(void))kae_signature_##nm##_verify_recover},                     \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))kae_signature_##nm##_digest_sign_init},                 \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))kae_signature_##nm##_digest_sign_update},             \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))kae_signature_##nm##_digest_sign_final},               \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))kae_signature_##nm##_digest_verify_init},             \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))kae_signature_##nm##_digest_verify_update},         \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))kae_signature_##nm##_digest_verify_final},           \
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))kae_signature_##nm##_freectx},                                   \
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))kae_signature_##nm##_dupctx},                                     \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))kae_signature_##nm##_get_ctx_params},                     \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))kae_signature_##nm##_gettable_ctx_params},           \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))kae_signature_##nm##_set_ctx_params},                     \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))kae_signature_##nm##_settable_ctx_params},           \
        {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))kae_signature_##nm##_get_ctx_md_params},               \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))kae_signature_##nm##_gettable_ctx_md_params},     \
        {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))kae_signature_##nm##_set_ctx_md_params},               \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))kae_signature_##nm##_settable_ctx_md_params},     \
        {0, NULL}}

typedef struct {
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;
    int refcnt;

    OSSL_FUNC_keyexch_newctx_fn *newctx;
    OSSL_FUNC_keyexch_init_fn *init;
    OSSL_FUNC_keyexch_set_peer_fn *set_peer;
    OSSL_FUNC_keyexch_derive_fn *derive;
    OSSL_FUNC_keyexch_freectx_fn *freectx;
    OSSL_FUNC_keyexch_dupctx_fn *dupctx;
    OSSL_FUNC_keyexch_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_keyexch_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_keyexch_get_ctx_params_fn *get_ctx_params;
    OSSL_FUNC_keyexch_gettable_ctx_params_fn *gettable_ctx_params;
} KAE_PKEY_KEYEXCH;

#define KAE_PKEY_KEYEXCH_DESCR(nm, alg)                                                                        \
    static OSSL_FUNC_keyexch_newctx_fn kae_keyexch_##nm##_newctx;                                              \
    static OSSL_FUNC_keyexch_init_fn kae_keyexch_##nm##_init;                                                  \
    static OSSL_FUNC_keyexch_set_peer_fn kae_keyexch_##nm##_set_peer;                                          \
    static OSSL_FUNC_keyexch_derive_fn kae_keyexch_##nm##_derive;                                              \
    static OSSL_FUNC_keyexch_freectx_fn kae_keyexch_##nm##_freectx;                                            \
    static OSSL_FUNC_keyexch_dupctx_fn kae_keyexch_##nm##_dupctx;                                              \
    static OSSL_FUNC_keyexch_set_ctx_params_fn kae_keyexch_##nm##_set_ctx_params;                              \
    static OSSL_FUNC_keyexch_settable_ctx_params_fn kae_keyexch_##nm##_settable_ctx_params;                    \
    static OSSL_FUNC_keyexch_get_ctx_params_fn kae_keyexch_##nm##_get_ctx_params;                              \
    static OSSL_FUNC_keyexch_gettable_ctx_params_fn kae_keyexch_##nm##_gettable_ctx_params;                    \
    static KAE_PKEY_KEYEXCH get_default_##nm##_keyexch(void)                                                   \
    {                                                                                                          \
        KAE_PKEY_KEYEXCH s_keyexch;                                                                            \
        static int initilazed;                                                                                 \
                                                                                                               \
        if (!initilazed) {                                                                                     \
            KAE_PKEY_KEYEXCH *keyexch = (KAE_PKEY_KEYEXCH *)EVP_KEYEXCH_fetch(NULL, #alg, "provider=default"); \
            if (keyexch) {                                                                                     \
                s_keyexch = *keyexch;                                                                          \
                EVP_KEYEXCH_free((EVP_KEYEXCH *)keyexch);                                                      \
                initilazed = 1;                                                                                \
            } else {                                                                                           \
                fprintf(stderr, "failed to EVP_KEYEXCH_fetch default provider\n");                             \
            }                                                                                                  \
        }                                                                                                      \
        return s_keyexch;                                                                                      \
    }                                                                                                          \
    const OSSL_DISPATCH kae_##nm##_keyexch_functions[] = {                                                     \
        {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))kae_keyexch_##nm##_newctx},                                 \
        {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))kae_keyexch_##nm##_set_ctx_params},                 \
        {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))kae_keyexch_##nm##_init},                                     \
        {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))kae_keyexch_##nm##_derive},                                 \
        {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))kae_keyexch_##nm##_set_peer},                             \
        {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))kae_keyexch_##nm##_freectx},                               \
        {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))kae_keyexch_##nm##_dupctx},                                 \
        {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))kae_keyexch_##nm##_settable_ctx_params},       \
        {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))kae_keyexch_##nm##_get_ctx_params},                 \
        {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))kae_keyexch_##nm##_gettable_ctx_params},       \
        {0, NULL}}

#endif