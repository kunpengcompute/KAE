/*
 * Copyright (C) 2025. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:    This file provides the implementation for KAE engine rsa
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

#ifndef BSSL_RSA_H
#define BSSL_RSA_H

#include <pthread.h>

#ifndef OPENSSL_FILE
#ifdef OPENSSL_NO_FILENAMES
#define OPENSSL_FILE ""
#define OPENSSL_LINE 0
#else
#define OPENSSL_FILE __FILE__
#define OPENSSL_LINE __LINE__
#endif
#endif

#ifndef OPENSSL_RSA_SMALL_MODULUS_BITS
#define OPENSSL_RSA_SMALL_MODULUS_BITS 3072
#endif
#ifndef OPENSSL_RSA_MAX_PUBEXP_BITS
#define OPENSSL_RSA_MAX_PUBEXP_BITS 64
#endif

#define RSA_SSLV23_PADDING 2
#define RSA_X931_PADDING 5
#define BN_FLG_CONSTTIME 0x04
#define RSA_PKCS1_PADDING_SIZE 11
#define RSA_ASN1_VERSION_MULTI 1

#define RSA_METH_RET_DEFAULT (1)
#define RSA_meth_set_mod_exp(meth, exp) RSA_METH_RET_DEFAULT
#define RSA_meth_set_bn_mod_exp(meth, exp) RSA_METH_RET_DEFAULT
#define RSA_meth_set_init(meth, init) RSA_METH_RET_DEFAULT
#define RSA_meth_set_finish(meth, finish) RSA_METH_RET_DEFAULT
#define RSA_get_default_method() bssl_soft_get_default_RSA_methods()
#define RSA_meth_new bssl_soft_rsa_meth_new
#define RSA_meth_free bssl_soft_rsa_meth_free
#define RSA_meth_get_pub_enc(meth) RSA_public_encrypt
#define RSA_meth_get_pub_dec(meth) RSA_public_decrypt
#define RSA_meth_get_priv_enc(meth) RSA_private_encrypt_default
#define RSA_meth_get_priv_dec(meth) RSA_private_decrypt_default

#define RSA_METH_SET_NOTHING(meth, func) \
    RSA_METH_RET_DEFAULT;               \
    do {                                \
        if (meth->app_data == NULL) { \
            meth->app_data = func;    \
            meth->app_data = NULL;    \
        }                               \
    } while (0)
#define RSA_meth_set_pub_enc(meth, func) RSA_METH_SET_NOTHING(meth, func)
#define RSA_meth_set_pub_dec(meth, func) RSA_METH_SET_NOTHING(meth, func)
#define RSA_meth_set_priv_enc(meth, func) RSA_METH_SET_NOTHING(meth, func)
#define RSA_meth_set_priv_dec(meth, func) RSA_METH_SET_NOTHING(meth, func)
#define RSA_meth_set_priv_bssl bssl_soft_rsa_set_priv_meth
#define RSA_padding_add_none bssl_soft_rsa_padding_add_none
#define RSA_padding_check_none bssl_soft_rsa_padding_check_none
#define RSA_padding_add_PKCS1_type_1 bssl_soft_rsa_padding_add_pkcs1_type_1
#define RSA_padding_check_PKCS1_type_1 bssl_soft_rsa_padding_check_pkcs1_type_1
#define RSA_padding_add_PKCS1_type_2 bssl_soft_rsa_padding_add_pkcs1_type_2
#define RSA_padding_check_PKCS1_type_2 bssl_soft_rsa_padding_check_pkcs1_type_2
#define RSA_padding_check_PKCS1_OAEP bssl_soft_rsa_padding_check_pkcs1_OAEP
#define RSA_padding_add_SSLv23 bssl_soft_rsa_padding_add_sslv23
#define RSA_padding_check_SSLv23 bssl_soft_rsa_padding_check_sslv23
#define RSA_padding_add_X931 bssl_soft_rsa_padding_add_x931
#define RSA_padding_check_X931 bssl_soft_rsa_padding_check_x931

typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int (*init)(EVP_PKEY_CTX *ctx);
    int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    void (*cleanup)(EVP_PKEY_CTX *ctx);
    int (*paramgen_init)(EVP_PKEY_CTX *ctx);
    int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*keygen_init)(EVP_PKEY_CTX *ctx);
    int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int (*sign_init)(EVP_PKEY_CTX *ctx);
    int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
    int (*verify_init)(EVP_PKEY_CTX *ctx);
    int (*verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
    int (*verify_recover_init)(EVP_PKEY_CTX *ctx);
    int (*verify_recover)(
        EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const unsigned char *sig, size_t siglen);
    int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx);
    int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int (*verifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx);
    int (*encrypt_init)(EVP_PKEY_CTX *ctx);
    int (*encrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    int (*decrypt_init)(EVP_PKEY_CTX *ctx);
    int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    int (*derive_init)(EVP_PKEY_CTX *ctx);
    int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int (*ctrl_str)(EVP_PKEY_CTX *ctx, const char *type, const char *value);
    int (*digestsign)(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
    int (*digestverify)(
        EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
    int (*check)(EVP_PKEY *pkey);
    int (*public_check)(EVP_PKEY *pkey);
    int (*param_check)(EVP_PKEY *pkey);

    int (*digest_custom)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
};

typedef struct crypto_mutex_st {
    char padding;
} CRYPTO_MUTEX;

typedef struct bn_blinding_st {
    BIGNUM *A;
    BIGNUM *Ai;
    unsigned counter;
} BN_BLINDING;

struct rsa_st {
    RSA_METHOD *meth;

    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;

    CRYPTO_EX_DATA ex_data;
    CRYPTO_refcount_t references;
    int flags;

    CRYPTO_MUTEX lock;

    BN_MONT_CTX *mont_n;
    BN_MONT_CTX *mont_p;
    BN_MONT_CTX *mont_q;

    BIGNUM *d_fixed, *dmp1_fixed, *dmq1_fixed;
    BIGNUM *iqmp_mont;

    size_t num_blindings;
    BN_BLINDING **blindings;
    unsigned char *blindings_inuse;
    uint64_t blinding_fork_generation;
    unsigned private_key_frozen : 1;
};

int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))(BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx);

int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))(
    BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

RSA_METHOD *bssl_soft_rsa_meth_new(const char *name, int flags);

void bssl_soft_rsa_meth_free(RSA_METHOD *meth);

int bssl_soft_rsa_set_priv_meth(RSA_METHOD *meth,
    int (*sign_raw)(
        RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding),
    int (*decrypt)(
        RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding));

int bssl_soft_rsa_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len);

int bssl_soft_rsa_padding_check_none(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);

int bssl_soft_rsa_padding_add_pkcs1_type_1(uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len);

int bssl_soft_rsa_padding_check_pkcs1_type_1(unsigned char *to, int tlen, const unsigned char *from, int flen, int num);

int bssl_soft_rsa_padding_add_pkcs1_type_2(uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len);

int bssl_soft_rsa_padding_check_pkcs1_type_2(
    uint8_t *out, size_t out_len, const uint8_t *from, size_t from_len, size_t max_out);
int bssl_soft_rsa_padding_check_pkcs1_OAEP(unsigned char *out, int out_len, const unsigned char *from, int from_len,
    int max_out, const unsigned char *p, int pl);

int bssl_soft_rsa_padding_add_sslv23(unsigned char *to, int tlen, const unsigned char *f, int fl);

int bssl_soft_rsa_padding_check_sslv23(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);

int bssl_soft_rsa_padding_add_x931(unsigned char *to, int tlen, const unsigned char *f, int fl);

int bssl_soft_rsa_padding_check_x931(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);

#endif