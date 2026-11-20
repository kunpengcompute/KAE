/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the implementation for KAE rsa using wd interface
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

#ifndef HPRE_RSA_H
#define HPRE_RSA_H

#include <semaphore.h>
#include <asm/types.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "../../../common/kae_opensslerr.h"
#include "../../../common/kae_utils.h"

#define RSA_MIN_MODULUS_BITS 512

#define RSA1024BITS 1024
#define RSA2048BITS 2048
#define RSA3072BITS 3072
#define RSA4096BITS 4096

enum {
    INVALID = 0,
    PUB_ENC,
    PUB_DEC,
    PRI_ENC,
    PRI_DEC,
    MAX_CODE,
};

struct bignum_st {
    BN_ULONG *d;
    int top;
    int dmax;
    int neg;
    int flags;
};

typedef int CRYPTO_REF_COUNT;

typedef struct rsa_pss_params_30_st {
    int hash_algorithm_nid;
    struct {
        int algorithm_nid; /* Currently always NID_mgf1 */
        int hash_algorithm_nid;
    } mask_gen;
    int salt_len;
    int trailer_field;
} RSA_PSS_PARAMS_30;

struct rsa_st {
    /*
     * #legacy
     * The first field is used to pickup errors where this is passed
     * instead of an EVP_PKEY.  It is always zero.
     * THIS MUST REMAIN THE FIRST FIELD.
     */
    int dummy_zero;

    OSSL_LIB_CTX *libctx;
    int32_t version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;

    /*
     * If a PSS only key this contains the parameter restrictions.
     * There are two structures for the same thing, used in different cases.
     */
    /* This is used uniquely by OpenSSL provider implementations. */
    RSA_PSS_PARAMS_30 pss_params;

    /* This is used uniquely by rsa_ameth.c and rsa_pmeth.c. */
    RSA_PSS_PARAMS *pss;
    /* for multi-prime RSA, defined in RFC 8017 */
    STACK_OF(RSA_PRIME_INFO) * prime_infos;
    /* Be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;

    int references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
    CRYPTO_RWLOCK *lock;

    int dirty_cnt;
};

struct rsa_gen_ctx {
    OSSL_LIB_CTX *libctx;
    const char *propq;

    int rsa_type;

    size_t nbits;
    BIGNUM *pub_exp;
    size_t primes;

    /* For PSS */
    RSA_PSS_PARAMS_30 pss_params;
    int pss_defaults_set;

    /* For generation callback */
    OSSL_CALLBACK *cb;
    void *cbarg;
};

typedef struct {
    OSSL_LIB_CTX *libctx;
    RSA *rsa;
    int pad_mode;
    int operation;
    /* OAEP message digest */
    EVP_MD *oaep_md;
    /* message digest for MGF1 */
    EVP_MD *mgf1_md;
    /* OAEP label */
    unsigned char *oaep_label;
    size_t oaep_labellen;
    /* TLS padding */
    unsigned int client_version;
    unsigned int alt_version;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    unsigned int implicit_rejection;
#endif

} PROV_RSA_ASYM_CTX;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    RSA *rsa;
    int operation;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    unsigned int flag_sigalg : 1;
#endif
    unsigned int flag_allow_md : 1;
    unsigned int mgf1_md_set : 1;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    unsigned int flag_allow_update : 1;
    unsigned int flag_allow_final : 1;
    unsigned int flag_allow_oneshot : 1;
#endif

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int mdnid;
    char mdname[50]; /* Purely informational */

    /* RSA padding mode */
    int pad_mode;
    /* message digest for MGF1 */
    EVP_MD *mgf1_md;
    int mgf1_mdnid;
    char mgf1_mdname[50]; /* Purely informational */
    /* PSS salt length */
    int saltlen;
    /* Minimum salt length or -1 if no PSS parameter restriction */
    int min_saltlen;

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    unsigned char *sig;
    size_t siglen;
#endif

    /* Temp buffer */
    unsigned char *tbuf;

} PROV_RSA_SIG_CTX;

int hpre_module_rsa_init(void);

int hpre_rsa_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

int hpre_rsa_private_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

int hpre_rsa_public_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

int hpre_rsa_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

int hpre_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

#endif
