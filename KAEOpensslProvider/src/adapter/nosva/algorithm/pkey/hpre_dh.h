/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the implementation for KAE engine DH.
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

#ifndef HPRE_DH_H
#define HPRE_DH_H

#include <openssl/dh.h>

#define DH768BITS 768
#define DH1024BITS 1024
#define DH1536BITS 1536
#define DH2048BITS 2048
#define DH3072BITS 3072
#define DH4096BITS 4096

#define DH_MAX_PARAM_LEN 80
#define IGNORE_Q 1
#define USE_PAD 1
#define KDF_PARAM_NUM 5

/*
 * This type is only really used to handle some legacy related functionality.
 * If you need to use other KDF's (such as SSKDF) just use PROV_DH_KDF_NONE
 * here and then create and run a KDF after the key is derived.
 * Note that X942 has 2 variants of key derivation:
 *   (1) DH_KDF_X9_42_ASN1 - which contains an ANS1 encoded object that has
 *   the counter embedded in it.
 *   (2) DH_KDF_X941_CONCAT - which is the same as ECDH_X963_KDF (which can be
 *       done by creating a "X963KDF".
 */
enum kdf_type { PROV_DH_KDF_NONE = 0, PROV_DH_KDF_X9_42_ASN1 };

/*
 * Finite field cryptography (FFC) domain parameters are used by DH and DSA.
 * Refer to FIPS186_4 Appendix A & B.
 */
typedef struct ffc_params_st {
    /* Primes */
    BIGNUM *p;
    BIGNUM *q;
    /* Generator */
    BIGNUM *g;
    /* DH X9.42 Optional Subgroup factor j >= 2 where p = j * q + 1 */
    BIGNUM *j;

    /* Required for FIPS186_4 validation of p, q and optionally canonical g */
    unsigned char *seed;
    /* If this value is zero the hash size is used as the seed length */
    size_t seedlen;
    /* Required for FIPS186_4 validation of p and q */
    int pcounter;
    /* The identity of a named group */
    int nid;

    /*
     * Required for FIPS186_4 generation & validation of canonical g.
     * It uses unverifiable g if this value is -1.
     */
    int gindex;
    /* loop counter for unverifiable g */
    int h;

    unsigned int flags;
    /*
     * The digest to use for generation or validation. If this value is NULL,
     * then the digest is chosen using the value of N.
     */
    const char *mdname;
    const char *mdprops;
#if OPENSSL_VERSION_NUMBER >= 0x30000060
    /* Default key length for known named groups according to RFC7919 */
    int keylength;
#endif
} FFC_PARAMS;

struct dh_st {
    /*
     * This first argument is used to pick up errors when a DH is passed
     * instead of a EVP_PKEY
     */
    int pad;
    int version;
    FFC_PARAMS params;
    /* max generated private key length (can be less than len(q)) */
    int32_t length;
    BIGNUM *pub_key;  /* g^x % p */
    BIGNUM *priv_key; /* x */
    int flags;
    BN_MONT_CTX *method_mont_p;
    int references;
#ifndef FIPS_MODULE
    CRYPTO_EX_DATA ex_data;
    ENGINE *engine;
#endif
    OSSL_LIB_CTX *libctx;
    const DH_METHOD *meth;
    void *lock;

    /* Provider data */
    /* If any key material changes, increment this */
    size_t dirty_cnt;
}; /* DH */

typedef struct {
    OSSL_LIB_CTX *libctx;

    FFC_PARAMS *ffc_params;
    int selection;
    /* All these parameters are used for parameter generation only */
    /* If there is a group name then the remaining parameters are not needed */
    int group_nid;
    size_t pbits;
    size_t qbits;
    unsigned char *seed; /* optional FIPS186-4 param for testing */
    size_t seedlen;
    int gindex;    /* optional  FIPS186-4 generator index (ignored if -1) */
    int gen_type;  /* see dhtype2id */
    int generator; /* Used by DH_PARAMGEN_TYPE_GENERATOR in non fips mode only */
    int pcounter;
    int hindex;
    int priv_len;

    char *mdname;
    char *mdprops;
    OSSL_CALLBACK *cb;
    void *cbarg;
    int dh_type;
} PROV_DH_KEYMGMT_CTX;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DH structures, so
 * we use that here too.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    DH *dh;
    DH *dhpeer;
    unsigned int pad : 1;

    /* DH KDF */
    /* KDF (if any) to use for DH */
    enum kdf_type kdf_type;
    /* Message digest to use for key derivation */
    EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
    char *kdf_cekalg;
} PROV_DH_KEYEXCH_CTX;

const DH_METHOD *hpre_get_dh_methods(void);

int hpre_module_dh_init(void);

int hpre_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);

int hpre_dh_generate_key(DH *dh);

EVP_PKEY_METHOD *get_dh_pkey_meth(void);

EVP_PKEY_METHOD *get_dsa_pkey_meth(void);

#endif
