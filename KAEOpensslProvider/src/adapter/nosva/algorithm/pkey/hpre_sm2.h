/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the rsa interface for KAE rsa using wd interface
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

#ifndef HPRE_SM2_H
#define HPRE_SM2_H

#include <openssl/ec.h>
#include "uadk/v1/wd_ecc.h"
#include "../../wdwarp/wd_queue_memory.h"

extern KAE_QUEUE_POOL_HEAD_S *g_hpre_sm2_qnode_pool;

#define HPRE_SM2_DO_SOFT			(-0xE0)
#define TRANS_BITS_BYTES_SHIFT		3
#define ECC_POINT_SIZE(n)		((n) * 2)
#define GET_MS_BYTE(n)			((n) >> 8)
#define GET_LS_BYTE(n)			((n) & 0xFF)
#define DGST_SHIFT_NUM(n)		(8 - ((n) & 0x7))
#define ECC_TYPE	
#define BITS_TO_BYTES(bits)		(((bits) + 7) >> 3)

#define HPRE_SM2_DO_SOFT			(-0xE0)
#define SM2_MAX_KEY_BYTES		66
#define SM2_GET_RAND_MAX_CNT	100
#define SM2_OCTET_STRING		0x04
#define SM2_ECC_PUBKEY_PARAM_NUM	2
#define SM2_MAX_KEY_BYTES		66
#define SM2_KEY_BYTES			32
#define MAX_SEND_TRY_CNTS  50

enum {
	HPRE_SM2_INIT_FAIL = -1,
	HPRE_SM2_UNINIT,
	HPRE_SM2_INIT_SUCC
};

enum {
	MD_UNCHANGED,
	MD_CHANGED
};

typedef struct hpre_sm2_ciphertext {
	BIGNUM *C1x;
	BIGNUM *C1y;
	ASN1_OCTET_STRING *C3;
	ASN1_OCTET_STRING *C2;
} HPRE_SM2_Ciphertext;

struct hpre_sm2_param {
	/*
	 * p: BIGNUM with the prime number (GFp) or the polynomial
	 * defining the underlying field (GF2m)
	 */
	BIGNUM *p;
	/* a: BIGNUM for parameter a of the equation */
	BIGNUM *a;
	/* b: BIGNUM for parameter b of the equation */
	BIGNUM *b;
	/* xG: BIGNUM for the x-coordinate value of G point */
	BIGNUM *xG;
	/* yG: BIGNUM for the y-coordinate value of G point */
	BIGNUM *yG;
	/* xA: BIGNUM for the x-coordinate value of PA point */
	BIGNUM *xA;
	/* yA: BIGNUM for the y-coordinate value of PA point */
	BIGNUM *yA;
};

typedef struct hpre_sm2_engine_ctx hpre_sm2_engine_ctx_t;

typedef struct {
	/* Key and paramgen group */
	EC_GROUP *gen_group;
	/* Message digest */
	const EVP_MD *md;
	/* Distinguishing Identifier, ISO/IEC 15946-3 */
	uint8_t *id;
	size_t id_len;
	/* Indicates if the 'id' field is set (1) or not (0) */
	int id_set;
} HPRE_SM2_PKEY_CTX;

typedef struct  {
	HPRE_SM2_PKEY_CTX ctx;
	// handle_t sess;
	const BIGNUM *prikey;
	const EC_POINT *pubkey;
	BIGNUM *order;
	int init_status;
	/* The nid of digest method */
	int md_nid;
	/* The update status of digest method, changed (1), not changed (0) */
	int md_update_status;
	hpre_sm2_engine_ctx_t *e_hpre_sm2_ctx;
} hpre_sm2_priv_ctx;


struct hpre_sm2_engine_ctx {
	void * wd_ctx;
	struct wcrypto_ecc_op_data opdata;
	struct wcrypto_ecc_ctx_setup setup;
	KAE_QUEUE_DATA_NODE_S *qlist;
	hpre_sm2_priv_ctx *priv_ctx;
};

#define OSSL_MAX_NAME_SIZE		50 /* Algorithm name */
#define OSSL_MAX_ALGORITHM_ID_SIZE	256 /* AlgorithmIdentifier DER */

/* Structure for sm2 key related data */
typedef struct {
	BIGNUM *order;
	/* Key and paramgen group */
	EC_GROUP *gen_group;
	const BIGNUM *prikey;
	const EC_POINT *pubkey;
} SM2_PKEY_DATA;

/* Structure for sm2 digest method related data */
typedef struct {
	/* The nid of digest method */
	int md_nid;
	/* Legacy: update status of digest method, changed (1), unchanged (0) */
	int md_update_status;
	/*
	 * References to the underlying digest implementation.
	 * |md| caches the digest, always.
	 * |alloc_md| only holds a reference to an explicitly fetched digest.
	 */
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
	EVP_MD *alloc_md;
	size_t mdsize;
} SM2_MD_DATA;

/* Structure for SM2 private context in kae_provider, related to KAE */
typedef struct {
	int init_status;
	/* The session related to KAE */
	// handle_t sess;
    hpre_sm2_priv_ctx *hsmctx;
	SM2_PKEY_DATA *sm2_pd;
	SM2_MD_DATA *sm2_md;
	int do_soft;
} SM2_PROV_CTX;


/*
 * To stay same structure with openssl sm2 cipher context,
 * add openssl PROV_DIGEST type to kae provider.
 * It will not be used in kae provider, so set it all zero.
 */
struct PROV_DIGEST {
	const EVP_MD *md;
	EVP_MD *alloc_md;

	ENGINE *engine;

	/* The resv is additional field, not in openssl structure.
	 * Add it to prevent possible field changes of openssl in future.
	 */
	char resv[OSSL_MAX_NAME_SIZE];
};

typedef struct {
	OSSL_LIB_CTX *libctx;
	/* Use EC_KEY refer to keymgmt */
	EC_KEY *ec_key;
	/* The md will used by openssl, but not used by kae provider */
	struct PROV_DIGEST md;

	SM2_PROV_CTX *sm2_pctx;
} PROV_SM2_ASYM_CTX;

typedef struct {
	OSSL_LIB_CTX *libctx;
	char *propq;
	/* Use EC_KEY refer to keymgmt */
	EC_KEY *ec_key;

	/*
	 * Flag to termine if the 'z' digest needs to be computed and fed to the
	 * hash function.
	 * This flag should be set on initialization and the compuation should
	 * be performed only once, on first update.
	 */
	unsigned int flag_compute_z_digest : 1;

	/* Will used by openssl, but not used by UADK, so put it outside SM2_PROV_CTX */
	char mdname[OSSL_MAX_NAME_SIZE];

	/* The Algorithm Identifier of the combined signature algorithm */
	unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
	unsigned char *aid;
	size_t  aid_len;

	/*
	 * SM2 ID used for calculating the Z value,
	 * distinguishing Identifier, ISO/IEC 15946-3
	 */
	unsigned char *id;
	size_t id_len;
	/* Indicates if the 'id' field is set (1) or not (0) */
	int id_set;

	SM2_PROV_CTX *sm2_pctx;
} PROV_SM2_SIGN_CTX;


int hpre_module_sm2_init(void);

void wd_sm2_uninit_qnode_pool(void);

KAE_QUEUE_POOL_HEAD_S *wd_hpre_sm2_get_qnode_pool(void);

int hpre_sm2_update_sess(SM2_PROV_CTX *sm2_pctx);

int hpre_sm2_encrypt(PROV_SM2_ASYM_CTX *psm2ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen);

int hpre_sm2_decrypt(PROV_SM2_ASYM_CTX *psm2ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen);

int hpre_sm2_sign(PROV_SM2_SIGN_CTX *psm2ctx, unsigned char *sig, size_t *siglen,
		    const unsigned char *tbs, size_t tbslen);
		
int hpre_sm2_verify(PROV_SM2_SIGN_CTX *psm2ctx,
		      const unsigned char *sig, size_t siglen,
		      const unsigned char *tbs, size_t tbslen);

int hpre_sm2_compute_z_digest(uint8_t *out, const EVP_MD *digest,
				const uint8_t *id, const size_t id_len,
				const EC_KEY *key);

// todo unuse
// void hpre_sm2_cleanup(PROV_SM2_ASYM_CTX *psm2ctx);

#endif

