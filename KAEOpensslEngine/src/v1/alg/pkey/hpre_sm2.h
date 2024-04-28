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

#include "uadk/v1/wd_ecc.h"
#include "../../wdmngr/wd_queue_memory.h"

extern KAE_QUEUE_POOL_HEAD_S *g_hpre_sm2_qnode_pool;

#define HPRE_SM2_RETURN_FAIL_IF(cond, mesg, ret) \
	do { \
		if (unlikely(cond)) { \
			US_ERR(mesg); \
				return (ret); \
		} \
	} while (0)

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

typedef int (*PFUNC_SIGN)(EVP_PKEY_CTX *ctx,
			  unsigned char *sig,
			  size_t *siglen,
			  const unsigned char *tbs,
			  size_t tbslen);

typedef int (*PFUNC_VERIFY)(EVP_PKEY_CTX *ctx,
			    const unsigned char *sig,
			    size_t siglen,
			    const unsigned char *tbs,
			    size_t tbslen);
typedef int (*PFUNC_ENC)(EVP_PKEY_CTX *ctx,
			 unsigned char *out,
			 size_t *outlen,
			 const unsigned char *in,
			 size_t inlen);
typedef int (*PFUNC_DEC)(EVP_PKEY_CTX *ctx,
			 unsigned char *out,
			 size_t *outlen,
			 const unsigned char *in,
			 size_t inlen);

// struct hpre_pkey_meth {
// 	EVP_PKEY_METHOD *sm2;
// };

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

struct hpre_sm2_priv_ctx {
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
};

typedef struct hpre_sm2_priv_ctx hpre_sm2_priv_ctx_t;
struct hpre_sm2_engine_ctx {
	void * wd_ctx;
	struct wcrypto_ecc_op_data opdata;
	struct wcrypto_ecc_ctx_setup setup;
	KAE_QUEUE_DATA_NODE_S *qlist;
	hpre_sm2_priv_ctx_t *priv_ctx;
};

int hpre_get_sm2_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
int hpre_module_sm2_init(void);
void wd_sm2_uninit_qnode_pool(void);
void hpre_sm2_set_enabled(int nid, int enabled);
KAE_QUEUE_POOL_HEAD_S *wd_hpre_sm2_get_qnode_pool(void);

#endif

