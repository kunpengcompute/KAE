/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
 *
 */
#ifndef UADK_PKEY_H
#define UADK_PKEY_H
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <uadk/wd.h>
#include <uadk/wd_ecc.h>

#define UADK_DO_SOFT			(-0xE0)
#define UADK_ECC_MAX_KEY_BITS		521
#define UADK_ECC_MAX_KEY_BYTES		66
#define UADK_ECC_CV_PARAM_NUM		6
#define SM2_KEY_BYTES			32
#define UADK_OCTET_STRING		0x04
#define UADK_ECC_PUBKEY_PARAM_NUM	2
#define UADK_ECC_PADDING		7
#define UADK_ECDH_CV_NUM		8
#define ENV_ENABLED			1
#define UADK_E_INVALID			(-2)
#define TRANS_BITS_BYTES_SHIFT		3
#define ECC_POINT_SIZE(n)		((n) * 2)
#define GET_MS_BYTE(n)			((n) >> 8)
#define GET_LS_BYTE(n)			((n) & 0xFF)
#define DGST_SHIFT_NUM(n)		(8 - ((n) & 0x7))
#define ECC_TYPE			5

enum {
	SM2_SUPPORT,
	ECDSA_SUPPORT,
	ECDH_SUPPORT,
	X25519_SUPPORT,
	X448_SUPPORT
};

struct uadk_pkey_meth {
	EVP_PKEY_METHOD *sm2;
	EVP_PKEY_METHOD *ec;
	EVP_PKEY_METHOD *x448;
	EVP_PKEY_METHOD *x25519;
};

bool uadk_is_all_zero(const unsigned char *data, size_t dlen);
bool uadk_support_algorithm(const char *alg);
int uadk_ecc_get_rand(char *out, size_t out_len, void *usr);
void uadk_e_ecc_cb(void *req_t);
void uadk_ecc_fill_req(struct wd_ecc_req *req,
			      unsigned int op, void *in, void *out);
int uadk_ecc_set_private_key(handle_t sess, const EC_KEY *eckey);
int uadk_ecc_set_public_key(handle_t sess, const EC_KEY *eckey);
int uadk_ecc_crypto(handle_t sess, struct wd_ecc_req *req,
		    void *usr);
bool uadk_prime_field(const EC_GROUP *group);
int uadk_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
		   BIGNUM *b, BN_CTX *ctx);
int uadk_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p,
				BIGNUM *x, BIGNUM *y, BN_CTX *ctx);

int uadk_init_ecc(void);
const EVP_PKEY_METHOD *get_openssl_pkey_meth(int nid);
int uadk_sm2_create_pmeth(struct uadk_pkey_meth *pkey_meth);
void uadk_sm2_delete_pmeth(struct uadk_pkey_meth *pkey_meth);
int uadk_ec_create_pmeth(struct uadk_pkey_meth *pkey_meth);
void uadk_ec_delete_meth(void);
int uadk_x448_create_pmeth(struct uadk_pkey_meth *pkey_meth);
void uadk_x448_delete_pmeth(struct uadk_pkey_meth *pkey_meth);
int uadk_x25519_create_pmeth(struct uadk_pkey_meth *pkey_meth);
void uadk_x25519_delete_pmeth(struct uadk_pkey_meth *pkey_meth);
int uadk_bind_ec(ENGINE *e);
int uadk_e_ecc_get_numa_id(void);
int uadk_e_ecc_get_support_state(int alg_tag);

#endif
