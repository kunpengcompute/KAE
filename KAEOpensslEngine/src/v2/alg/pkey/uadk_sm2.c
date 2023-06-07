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
#include <openssl/bn.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "v2/uadk.h"
#include "v2/alg/pkey/uadk_pkey.h"
#include "utils/engine_log.h"

enum {
	CTX_INIT_FAIL = -1,
	CTX_UNINIT,
	CTX_INIT_SUCC
};

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
} SM2_PKEY_CTX;

struct sm2_ctx {
	SM2_PKEY_CTX ctx;
	handle_t sess;
	const BIGNUM *prikey;
	const EC_POINT *pubkey;
	BIGNUM *order;
	int init_status;
};

typedef struct sm2_ciphertext {
	BIGNUM *C1x;
	BIGNUM *C1y;
	ASN1_OCTET_STRING *C3;
	ASN1_OCTET_STRING *C2;
} SM2_Ciphertext;

struct sm2_param {
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

DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

ASN1_SEQUENCE(SM2_Ciphertext) = {
	ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

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

static int get_hash_type(int nid_hash)
{
	switch (nid_hash) {
	case NID_sha1:
		return WD_HASH_SHA1;
	case NID_sha224:
		return WD_HASH_SHA224;
	case NID_sha256:
		return WD_HASH_SHA256;
	case NID_sha384:
		return WD_HASH_SHA384;
	case NID_sha512:
		return WD_HASH_SHA512;
	case NID_md4:
		return WD_HASH_MD4;
	case NID_md5:
		return WD_HASH_MD5;
	case NID_sm3:
		return WD_HASH_SM3;
	default:
		return -1;
	}
}

static int compute_hash(const char *in, size_t in_len,
		       char *out, size_t out_len, void *usr)
{
	const EVP_MD *digest = (const EVP_MD *)usr;
	EVP_MD_CTX *hash = EVP_MD_CTX_new();
	int ret = 0;

	if (EVP_DigestInit(hash, digest) == 0 ||
		EVP_DigestUpdate(hash, in, in_len) == 0 ||
		EVP_DigestFinal(hash, (void *)out, NULL) == 0) {
		fprintf(stderr, "compute hash failed\n");
		ret = -1;
	}

	EVP_MD_CTX_free(hash);

	return ret;
}

static int sm2_update_sess(struct sm2_ctx *smctx)
{
	const unsigned char sm2_order[] = {
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
		0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23
	};
	int nid_hash = smctx->ctx.md ? EVP_MD_type(smctx->ctx.md) : NID_sm3;
	struct wd_ecc_sess_setup setup;
	handle_t sess;
	BIGNUM *order;
	int type;

	memset(&setup, 0, sizeof(setup));
	setup.alg = "sm2";

	if (smctx->ctx.md) {
		setup.hash.cb = compute_hash;
		setup.hash.usr = (void *)smctx->ctx.md;
		type = get_hash_type(nid_hash);
		if (type < 0) {
			fprintf(stderr, "uadk not support hash nid %d\n",
				nid_hash);
			return -EINVAL;
		}
		setup.hash.type = type;
	}

	order = BN_bin2bn((void *)sm2_order, sizeof(sm2_order), NULL);
	setup.rand.cb = uadk_ecc_get_rand;
	setup.rand.usr = (void *)order;
	sess = wd_ecc_alloc_sess(&setup);
	if (!sess) {
		fprintf(stderr, "failed to alloc sess\n");
		BN_free(order);
		return -EINVAL;
	}

	if (smctx->sess)
		wd_ecc_free_sess(smctx->sess);

	smctx->sess = sess;
	smctx->prikey = NULL;
	smctx->pubkey = NULL;
	smctx->order = order;
	return 0;
}

static int update_public_key(EVP_PKEY_CTX *ctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *eckey = EVP_PKEY_get0(p_key);
	const EC_GROUP *group;
	const EC_POINT *point;
	int ret;

	point = EC_KEY_get0_public_key(eckey);
	if (!point) {
		fprintf(stderr, "pubkey not set!\n");
		return -EINVAL;
	}

	if (smctx->pubkey) {
		group = EC_KEY_get0_group(eckey);
		ret = EC_POINT_cmp(group, (void *)smctx->pubkey, point, NULL);
		if (!ret)
			return 0;
	}

	ret = uadk_ecc_set_public_key(smctx->sess, eckey);
	if (ret)
		return ret;

	smctx->pubkey = point;
	return 0;
}

static int update_private_key(EVP_PKEY_CTX *ctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *eckey = EVP_PKEY_get0(p_key);
	const BIGNUM *d;
	int ret;

	d = EC_KEY_get0_private_key(eckey);
	if (!d) {
		fprintf(stderr, "private key not set\n");
		return -EINVAL;
	}

	if (smctx->prikey && !BN_cmp(d, smctx->prikey))
		return 0;

	ret = uadk_ecc_set_private_key(smctx->sess, eckey);
	if (ret)
		return ret;

	smctx->prikey = d;
	return 0;
}

static int openssl_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_SIGN sign_pfunc = NULL;

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_sign(openssl_meth, NULL, &sign_pfunc);
	if (!sign_pfunc) {
		fprintf(stderr, "sign_pfunc is NULL\n");
		return -1;
	}

	return (*sign_pfunc)(ctx, sig, siglen, tbs, tbslen);
}

static int openssl_verify(EVP_PKEY_CTX *ctx,
			  const unsigned char *sig, size_t siglen,
			  const unsigned char *tbs, size_t tbslen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_VERIFY verify_pfunc = NULL;

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_verify(openssl_meth, NULL, &verify_pfunc);
	if (!verify_pfunc) {
		fprintf(stderr, "verify_pfunc is NULL\n");
		return -1;
	}

	return (*verify_pfunc)(ctx, sig, siglen, tbs, tbslen);
}

static int openssl_encrypt(EVP_PKEY_CTX *ctx,
			   unsigned char *out, size_t *outlen,
			   const unsigned char *in, size_t inlen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_DEC enc_pfunc = NULL;

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_encrypt(openssl_meth, NULL, &enc_pfunc);
	if (!enc_pfunc) {
		fprintf(stderr, "enc_pfunc is NULL\n");
		return -1;
	}

	return (*enc_pfunc)(ctx, out, outlen, in, inlen);
}

static int openssl_decrypt(EVP_PKEY_CTX *ctx,
			   unsigned char *out, size_t *outlen,
			   const unsigned char *in, size_t inlen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_ENC dec_pfunc = NULL;

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_decrypt(openssl_meth, NULL, &dec_pfunc);
	if (!dec_pfunc) {
		fprintf(stderr, "dec_pfunc is NULL\n");
		return -1;
	}

	return (*dec_pfunc)(ctx, out, outlen, in, inlen);
}

static int sm2_sign_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sign_bin_to_ber(EC_KEY *ec, struct wd_dtb *r, struct wd_dtb *s,
			   unsigned char *sig, size_t *siglen)
{
	int ret = -EINVAL;
	ECDSA_SIG *e_sig;
	BIGNUM *br, *bs;
	int sltmp;

	e_sig = ECDSA_SIG_new();
	if (!e_sig) {
		fprintf(stderr, "failed to ECDSA_SIG_new\n");
		return -EINVAL;
	}

	br = BN_bin2bn((void *)r->data, r->dsize, NULL);
	if (!br) {
		fprintf(stderr, "failed to BN_bin2bn r\n");
		goto free_sig;
	}

	bs = BN_bin2bn((void *)s->data, s->dsize, NULL);
	if (!bs) {
		fprintf(stderr, "failed to BN_bin2bn s\n");
		goto free_r;
	}

	ret = ECDSA_SIG_set0(e_sig, br, bs);
	if (!ret) {
		fprintf(stderr, "failed to ECDSA_SIG_set0\n");
		ret = -EINVAL;
		goto free_s;
	}

	sltmp = i2d_ECDSA_SIG(e_sig, &sig);
	if (sltmp < 0) {
		fprintf(stderr, "failed to i2d_ECDSA_SIG\n");
		ret = -EINVAL;
		goto free_s;
	}
	*siglen = (size_t)sltmp;
	return 0;

free_s:
	BN_free(bs);
free_r:
	BN_free(br);
free_sig:
	ECDSA_SIG_free(e_sig);

	return ret;
}

static int sig_ber_to_bin(EC_KEY *ec, unsigned char *sig, size_t sig_len,
			  struct wd_dtb *r, struct wd_dtb *s)
{
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	ECDSA_SIG *e_sig = NULL;
	int ret, len1, len2;
	BIGNUM *b_r, *b_s;

	e_sig = ECDSA_SIG_new();
	if (!e_sig) {
		fprintf(stderr, "failed to ECDSA_SIG_new\n");
		return -ENOMEM;
	}

	if (d2i_ECDSA_SIG(&e_sig, &p, sig_len) == NULL) {
		fprintf(stderr, "d2i_ECDSA_SIG error\n");
		ret = -EINVAL;
		goto free_sig;
	}

	/* Ensure signature uses DER and doesn't have trailing garbage */
	len1 = i2d_ECDSA_SIG(e_sig, &der);
	if (len1 != sig_len || memcmp(sig, der, len1) != 0) {
		fprintf(stderr, "sig data error, derlen(%d), sig_len(%lu)\n",
		len1, sig_len);
		ret = -EINVAL;
		goto free_der;
	}

	b_r = (void *)ECDSA_SIG_get0_r((const ECDSA_SIG *)e_sig);
	if (!b_r) {
		fprintf(stderr, "failed to get r\n");
		ret = -EINVAL;
		goto free_der;
	}

	b_s = (void *)ECDSA_SIG_get0_s((const ECDSA_SIG *)e_sig);
	if (!b_s) {
		fprintf(stderr, "failed to get s\n");
		ret = -EINVAL;
		goto free_der;
	}

	len1 = BN_num_bytes(b_r);
	len2 = BN_num_bytes(b_s);
	if (len1 > UADK_ECC_MAX_KEY_BYTES || len2 > UADK_ECC_MAX_KEY_BYTES) {
		fprintf(stderr, "r or s bytes = (%d, %d) error\n", len1, len2);
		ret = -EINVAL;
		goto free_der;
	}
	r->dsize = BN_bn2bin(b_r, (void *)r->data);
	s->dsize = BN_bn2bin(b_s, (void *)s->data);
	ret = 0;
free_der:
	OPENSSL_free(der);
free_sig:
	ECDSA_SIG_free(e_sig);

	return ret;
}

static int cipher_bin_to_ber(const EVP_MD *md, struct wd_ecc_point *c1,
			     struct wd_dtb *c2, struct wd_dtb *c3,
			     unsigned char *ber, size_t *ber_len)
{
	struct sm2_ciphertext ctext_struct;
	int ciphertext_leni, ret;
	BIGNUM *x1, *y1;

	x1 = BN_bin2bn((void *)c1->x.data, c1->x.dsize, NULL);
	if (!x1) {
		fprintf(stderr, "failed to BN_bin2bn x1\n");
		return -ENOMEM;
	}

	y1 = BN_bin2bn((void *)c1->y.data, c1->y.dsize, NULL);
	if (!y1) {
		fprintf(stderr, "failed to BN_bin2bn y1\n");
		ret = -ENOMEM;
		goto free_x1;
	}

	ctext_struct.C1x = x1;
	ctext_struct.C1y = y1;
	ctext_struct.C3 = ASN1_OCTET_STRING_new();
	if (!ctext_struct.C3) {
		ret = -ENOMEM;
		goto free_y1;
	}

	ctext_struct.C2 = ASN1_OCTET_STRING_new();
	if (!ctext_struct.C2) {
		ret = -ENOMEM;
		goto free_y1;
	}

	if (!ASN1_OCTET_STRING_set(ctext_struct.C3, (void *)c3->data, c3->dsize)
		|| !ASN1_OCTET_STRING_set(ctext_struct.C2,
					  (void *)c2->data, c2->dsize)) {
		fprintf(stderr, "failed to ASN1_OCTET_STRING_set\n");
		ret = -EINVAL;
		goto free_y1;
	}

	ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct,
					     (unsigned char **)&ber);
	/* Ensure cast to size_t is safe */
	if (ciphertext_leni < 0) {
		ret = -EINVAL;
		goto free_y1;
	}
	*ber_len = (size_t)ciphertext_leni;
	ret = 0;
free_y1:
	BN_free(y1);
free_x1:
	BN_free(x1);

	return ret;
}

static int cipher_ber_to_bin(unsigned char *ber, size_t ber_len,
			     struct wd_ecc_point *c1,
			     struct wd_dtb *c2,
			     struct wd_dtb *c3)
{
	struct sm2_ciphertext *ctext_struct;
	int ret, len, len1;

	ctext_struct = d2i_SM2_Ciphertext(NULL, (const unsigned char **)&ber,
					  ber_len);
	if (!ctext_struct) {
		fprintf(stderr, "failed to d2i_SM2_Ciphertext\n");
		return -ENOMEM;
	}

	len = BN_num_bytes(ctext_struct->C1x);
	len1 = BN_num_bytes(ctext_struct->C1y);
	c1->x.data = malloc(len + len1 + ctext_struct->C2->length +
			    ctext_struct->C3->length);
	if (!c1->x.data) {
		ret = -ENOMEM;
		goto free_ctext;
	}
	c1->y.data = c1->x.data + len;
	c3->data = c1->y.data + len1;
	c2->data = c3->data + ctext_struct->C3->length;
	memcpy(c2->data, ctext_struct->C2->data, ctext_struct->C2->length);
	memcpy(c3->data, ctext_struct->C3->data, ctext_struct->C3->length);
	c2->dsize = ctext_struct->C2->length;
	c3->dsize = ctext_struct->C3->length;
	c1->x.dsize = BN_bn2bin(ctext_struct->C1x, (void *)c1->x.data);
	c1->y.dsize = BN_bn2bin(ctext_struct->C1y, (void *)c1->y.data);

	return 0;
free_ctext:
	SM2_Ciphertext_free(ctext_struct);
	return ret;
}

static size_t ec_field_size(const EC_GROUP *group)
{
	BIGNUM *p = BN_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	size_t field_size = 0;
	size_t p_bits;

	if (p == NULL || a == NULL || b == NULL)
		goto done;

	if (!EC_GROUP_get_curve(group, p, a, b, NULL))
		goto done;

	p_bits = BN_num_bits(p);
	field_size = BITS_TO_BYTES(p_bits);

done:
	BN_free(p);
	BN_free(a);
	BN_free(b);

	return field_size;
}

static int sm2_plaintext_size(const unsigned char *ct, size_t ct_size, size_t *pt_size)
{
	struct sm2_ciphertext *sm2_ctext;

	sm2_ctext = d2i_SM2_Ciphertext(NULL, &ct, ct_size);
	if (!sm2_ctext) {
		fprintf(stderr, "invalid sm2 encoding\n");
		return 0;
	}

	*pt_size = sm2_ctext->C2->length;
	SM2_Ciphertext_free(sm2_ctext);

	return 1;
}

static int sm2_ciphertext_size(const EC_KEY *key,
			       const EVP_MD *digest, size_t msg_len,
			       size_t *ct_size)
{
	const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
	const int md_size = EVP_MD_size(digest);
	size_t sz;

	if (field_size == 0 || md_size < 0)
		return 0;

	/*
	 * Integer and string are simple type; set constructed = 0, means
	 * primitive and definite length encoding.
	 */
	sz = ECC_POINT_SIZE(ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER))
		+ ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
		+ ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
	*ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

	return 1;
}

static int sm2_sign_init_iot(handle_t sess, struct wd_ecc_req *req,
			     unsigned char *digest, size_t digest_len)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wd_sm2_new_sign_out(sess);
	if (!ecc_out) {
		fprintf(stderr, "failed to new sign out\n");
		return UADK_DO_SOFT;
	}

	e.data = (void *)digest;
	e.dsize = digest_len;
	ecc_in = wd_sm2_new_sign_in(sess, &e, NULL, NULL, 1);
	if (!ecc_in) {
		fprintf(stderr, "failed to new sign in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_SM2_SIGN, ecc_in, ecc_out);

	return 0;
}

static int sm2_sign_check(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		  const unsigned char *tbs, size_t tbslen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	const int sig_sz = ECDSA_size(ec);

	if (!smctx || !smctx->sess) {
		fprintf(stderr, "smctx or sess NULL\n");
		return UADK_DO_SOFT;
	}

	if (sig_sz <= 0) {
		fprintf(stderr, "sig_sz error\n");
		return -EINVAL;
	}

	if (sig == NULL) {
		*siglen = (size_t)sig_sz;
		return 1;
	}

	if (*siglen < (size_t)sig_sz) {
		fprintf(stderr, "siglen(%lu) < sig_sz(%lu)\n", *siglen, (size_t)sig_sz);
		return -EINVAL;
	}

	if (tbslen > SM2_KEY_BYTES)
		return UADK_DO_SOFT;

	if (uadk_is_all_zero(tbs, tbslen))
		return UADK_DO_SOFT;

	return 0;
}

static int sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		    const unsigned char *tbs, size_t tbslen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	struct wd_ecc_req req;
	int ret;

	ret = sm2_sign_check(ctx, sig, siglen, tbs, tbslen);
	if (ret)
		goto do_soft;

	if (smctx->init_status != CTX_INIT_SUCC) {
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	memset(&req, 0, sizeof(req));
	ret = sm2_sign_init_iot(smctx->sess, &req, (void *)tbs, tbslen);
	if (ret)
		goto do_soft;

	ret = update_private_key(ctx);
	if (ret) {
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	ret = uadk_ecc_crypto(smctx->sess, &req, smctx);
	if (!ret) {
		fprintf(stderr, "failed to uadk_ecc_crypto, ret = %d\n", ret);
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	wd_sm2_get_sign_out_params(req.dst, &r, &s);
	ret = sign_bin_to_ber(NULL, r, s, sig, siglen);
	if (ret)
		goto uninit_iot;

	ret = 1;

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);
do_soft:
	if (ret != UADK_DO_SOFT){
		US_DEBUG("sm2_sign successed!\n");
		return ret;
	}
	fprintf(stderr, "sm2_sign failed, switch to execute openssl software calculation.\n");
	US_ERR("sm2_sign failed, switch to execute openssl software calculation.\n");
	return openssl_sign(ctx, sig, siglen, tbs, tbslen);
}

static int sm2_verify_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sm2_verify_init_iot(handle_t sess, struct wd_ecc_req *req,
			       struct wd_dtb *e, struct wd_dtb *r,
			       struct wd_dtb *s)
{
	struct wd_ecc_in *ecc_in;

	ecc_in = wd_sm2_new_verf_in(sess, e, r, s, NULL, 1);
	if (!ecc_in) {
		fprintf(stderr, "failed to new verf in\n");
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_SM2_VERIFY, ecc_in, NULL);

	return 0;
}

static int sm2_verify_check(EVP_PKEY_CTX *ctx,
			    const unsigned char *sig,
			    size_t siglen,
			    const unsigned char *tbs,
			    size_t tbslen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);

	if (!smctx || !smctx->sess) {
		fprintf(stderr, "smctx or sess NULL\n");
		return UADK_DO_SOFT;
	}

	if (tbslen > SM2_KEY_BYTES)
		return UADK_DO_SOFT;

	if (uadk_is_all_zero(tbs, tbslen))
		return UADK_DO_SOFT;

	return 0;
}

static int sm2_verify(EVP_PKEY_CTX *ctx,
		      const unsigned char *sig, size_t siglen,
		      const unsigned char *tbs, size_t tbslen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	unsigned char buf_r[UADK_ECC_MAX_KEY_BYTES] = {0};
	unsigned char buf_s[UADK_ECC_MAX_KEY_BYTES] = {0};
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	struct wd_dtb e = {0};
	struct wd_dtb r = {0};
	struct wd_dtb s = {0};
	struct wd_ecc_req req;
	int ret;

	ret = sm2_verify_check(ctx, sig, siglen, tbs, tbslen);
	if (ret){
		US_ERR("sm2_verify_check failed.\n");
		goto do_soft;
	}

	if (smctx->init_status != CTX_INIT_SUCC) {
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	r.data = (void *)buf_r;
	s.data = (void *)buf_s;
	r.bsize = UADK_ECC_MAX_KEY_BYTES;
	s.bsize = UADK_ECC_MAX_KEY_BYTES;
	ret = sig_ber_to_bin(ec, (void *)sig, siglen, &r, &s);
	if (ret)
		return ret;

	e.data = (void *)tbs;
	e.dsize = tbslen;
	memset(&req, 0, sizeof(req));
	ret = sm2_verify_init_iot(smctx->sess, &req, &e, &r, &s);
	if (ret)
		goto do_soft;

	ret = update_public_key(ctx);
	if (ret) {
		ret = UADK_DO_SOFT;
		US_ERR("sm2_verify_check failed,switch to soft.\n");
		goto uninit_iot;
	}

	ret = uadk_ecc_crypto(smctx->sess, &req, smctx);
	if (!ret) {
		ret = UADK_DO_SOFT;
		fprintf(stderr, "failed to uadk_ecc_crypto, ret = %d\n", ret);
		US_ERR("uadk_ecc_crypto failed,switch to soft.\n");
		goto uninit_iot;
	}

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
do_soft:
	if (ret != UADK_DO_SOFT){
		US_DEBUG("sm2_verify successed!\n");
		return ret;
	}
	fprintf(stderr, "sm2_verify failed,switch to execute openssl software calculation.\n");
	US_ERR("sm2_verify failed,switch to execute openssl software calculation.\n");
	return openssl_verify(ctx, sig, siglen, tbs, tbslen);
}

static int sm2_encrypt_init_iot(handle_t sess, struct wd_ecc_req *req,
				unsigned char *in, size_t inlen)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wd_sm2_new_enc_out(sess, inlen);
	if (!ecc_out) {
		fprintf(stderr, "failed to new enc out\n");
		return UADK_DO_SOFT;
	}

	e.data = (void *)in;
	e.dsize = inlen;
	ecc_in = wd_sm2_new_enc_in(sess, NULL, &e);
	if (!ecc_in) {
		fprintf(stderr, "failed to new enc in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_SM2_ENCRYPT, ecc_in, ecc_out);
	return 0;
}

static int sm2_encrypt_check(EVP_PKEY_CTX *ctx,
			     unsigned char *out, size_t *outlen,
			     const unsigned char *in, size_t inlen)
{
	US_DEBUG("sm2_encrypt_check started.\n");
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	const EVP_MD *md;
	int c3_size;

	if (!smctx || !smctx->sess) {
		fprintf(stderr, "smctx or sess NULL\n");
		return UADK_DO_SOFT;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
	c3_size = EVP_MD_size(md);
	if (c3_size <= 0) {
		fprintf(stderr, "c3 size error\n");
		return 0;
	}

	if (!out) {
		if (!sm2_ciphertext_size(ec, md, inlen, outlen))
			return -1;
		else
			return 1;
	}

	if (inlen > UINT_MAX)
		return UADK_DO_SOFT;

	return 0;
}

static int sm2_encrypt_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sm2_encrypt(EVP_PKEY_CTX *ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen)
{

	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	struct wd_ecc_point *c1 = NULL;
	struct wd_dtb *c2 = NULL;
	struct wd_dtb *c3 = NULL;
	struct wd_ecc_req req;
	const EVP_MD *md;
	int ret;

	ret = sm2_encrypt_check(ctx, out, outlen, in, inlen);
	if (ret){
		US_ERR("sm2_encrypt_check failed ,then switch to soft!\n");
		goto do_soft;
	}

	if (smctx->init_status != CTX_INIT_SUCC) {
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	memset(&req, 0, sizeof(req));
	ret = sm2_encrypt_init_iot(smctx->sess, &req, (void *)in, inlen);
	if (ret){
		US_ERR("sm2_encrypt_init_iot failed , then switch to soft!\n");
		goto do_soft;
	}

	ret = update_public_key(ctx);
	if (ret) {
		ret = UADK_DO_SOFT;
		US_ERR("update_public_key failed , then switch to soft!\n");
		goto uninit_iot;
	}

	ret = uadk_ecc_crypto(smctx->sess, &req, smctx);
	if (!ret) {
		ret = UADK_DO_SOFT;
		fprintf(stderr, "failed to uadk_ecc_crypto, ret = %d\n", ret);
		US_ERR("uadk_ecc_crypto failed.\n");
		goto uninit_iot;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
	wd_sm2_get_enc_out_params(req.dst, &c1, &c2, &c3);
	ret = cipher_bin_to_ber(md, c1, c2, c3, out, outlen);
	if (ret)
		goto uninit_iot;

	ret = 1;
uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);
do_soft:
	if (ret != UADK_DO_SOFT)
		return ret;

	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_encrypt(ctx, out, outlen, in, inlen);
}

static int sm2_decrypt_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sm2_decrypt_check(EVP_PKEY_CTX *ctx,
			     unsigned char *out, size_t *outlen,
			     const unsigned char *in, size_t inlen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	const EVP_MD *md;
	int hash_size;

	if (!smctx || !smctx->sess) {
		fprintf(stderr, "smctx or sess NULL\n");
		return UADK_DO_SOFT;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
	hash_size = EVP_MD_size(md);
	if (hash_size <= 0) {
		fprintf(stderr, "hash size = %d error\n", hash_size);
		return 0;
	}

	if (!out) {
		if (!sm2_plaintext_size(in, inlen, outlen))
			return -1;
		else
			return 1;
	}

	return 0;
}

static int sm2_decrypt_init_iot(handle_t sess,
				struct wd_ecc_req *req,
				struct wd_ecc_point *c1,
				struct wd_dtb *c2,
				struct wd_dtb *c3)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;

	ecc_out = wd_sm2_new_dec_out(sess, c2->dsize);
	if (!ecc_out) {
		fprintf(stderr, "failed to new dec out\n");
		return UADK_DO_SOFT;
	}

	ecc_in = wd_sm2_new_dec_in(sess, c1, c2, c3);
	if (!ecc_in) {
		fprintf(stderr, "failed to new dec in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_SM2_DECRYPT, ecc_in, ecc_out);

	return 0;
}

static void sm2_decrypt_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_in(sess, req->src);
	wd_ecc_del_out(sess, req->dst);
}

static int sm2_get_plaintext(struct wd_ecc_req *req,
			     unsigned char *out, size_t *outlen)
{
	struct wd_dtb *ptext = NULL;

	wd_sm2_get_dec_out_params(req->dst, &ptext);
	if (*outlen < ptext->dsize) {
		fprintf(stderr, "outlen(%lu) < (%u)\n", *outlen, ptext->dsize);
		return -EINVAL;
	}

	memcpy(out, ptext->data, ptext->dsize);
	*outlen = ptext->dsize;

	return 0;
}

static int sm2_decrypt(EVP_PKEY_CTX *ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	struct wd_ecc_point c1;
	struct wd_ecc_req req;
	struct wd_dtb c2, c3;
	const EVP_MD *md;
	int ret;

	ret = sm2_decrypt_check(ctx, out, outlen, in, inlen);
	if (ret)
		goto do_soft;

	if (smctx->init_status != CTX_INIT_SUCC) {
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;

	ret = cipher_ber_to_bin((void *)in, inlen, &c1, &c2, &c3);
	if (ret)
		goto do_soft;

	if (c3.dsize != EVP_MD_size(md)) {
		fprintf(stderr, "c3 dsize != hash_size\n");
		ret = -EINVAL;
		goto free_c1;
	}

	memset(&req, 0, sizeof(req));
	ret = sm2_decrypt_init_iot(smctx->sess, &req, &c1, &c2, &c3);
	if (ret)
		goto free_c1;

	ret = update_private_key(ctx);
	if (ret) {
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	ret = uadk_ecc_crypto(smctx->sess, &req, smctx);
	if (!ret) {
		ret = UADK_DO_SOFT;
		fprintf(stderr, "failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	ret = sm2_get_plaintext(&req, out, outlen);
	if (ret)
		goto uninit_iot;

	ret = 1;
uninit_iot:
	sm2_decrypt_uninit_iot(smctx->sess, &req);
free_c1:
	free(c1.x.data);
do_soft:
	if (ret != UADK_DO_SOFT)
		return ret;

	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_decrypt(ctx, out, outlen, in, inlen);
}

static void sm2_cleanup(EVP_PKEY_CTX *ctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);

	if (!smctx)
		return;

	EC_GROUP_free(smctx->ctx.gen_group);
	OPENSSL_free(smctx->ctx.id);

	if (smctx->sess)
		wd_ecc_free_sess(smctx->sess);

	BN_free(smctx->order);
	free(smctx);
	EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int sm2_init(EVP_PKEY_CTX *ctx)
{
	US_DEBUG("sm2_init started.\n");
	struct sm2_ctx *smctx;
	int ret;

	smctx = malloc(sizeof(*smctx));
	if (!smctx) {
		fprintf(stderr, "failed to alloc sm2 ctx\n");
		return 0;
	}

	memset(smctx, 0, sizeof(*smctx));

	ret = uadk_init_ecc();
	if (ret) {
		fprintf(stderr, "failed to uadk_init_ecc, ret = %d\n", ret);
		US_ERR(""failed to uadk_init_ecc, ret = %d\n", ret");
		smctx->init_status = CTX_INIT_FAIL;
		goto end;
	}

	ret = sm2_update_sess(smctx);
	if (ret) {
		fprintf(stderr, "failed to update sess\n");
		US_ERR("failed to update sess\n"");
		smctx->init_status = CTX_INIT_FAIL;
		goto end;
	}

	smctx->init_status = CTX_INIT_SUCC;
	US_DEBUG("sm2_init successed.\n");
end:
	EVP_PKEY_CTX_set_data(ctx, smctx);
	EVP_PKEY_CTX_set0_keygen_info(ctx, NULL, 0);

	return 1;
}

static int sm2_set_ctx_id(struct sm2_ctx *smctx, int p1, const void *p2)
{
	uint8_t *tmp_id;

	if (p1 > 0) {
		tmp_id = OPENSSL_malloc(p1);
		if (tmp_id == NULL) {
			fprintf(stderr, "failed to malloc\n");
			return 0;
		}
		memcpy(tmp_id, p2, p1);
		OPENSSL_free(smctx->ctx.id);
		smctx->ctx.id = tmp_id;
	} else {
		/* Set null-ID */
		OPENSSL_free(smctx->ctx.id);
		smctx->ctx.id = NULL;
	}
	smctx->ctx.id_len = (size_t)p1;
	smctx->ctx.id_set = 1;

	return 1;
}

static int sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EC_GROUP *group;

	if (!smctx) {
		fprintf(stderr, "smctx not set.\n");
		return 0;
	}

	switch (type) {
	case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
		group = EC_GROUP_new_by_curve_name(p1);
		if (group == NULL) {
			fprintf(stderr, "invalid curve %d\n", p1);
			return 0;
		}
		EC_GROUP_free(smctx->ctx.gen_group);
		smctx->ctx.gen_group = group;
		return 1;
	case EVP_PKEY_CTRL_EC_PARAM_ENC:
		if (smctx->ctx.gen_group == NULL) {
			fprintf(stderr, "no parameters set\n");
			return 0;
		}
		EC_GROUP_set_asn1_flag(smctx->ctx.gen_group, p1);
		return 1;
	case EVP_PKEY_CTRL_MD:
		smctx->ctx.md = p2;
		if (smctx->init_status != CTX_INIT_SUCC)
			return 1;

		if (sm2_update_sess(smctx)) {
			fprintf(stderr, "failed to set MD\n");
			return 0;
		}
		return 1;
	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD **)p2 = smctx->ctx.md;
		return 1;
	case EVP_PKEY_CTRL_SET1_ID:
		return sm2_set_ctx_id(smctx, p1, p2);
	case EVP_PKEY_CTRL_GET1_ID:
		memcpy(p2, smctx->ctx.id, smctx->ctx.id_len);
		return 1;
	case EVP_PKEY_CTRL_GET1_ID_LEN:
		*(size_t *)p2 = smctx->ctx.id_len;
		return 1;
	case EVP_PKEY_CTRL_DIGESTINIT:
		/* Nothing to be inited, for suppress the error */
		return 1;
	default:
		fprintf(stderr, "sm2 ctrl type = %d error\n", type);
		return UADK_E_INVALID;
	}
}

static int sm2_ctrl_str(EVP_PKEY_CTX *ctx,
			const char *type, const char *value)
{
	if (strcmp(type, "ec_paramgen_curve") == 0) {
		int nid;

		if ((EC_curve_nist2nid(value) == NID_undef)
			&& (OBJ_sn2nid(value) == NID_undef)
			&& (OBJ_ln2nid(value) == NID_undef)) {
			fprintf(stderr, "invalid curve\n");
			return 0;
		}

		nid = EC_curve_nist2nid(value);
		if (nid == NID_undef) {
			nid = OBJ_sn2nid(value);
			if (nid == NID_undef)
				nid = OBJ_ln2nid(value);
		}
		return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
	} else if (strcmp(type, "ec_param_enc") == 0) {
		int param_enc;

		if (strcmp(value, "explicit") == 0)
			param_enc = 0;
		else if (strcmp(value, "named_curve") == 0)
			param_enc = OPENSSL_EC_NAMED_CURVE;
		else
			return UADK_E_INVALID;
		return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
	}

	return UADK_E_INVALID;
}

static int get_sm2_param(struct sm2_param *sm2_param, BN_CTX *ctx)
{
	sm2_param->p = BN_CTX_get(ctx);
	if (!sm2_param->p)
		goto end;

	sm2_param->a = BN_CTX_get(ctx);
	if (!sm2_param->a)
		goto end;

	sm2_param->b = BN_CTX_get(ctx);
	if (!sm2_param->b)
		goto end;

	sm2_param->xG = BN_CTX_get(ctx);
	if (!sm2_param->xG)
		goto end;

	sm2_param->yG = BN_CTX_get(ctx);
	if (!sm2_param->yG)
		goto end;

	sm2_param->xA = BN_CTX_get(ctx);
	if (!sm2_param->xA)
		goto end;

	sm2_param->yA = BN_CTX_get(ctx);
	if (!sm2_param->yA)
		goto end;

	return 1;

end:
	fprintf(stderr, "failed to malloc params\n");
	return 0;
}

static int check_digest_evp_lib(const EVP_MD *digest, EVP_MD_CTX *hash,
				const size_t id_len, const uint8_t *id)
{
	uint8_t e_byte;
	uint16_t entl;

	if (!EVP_DigestInit(hash, digest)) {
		fprintf(stderr, "error evp lib\n");
		return 0;
	}

	/* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
	if (id_len >= (UINT16_MAX >> TRANS_BITS_BYTES_SHIFT)) {
		fprintf(stderr, "id too large\n");
		return 0;
	}

	entl = (uint16_t)(id_len << TRANS_BITS_BYTES_SHIFT);

	/* Update the most significant (first) byte of 'entl' */
	e_byte = GET_MS_BYTE(entl);
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		fprintf(stderr, "error evp lib\n");
		return 0;
	}

	/* Update the least significant (second) byte of 'entl' */
	e_byte = GET_LS_BYTE(entl);
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		fprintf(stderr, "error evp lib\n");
		return 0;
	}

	if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
		fprintf(stderr, "error evp lib\n");
		return 0;
	}

	return 1;
}

static int check_equation_param(struct sm2_param *param, EVP_MD_CTX *hash,
				uint8_t *buf, int p_bytes)
{
	if (BN_bn2binpad(param->a, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->b, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes)) {
		fprintf(stderr, "failed to check equation param\n");
		return 0;
	}

	return 1;
}


static int check_base_point_group_param(struct sm2_param *param, BN_CTX *ctx,
					const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);

	if (!EC_POINT_get_affine_coordinates(group,
					     EC_GROUP_get0_generator(group),
					     param->xG, param->yG, ctx)) {
		fprintf(stderr, "failed to check base point group param\n");
		return 0;
	}

	return 1;
}

static int check_base_point_param(struct sm2_param *param, EVP_MD_CTX *hash,
				  uint8_t *buf, int p_bytes)
{
	if (BN_bn2binpad(param->xG, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->yG, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes)) {
		fprintf(stderr, "failed to check base point param\n");
		return 0;
	}

	return 1;
}

static int check_pkey_point_group_param(struct sm2_param *param, BN_CTX *ctx,
					const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);

	if (!EC_POINT_get_affine_coordinates(group,
					     EC_KEY_get0_public_key(key),
					     param->xA, param->yA, ctx)) {
		fprintf(stderr, "failed to check pkey point group param\n");
		return 0;
	}
	return 1;
}

static int check_pkey_point_param(struct sm2_param *param, EVP_MD_CTX *hash,
				  uint8_t *buf, int p_bytes, uint8_t *out)
{
	if (BN_bn2binpad(param->xA, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->yA, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    !EVP_DigestFinal(hash, out, NULL)) {
		fprintf(stderr, "failed to check pkey point param\n");
		return 0;
	}

	return 1;
}

static int sm2_compute_z_digest(uint8_t *out, const EVP_MD *digest,
				const uint8_t *id, const size_t id_len,
				const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);
	struct sm2_param *param = NULL;
	EVP_MD_CTX *hash = NULL;
	uint8_t *buf = NULL;
	BN_CTX *ctx = NULL;
	int p_bytes;
	int ret = 0;

	hash = EVP_MD_CTX_new();
	if (!hash)
		return ret;

	ctx = BN_CTX_new();
	if (!ctx)
		goto free_hash;

	param = OPENSSL_zalloc(sizeof(struct sm2_param));
	if (!param) {
		fprintf(stderr, "failed to malloc sm2 param\n");
		goto free_ctx;
	}

	if (!get_sm2_param(param, ctx))
		goto free_param;

	if (!check_digest_evp_lib(digest, hash, id_len, id))
		goto free_param;

	if (!EC_GROUP_get_curve(group, param->p, param->a, param->b, ctx)) {
		fprintf(stderr, "failed to get curve\n");
		goto free_param;
	}

	p_bytes = BN_num_bytes(param->p);
	buf = OPENSSL_zalloc(p_bytes);
	if (!buf) {
		fprintf(stderr, "failed to malloc buf\n");
		goto free_param;
	}

	if (!check_equation_param(param, hash, buf, p_bytes) ||
	    !check_base_point_group_param(param, ctx, key) ||
	    !check_base_point_param(param, hash, buf, p_bytes) ||
	    !check_pkey_point_group_param(param, ctx, key) ||
	    !check_pkey_point_param(param, hash, buf, p_bytes, out))
		goto free_buf;

	ret = 1;

free_buf:
	OPENSSL_free(buf);
free_param:
	OPENSSL_free(param);
free_ctx:
	BN_CTX_free(ctx);
free_hash:
	EVP_MD_CTX_free(hash);
	return ret;
}

static int sm2_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	const EVP_MD *md = EVP_MD_CTX_md(mctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	uint8_t z[EVP_MAX_MD_SIZE];
	int mdlen = EVP_MD_size(md);

	if (!smctx) {
		fprintf(stderr, "smctx not set in digest custom\n");
		return 0;
	}

	if (!smctx->ctx.id_set) {
		/*
		 * An ID value must be set. The specifications are not clear whether a
		 * NULL is allowed. We only allow it if set explicitly for maximum
		 * flexibility.
		 */
		fprintf(stderr, "id not set\n");
		return 0;
	}

	if (mdlen < 0) {
		fprintf(stderr, "invalid digest size %d\n", mdlen);
		return 0;
	}

	/* Get hashed prefix 'z' of tbs message */
	if (!sm2_compute_z_digest(z, md, smctx->ctx.id, smctx->ctx.id_len, ec))
		return 0;

	return EVP_DigestUpdate(mctx, z, (size_t)mdlen);
}

static int sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	struct sm2_ctx *dctx, *sctx;

	if (!sm2_init(dst))
		return 0;
	sctx = EVP_PKEY_CTX_get_data(src);
	dctx = EVP_PKEY_CTX_get_data(dst);
	if (sctx->ctx.gen_group != NULL) {
		dctx->ctx.gen_group = EC_GROUP_dup(sctx->ctx.gen_group);
		if (dctx->ctx.gen_group == NULL) {
			fprintf(stderr, "failed to EC GROUP dup\n");
			sm2_cleanup(dst);
			return 0;
		}
	}

	if (sctx->ctx.id != NULL) {
		dctx->ctx.id = OPENSSL_malloc(sctx->ctx.id_len);
		if (dctx->ctx.id == NULL) {
			fprintf(stderr, "failed to malloc\n");
			sm2_cleanup(dst);
			return 0;
		}
		memcpy(dctx->ctx.id, sctx->ctx.id, sctx->ctx.id_len);
	}
	dctx->ctx.id_len = sctx->ctx.id_len;
	dctx->ctx.id_set = sctx->ctx.id_set;
	dctx->ctx.md = sctx->ctx.md;

	return 1;
}

int uadk_sm2_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	US_DEBUG("uadk_sm2_create_pmeth start.\n");
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	if (pkey_meth->sm2){
		US_DEBUG("have created EVP_PKEY_METHOD of sm2.\n");
		return 1;
	}

	meth = EVP_PKEY_meth_new(EVP_PKEY_SM2, 0);
	if (meth == NULL) {
		fprintf(stderr, "failed to EVP_PKEY_meth_new\n");
		US_ERR("failed to EVP_PKEY_meth_new\n");
		return 0;
	}

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_copy(meth, openssl_meth);

	if (!uadk_support_algorithm("sm2")) {
		pkey_meth->sm2 = meth;
		return 1;
	}

	EVP_PKEY_meth_set_init(meth, sm2_init);
	EVP_PKEY_meth_set_copy(meth, sm2_copy);
	EVP_PKEY_meth_set_ctrl(meth, sm2_ctrl, sm2_ctrl_str);
	EVP_PKEY_meth_set_digest_custom(meth, sm2_digest_custom);
	EVP_PKEY_meth_set_cleanup(meth, sm2_cleanup);
	EVP_PKEY_meth_set_encrypt(meth, sm2_encrypt_init, sm2_encrypt);
	EVP_PKEY_meth_set_decrypt(meth, sm2_decrypt_init, sm2_decrypt);
	EVP_PKEY_meth_set_sign(meth, sm2_sign_init, sm2_sign);
	EVP_PKEY_meth_set_verify(meth, sm2_verify_init, sm2_verify);
	pkey_meth->sm2 = meth;
	
	US_DEBUG("uadk_sm2_create_pmeth successed.\n");
	return 1;
}

void uadk_sm2_delete_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	if (!pkey_meth || !pkey_meth->sm2)
		return;

	EVP_PKEY_meth_free(pkey_meth->sm2);
	pkey_meth->sm2 = NULL;
}
