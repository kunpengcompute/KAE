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
#include <errno.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "v2/alg/pkey/uadk_pkey.h"
#include "v2/uadk.h"

#define ECC128BITS	128
#define ECC192BITS	192
#define ECC224BITS	224
#define ECC256BITS	256
#define ECC320BITS	320
#define ECC384BITS	384
#define ECC521BITS	521

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

typedef ECDSA_SIG* (*PFUNC_SIGN_SIG)(const unsigned char *,
				     int,
				     const BIGNUM *,
				     const BIGNUM *,
				     EC_KEY *);

typedef int (*PFUNC_VERIFY_SIG)(const unsigned char *,
				int,
				const ECDSA_SIG *,
				EC_KEY *eckey);

typedef int (*PFUNC_GEN_KEY)(EC_KEY *);

typedef int (*PFUNC_COMP_KEY)(unsigned char **,
			      size_t *,
			      const EC_POINT *,
			      const EC_KEY *);


static EC_KEY_METHOD *uadk_ec_method;

static void init_dtb_param(void *dtb, char *start,
			   __u32 dsz, __u32 bsz, __u32 num)
{
	struct wd_dtb *tmp = dtb;
	char *buff = start;
	int i = 0;

	while (i++ < num) {
		tmp->data = buff;
		tmp->dsize = dsz;
		tmp->bsize = bsz;
		tmp += 1;
		buff += bsz;
	}
}

static void fill_ecc_cv_param(struct wd_ecc_curve *pparam,
			      struct curve_param *cv_param,
			      BIGNUM *g_x, BIGNUM *g_y)
{
	pparam->p.dsize = BN_bn2bin(cv_param->p, (void *)pparam->p.data);
	pparam->a.dsize = BN_bn2bin(cv_param->a, (void *)pparam->a.data);
	if (!pparam->a.dsize) {
		pparam->a.dsize = 1;
		pparam->a.data[0] = 0;
	}

	pparam->b.dsize = BN_bn2bin(cv_param->b, (void *)pparam->b.data);
	if (!pparam->b.dsize) {
		pparam->b.dsize = 1;
		pparam->b.data[0] = 0;
	}

	pparam->g.x.dsize = BN_bn2bin(g_x, (void *)pparam->g.x.data);
	pparam->g.y.dsize = BN_bn2bin(g_y, (void *)pparam->g.y.data);
	pparam->n.dsize = BN_bn2bin(cv_param->order, (void *)pparam->n.data);
}

static int set_sess_setup_cv(const EC_GROUP *group,
			     struct wd_ecc_curve_cfg *cv)
{
	struct wd_ecc_curve *pparam = cv->cfg.pparam;
	struct curve_param *cv_param;
	BIGNUM *g_x, *g_y;
	int ret = -1;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	if (!ctx)
		return ret;

	BN_CTX_start(ctx);

	cv_param = OPENSSL_malloc(sizeof(struct curve_param));
	if (!cv_param)
		goto free_ctx;

	cv_param->p = BN_CTX_get(ctx);
	if (!cv_param->p)
		goto free_cv;

	cv_param->a = BN_CTX_get(ctx);
	if (!cv_param->a)
		goto free_cv;

	cv_param->b = BN_CTX_get(ctx);
	if (!cv_param->b)
		goto free_cv;

	g_x = BN_CTX_get(ctx);
	if (!g_x)
		goto free_cv;

	g_y = BN_CTX_get(ctx);
	if (!g_y)
		goto free_cv;

	ret = uadk_get_curve(group, cv_param->p, cv_param->a, cv_param->b, ctx);
	if (ret)
		goto free_cv;

	cv_param->g = EC_GROUP_get0_generator(group);
	if (!cv_param->g)
		goto free_cv;

	ret = uadk_get_affine_coordinates(group, cv_param->g, g_x, g_y, ctx);
	if (ret)
		goto free_cv;

	cv_param->order = EC_GROUP_get0_order(group);
	if (!cv_param->order)
		goto free_cv;

	fill_ecc_cv_param(pparam, cv_param, g_x, g_y);
	cv->type = WD_CV_CFG_PARAM;
	ret = 0;

free_cv:
	OPENSSL_free(cv_param);
free_ctx:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}

static int get_smallest_hw_keybits(int bits)
{
	if (bits > ECC384BITS)
		return ECC521BITS;
	else if (bits > ECC320BITS)
		return ECC384BITS;
	else if (bits > ECC256BITS)
		return ECC320BITS;
	else if (bits > ECC192BITS)
		return ECC256BITS;
	else if (bits > ECC128BITS)
		return ECC192BITS;
	else
		return ECC128BITS;
}

static handle_t ecc_alloc_sess(const EC_KEY *eckey, char *alg)
{
	char buff[UADK_ECC_MAX_KEY_BYTES * UADK_ECC_CV_PARAM_NUM];
	struct sched_params sch_p = {0};
	struct wd_ecc_sess_setup sp;
	struct wd_ecc_curve param;
	struct uacce_dev *dev;
	const EC_GROUP *group;
	const BIGNUM *order;
	int ret, key_bits;
	handle_t sess;

	dev = wd_get_accel_dev(alg);
	if (!dev)
		return 0;

	init_dtb_param(&param, buff, 0, UADK_ECC_MAX_KEY_BYTES,
		       UADK_ECC_CV_PARAM_NUM);

	memset(&sp, 0, sizeof(sp));
	sp.cv.cfg.pparam = &param;
	group = EC_KEY_get0_group(eckey);
	ret = set_sess_setup_cv(group, &sp.cv);
	if (ret)
		goto free_dev;

	order = EC_GROUP_get0_order(group);
	if (!order)
		goto free_dev;

	key_bits = BN_num_bits(order);
	sp.alg = alg;
	sp.key_bits = get_smallest_hw_keybits(key_bits);
	sp.rand.cb = uadk_ecc_get_rand;
	sp.rand.usr = (void *)order;
	sch_p.numa_id = dev->numa_id;
	sp.sched_param = &sch_p;
	sess = wd_ecc_alloc_sess(&sp);
	if (!sess)
		fprintf(stderr, "failed to alloc ecc sess\n");

	free(dev);
	return sess;

free_dev:
	free(dev);
	return (handle_t)0;
}

static int check_ecc_bit_useful(const int bits)
{
	switch (bits) {
	case ECC128BITS:
	case ECC192BITS:
	case ECC224BITS:
	case ECC256BITS:
	case ECC320BITS:
	case ECC384BITS:
	case ECC521BITS:
		return 1;
	default:
		break;
	}

	return 0;
}

static int eckey_check(const EC_KEY *eckey)
{
	const EC_GROUP *group;
	const BIGNUM *order;
	const EC_POINT *g;
	int bits;

	if (!eckey) {
		fprintf(stderr, "eckey is NULL\n");
		return -1;
	}

	group = EC_KEY_get0_group(eckey);
	if (!group) {
		fprintf(stderr, "group is NULL\n");
		return -1;
	}

	order = EC_GROUP_get0_order(group);
	g = EC_GROUP_get0_generator(group);
	if (!order || !g) {
		fprintf(stderr, "order or g is NULL\n");
		return -1;
	}

	/* Field GF(2m) is not supported by uadk */
	if (!uadk_prime_field(group))
		return UADK_DO_SOFT;

	bits = BN_num_bits(order);
	if (!check_ecc_bit_useful(bits))
		return UADK_DO_SOFT;

	return 0;
}

static int ecdsa_do_sign_check(EC_KEY *eckey,
			       const unsigned char *dgst, int dlen,
			       const BIGNUM *k, const BIGNUM *r)
{
	const BIGNUM *priv_key;
	int ret;

	if (!dgst) {
		fprintf(stderr, "eckey or dgst NULL\n");
		return -1;
	}

	if (dlen <= 0) {
		fprintf(stderr, "dlen error, dlen = %d", dlen);
		return -1;
	}

	if (k || r)
		return UADK_DO_SOFT;

	ret = eckey_check(eckey);
	if (ret)
		return ret;

	priv_key = EC_KEY_get0_private_key(eckey);
	if (!priv_key) {
		fprintf(stderr, "priv_key is NULL\n");
		return -1;
	}
	return 0;
}

static int set_digest(handle_t sess, struct wd_dtb *e,
		      struct wd_dtb *sdgst, EC_KEY *eckey)
{
	const unsigned char *dgst = (const unsigned char *)sdgst->data;
	const EC_GROUP *group = EC_KEY_get0_group(eckey);
	const BIGNUM *order = EC_GROUP_get0_order(group);
	unsigned int order_bits = BN_num_bits(order);
	unsigned int dlen = sdgst->dsize;
	BIGNUM *m;

	if (dlen << TRANS_BITS_BYTES_SHIFT > order_bits) {
		m = BN_new();

		/* Need to truncate digest if it is too long: first truncate
		 * whole bytes
		 */
		dlen = BITS_TO_BYTES(order_bits);
		if (!BN_bin2bn(dgst, dlen, m)) {
			fprintf(stderr, "failed to BN_bin2bn digest\n");
			BN_free(m);
			return -1;
		}

		/* If the length of digest is still longer than the length
		 * of the base point order, truncate remaining bits with a
		 * shift to that length
		 */
		if (dlen << TRANS_BITS_BYTES_SHIFT > order_bits &&
		    !BN_rshift(m, m, DGST_SHIFT_NUM(order_bits))) {
			fprintf(stderr, "failed to truncate input digest\n");
			BN_free(m);
			return -1;
		}
		e->dsize = BN_bn2bin(m, (void *)e->data);
		BN_free(m);
	} else {
		e->data = (void *)dgst;
		e->dsize = dlen;
	}

	if (uadk_is_all_zero((void *)e->data, (size_t)e->dsize))
		return UADK_DO_SOFT;

	return 0;
}

static int ecdsa_sign_init_iot(handle_t sess, struct wd_ecc_req *req,
			       struct wd_dtb *dgst, EC_KEY *eckey)
{
	char buff[UADK_ECC_MAX_KEY_BYTES];
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = { 0 };
	int ret;

	ecc_out = wd_ecdsa_new_sign_out(sess);
	if (!ecc_out) {
		fprintf(stderr, "failed to new sign out\n");
		return UADK_DO_SOFT;
	}

	e.data = buff;
	ret = set_digest(sess, &e, dgst, eckey);
	if (ret)
		goto err;

	ecc_in = wd_ecdsa_new_sign_in(sess, &e, NULL);
	if (!ecc_in) {
		fprintf(stderr, "failed to new ecdsa sign in\n");
		ret = UADK_DO_SOFT;
		goto err;
	}

	uadk_ecc_fill_req(req, WD_ECDSA_SIGN, ecc_in, ecc_out);
	return 0;
err:
	wd_ecc_del_out(sess, ecc_out);

	return ret;
}

static ECDSA_SIG *openssl_do_sign(const unsigned char *dgst, int dlen,
				  const BIGNUM *in_kinv, const BIGNUM *in_r,
				  EC_KEY *eckey)
{
	PFUNC_SIGN_SIG sign_sig_pfunc = NULL;
	EC_KEY_METHOD *openssl_meth;

	openssl_meth = (EC_KEY_METHOD *)EC_KEY_OpenSSL();
	EC_KEY_METHOD_get_sign(openssl_meth, NULL, NULL,
			       &sign_sig_pfunc);
	if (!sign_sig_pfunc) {
		fprintf(stderr, "sign_sig_pfunc is NULL\n");
		return NULL;
	}

	return (*sign_sig_pfunc)(dgst, dlen, in_kinv, in_r, eckey);
}

static ECDSA_SIG *create_ecdsa_sig(struct wd_ecc_req *req)
{
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	BIGNUM *br, *bs;
	ECDSA_SIG *sig;
	int ret;

	sig = ECDSA_SIG_new();
	if (!sig) {
		fprintf(stderr, "failed to ECDSA_SIG_new\n");
		return NULL;
	}

	br = BN_new();
	bs = BN_new();
	if (!br || !bs) {
		fprintf(stderr, "failed to BN_new r or s\n");
		goto err;
	}

	ret = ECDSA_SIG_set0(sig, br, bs);
	if (!ret) {
		fprintf(stderr, "failed to ECDSA_SIG_set0\n");
		goto err;
	}

	wd_ecdsa_get_sign_out_params(req->dst, &r, &s);
	if (!BN_bin2bn((void *)r->data, r->dsize, br) ||
	    !BN_bin2bn((void *)s->data, s->dsize, bs)) {
		fprintf(stderr, "failed to BN_bin2bn r or s\n");
		goto err;
	}

	return sig;
err:
	ECDSA_SIG_free(sig);
	BN_free(br);
	BN_free(bs);
	return NULL;
}

static ECDSA_SIG *ecdsa_do_sign(const unsigned char *dgst, int dlen,
				const BIGNUM *in_kinv, const BIGNUM *in_r,
				EC_KEY *eckey)
{
	struct wd_ecc_req req;
	ECDSA_SIG *sig = NULL;
	struct wd_dtb tdgst;
	handle_t sess;
	int ret;

	ret = ecdsa_do_sign_check(eckey, dgst, dlen, in_kinv, in_r);
	if (ret)
		goto do_soft;

	ret = uadk_init_ecc();
	if (ret)
		goto do_soft;

	sess = ecc_alloc_sess(eckey, "ecdsa");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	tdgst.data = (void *)dgst;
	tdgst.dsize = dlen;
	ret = ecdsa_sign_init_iot(sess, &req, &tdgst, eckey);
	if (ret)
		goto free_sess;

	ret = uadk_ecc_set_private_key(sess, eckey);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (!ret)
		goto uninit_iot;

	sig = create_ecdsa_sig(&req);

	wd_ecc_del_in(sess, req.src);
	wd_ecc_del_out(sess, req.dst);
	wd_ecc_free_sess(sess);

	return sig;

uninit_iot:
	wd_ecc_del_in(sess, req.src);
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_sign(dgst, dlen, in_kinv, in_r, eckey);
}

static int ecdsa_sign(int type, const unsigned char *dgst, int dlen,
		      unsigned char *sig, unsigned int *siglen,
		      const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
	ECDSA_SIG *s;

	if (!dgst || dlen <= 0) {
		fprintf(stderr, "input param error, dlen = %d\n", dlen);
		goto err;
	}

	s = ecdsa_do_sign(dgst, dlen, kinv, r, eckey);
	if (!s) {
		fprintf(stderr, "failed to ecdsa do sign\n");
		goto err;
	}

	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);
	return 1;

err:
	if (siglen)
		*siglen = 0;

	return 0;
}

static int ecdsa_do_verify_check(EC_KEY *eckey,
				 const unsigned char *dgst, int dlen,
				 const ECDSA_SIG *sig)
{
	const BIGNUM *sig_r = NULL;
	const BIGNUM *sig_s = NULL;
	const EC_POINT *pub_key;
	const EC_GROUP *group;
	const BIGNUM *order;
	int ret;

	ret = eckey_check(eckey);
	if (ret)
		return ret;

	if (!dgst) {
		fprintf(stderr, "dgst is NULL\n");
		return -1;
	}

	if (dlen <= 0) {
		fprintf(stderr, "digest len error, dlen = %d", dlen);
		return -1;
	}

	pub_key = EC_KEY_get0_public_key(eckey);
	if (!pub_key) {
		fprintf(stderr, "pub_key is NULL\n");
		return -1;
	}

	ECDSA_SIG_get0((ECDSA_SIG *)sig, &sig_r, &sig_s);
	if (BN_num_bytes(sig_r) > UADK_ECC_MAX_KEY_BYTES ||
	    BN_num_bytes(sig_s) > UADK_ECC_MAX_KEY_BYTES) {
		fprintf(stderr, "ECDSA_SIG len error: rlen = %d, slen = %d\n",
			BN_num_bytes(sig_r), BN_num_bytes(sig_s));
		return -1;
	}

	group = EC_KEY_get0_group(eckey);
	order = EC_GROUP_get0_order(group);
	if (BN_is_zero(sig_r) ||
	    BN_is_negative(sig_r) ||
	    BN_ucmp(sig_r, order) >= 0 ||
	    BN_is_zero(sig_s) ||
	    BN_is_negative(sig_s) ||
	    BN_ucmp(sig_s, order) >= 0) {
		fprintf(stderr, "ECDSA_SIG is invalid\n");
		return -1;
	}

	return 0;
}

static int ecdsa_verify_init_iot(handle_t sess, struct wd_ecc_req *req,
				 struct wd_dtb *dgst,
				 const ECDSA_SIG *sig,
				 EC_KEY *eckey)
{
	char buf_r[UADK_ECC_MAX_KEY_BYTES] = { 0 };
	char buf_s[UADK_ECC_MAX_KEY_BYTES] = { 0 };
	char buf_e[UADK_ECC_MAX_KEY_BYTES] = { 0 };
	const BIGNUM *sig_r = NULL;
	const BIGNUM *sig_s = NULL;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = { 0 };
	struct wd_dtb r = { 0 };
	struct wd_dtb s = { 0 };
	int ret;

	e.data = buf_e;
	ret = set_digest(sess, &e, dgst, eckey);
	if (ret)
		return ret;

	r.data = buf_r;
	s.data = buf_s;
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	r.dsize = BN_bn2bin(sig_r, (void *)r.data);
	s.dsize = BN_bn2bin(sig_s, (void *)s.data);
	ecc_in = wd_ecdsa_new_verf_in(sess, &e, &r, &s);
	if (!ecc_in) {
		fprintf(stderr, "failed to new ecdsa verf in\n");
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_ECDSA_VERIFY, ecc_in, NULL);

	return 0;
}

static int openssl_do_verify(const unsigned char *dgst, int dlen,
			     const ECDSA_SIG *sig, EC_KEY *eckey)
{
	PFUNC_VERIFY_SIG verify_sig_pfunc = NULL;
	EC_KEY_METHOD *openssl_meth;

	openssl_meth = (EC_KEY_METHOD *)EC_KEY_OpenSSL();
	EC_KEY_METHOD_get_verify(openssl_meth, NULL,
				 &verify_sig_pfunc);
	if (!verify_sig_pfunc) {
		fprintf(stderr, "verify_sig_pfunc is NULL\n");
		return -1;
	}

	return (*verify_sig_pfunc)(dgst, dlen, sig, eckey);
}

static int ecdsa_do_verify(const unsigned char *dgst, int dlen,
			   const ECDSA_SIG *sig, EC_KEY *eckey)
{
	struct wd_ecc_req req;
	struct wd_dtb tdgst;
	handle_t sess;
	int ret;

	ret = ecdsa_do_verify_check(eckey, dgst, dlen, sig);
	if (ret)
		goto do_soft;

	ret = uadk_init_ecc();
	if (ret)
		goto do_soft;

	sess = ecc_alloc_sess(eckey, "ecdsa");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	tdgst.data = (void *)dgst;
	tdgst.dsize = dlen;
	ret = ecdsa_verify_init_iot(sess, &req, &tdgst, sig, eckey);
	if (ret)
		goto free_sess;

	ret = uadk_ecc_set_public_key(sess, eckey);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (!ret) {
		fprintf(stderr, "failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	wd_ecc_del_in(sess, req.src);
	wd_ecc_free_sess(sess);

	return ret;

uninit_iot:
	wd_ecc_del_in(sess, req.src);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_verify(dgst, dlen, sig, eckey);
}

static int ecdsa_verify(int type, const unsigned char *dgst, int dlen,
			const unsigned char *sig, int siglen, EC_KEY *eckey)
{
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int ret = -1;
	ECDSA_SIG *s;
	int derlen;

	s = ECDSA_SIG_new();
	if (!s) {
		fprintf(stderr, "failed to ECDSA_SIG_new\n");
		return ret;
	}

	if (!d2i_ECDSA_SIG(&s, &p, siglen)) {
		fprintf(stderr, "failed to d2i_ECDSA_SIG: siglen = %d\n",
			siglen);
		goto err;
	}

	/* Ensure signature uses DER and doesn't have trailing garbage */
	derlen = i2d_ECDSA_SIG(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen) != 0) {
		fprintf(stderr, "ECDSA_SIG s have trailing garbage\n");
		goto err;
	}

	ret = ecdsa_do_verify(dgst, dlen, s, eckey);
err:
	OPENSSL_free(der);
	ECDSA_SIG_free(s);
	return ret;
}

static int set_key_to_ec_key(EC_KEY *ec, struct wd_ecc_req *req)
{
	unsigned char buff[ECC_POINT_SIZE(SM2_KEY_BYTES) + 1] = {UADK_OCTET_STRING};
	struct wd_ecc_point *pubkey = NULL;
	struct wd_dtb *privkey = NULL;
	const EC_GROUP *group;
	EC_POINT *point, *ptr;
	BIGNUM *tmp;
	int ret;

	wd_sm2_get_kg_out_params(req->dst, &privkey, &pubkey);

	tmp = BN_bin2bn((unsigned char *)privkey->data, privkey->dsize, NULL);
	ret = EC_KEY_set_private_key(ec, tmp);
	BN_free(tmp);
	if (!ret) {
		fprintf(stderr, "failed to EC KEY set private key\n");
		return -EINVAL;
	}

	group = EC_KEY_get0_group(ec);
	point = EC_POINT_new(group);
	if (!point) {
		fprintf(stderr, "failed to EC POINT new\n");
		return -ENOMEM;
	}

	memcpy(buff + 1, pubkey->x.data, ECC_POINT_SIZE(SM2_KEY_BYTES));
	tmp = BN_bin2bn(buff, ECC_POINT_SIZE(SM2_KEY_BYTES) + 1, NULL);
	ptr = EC_POINT_bn2point(group, tmp, point, NULL);
	BN_free(tmp);
	if (!ptr) {
		fprintf(stderr, "failed to EC_POINT_bn2point\n");
		EC_POINT_free(point);
		return -EINVAL;
	}

	ret = EC_KEY_set_public_key(ec, point);
	EC_POINT_free(point);
	if (!ret) {
		fprintf(stderr, "failed to EC_KEY_set_public_key\n");
		return -EINVAL;
	}

	return 0;
}

static int openssl_do_generate(EC_KEY *eckey)
{
	PFUNC_GEN_KEY gen_key_pfunc = NULL;
	EC_KEY_METHOD *openssl_meth;

	openssl_meth = (EC_KEY_METHOD *)EC_KEY_OpenSSL();
	EC_KEY_METHOD_get_keygen(openssl_meth, &gen_key_pfunc);
	if (!gen_key_pfunc) {
		fprintf(stderr, "gen_key_pfunc is NULL\n");
		return -1;
	}

	return (*gen_key_pfunc)(eckey);
}

static int ecc_genkey_check(EC_KEY *eckey)
{
	BIGNUM *priv_key;
	int ret;

	ret = eckey_check(eckey);
	if (ret)
		return ret;

	priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (priv_key)
		return UADK_DO_SOFT;

	return 0;
}

static int sm2_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecc_out = wd_sm2_new_kg_out(sess);

	if (!ecc_out) {
		fprintf(stderr, "failed to new sign out\n");
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_SM2_KG, NULL, ecc_out);

	return 0;
}

static int eckey_create_key(EC_KEY *eckey)
{
	BIGNUM *priv_key;
	int ret;

	priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (priv_key)
		return 1;

	priv_key = BN_new();
	if (!priv_key) {
		fprintf(stderr, "failed to BN_new priv_key\n");
		return 0;
	}

	ret = EC_KEY_set_private_key(eckey, priv_key);
	if (!ret)
		fprintf(stderr, "failed to set private key\n");

	BN_free(priv_key);
	return ret;
}

static int ecdh_set_private_key(EC_KEY *eckey, BIGNUM *order)
{
	BIGNUM *priv_key;
	int ret;

	priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (priv_key)
		return 1;

	priv_key = BN_new();
	if (!priv_key) {
		fprintf(stderr, "failed to BN_new priv_key\n");
		return 0;
	}

	do {
		if (!BN_rand_range(priv_key, order)) {
			fprintf(stderr, "failed to generate random value\n");
			ret = 0;
			goto free_priv_key;
		}
	} while (BN_is_zero(priv_key));

	ret = EC_KEY_set_private_key(eckey, priv_key);
	if (!ret)
		fprintf(stderr, "failed to set private key\n");

free_priv_key:
	BN_free(priv_key);
	return ret;
}

static int ecdh_create_key(EC_KEY *eckey)
{
	const EC_GROUP *group;
	BIGNUM *order;
	BN_CTX *ctx;
	int ret;

	group = EC_KEY_get0_group(eckey);

	ctx = BN_CTX_new();
	if (!ctx) {
		fprintf(stderr, "failed to allocate ctx\n");
		return 0;
	}

	order = BN_CTX_get(ctx);
	if (!order) {
		fprintf(stderr, "failed to allocate order\n");
		ret = 0;
		goto free_ctx;
	}

	ret = EC_GROUP_get_order(group, order, ctx);
	if (!ret) {
		fprintf(stderr, "failed to retrieve order\n");
		goto free_order;
	}

	ret = ecdh_set_private_key(eckey, order);
	if (!ret)
		fprintf(stderr, "failed to set private key\n");

free_order:
	BN_clear(order);
free_ctx:
	BN_CTX_free(ctx);
	return ret;
}

static int sm2_generate_key(EC_KEY *eckey)
{
	struct wd_ecc_req req;
	handle_t sess;
	int ret;

	ret = ecc_genkey_check(eckey);
	if (ret)
		goto do_soft;

	ret = eckey_create_key(eckey);
	if (!ret)
		goto do_soft;

	ret = uadk_init_ecc();
	if (ret)
		goto do_soft;

	sess = ecc_alloc_sess(eckey, "sm2");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	ret = sm2_keygen_init_iot(sess, &req);
	if (ret)
		goto free_sess;

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (!ret)
		goto uninit_iot;

	ret = set_key_to_ec_key(eckey, &req);
	if (ret)
		goto uninit_iot;

	wd_ecc_del_out(sess, req.dst);
	wd_ecc_free_sess(sess);

	return 1;

uninit_iot:
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_generate(eckey);
}

static int ecdh_keygen_init_iot(handle_t sess, struct wd_ecc_req *req,
				EC_KEY *ecdh)
{
	struct wd_ecc_out *ecdh_out;

	ecdh_out = wd_ecxdh_new_out(sess);
	if (!ecdh_out) {
		fprintf(stderr, "failed to new sign out\n");
		return 0;
	}

	uadk_ecc_fill_req(req, WD_ECXDH_GEN_KEY, NULL, ecdh_out);

	return 1;
}


static int ecdh_compkey_init_iot(handle_t sess, struct wd_ecc_req *req,
				 const EC_POINT *pubkey, const EC_KEY *ecdh)
{
	char buf_x[UADK_ECC_MAX_KEY_BYTES];
	char buf_y[UADK_ECC_MAX_KEY_BYTES];
	struct wd_ecc_point in_pkey;
	struct wd_ecc_out *ecdh_out;
	struct wd_ecc_in *ecdh_in;
	BIGNUM *pkey_x, *pkey_y;
	const EC_GROUP *group;
	BN_CTX *ctx;
	int ret = 0;

	ctx = BN_CTX_new();
	if (!ctx)
		return -ENOMEM;

	BN_CTX_start(ctx);
	pkey_x = BN_CTX_get(ctx);
	if (!pkey_x)
		goto free_ctx;

	pkey_y = BN_CTX_get(ctx);
	if (!pkey_y)
		goto free_ctx;

	group = EC_KEY_get0_group(ecdh);
	if (!group)
		goto free_ctx;

	uadk_get_affine_coordinates(group, pubkey, pkey_x, pkey_y, ctx);
	in_pkey.x.data = buf_x;
	in_pkey.y.data = buf_y;
	in_pkey.x.dsize = BN_bn2bin(pkey_x, (unsigned char *)in_pkey.x.data);
	in_pkey.y.dsize = BN_bn2bin(pkey_y, (unsigned char *)in_pkey.y.data);

	/* Set public key */
	ecdh_in = wd_ecxdh_new_in(sess, &in_pkey);
	if (!ecdh_in) {
		fprintf(stderr, "failed to new ecxdh in\n");
		goto free_ctx;
	}

	ecdh_out = wd_ecxdh_new_out(sess);
	if (!ecdh_out) {
		fprintf(stderr, "failed to new ecxdh out\n");
		wd_ecc_del_in(sess, ecdh_in);
		goto free_ctx;
	}

	uadk_ecc_fill_req(req, WD_ECXDH_COMPUTE_KEY, ecdh_in, ecdh_out);

	ret = 1;

free_ctx:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}

static int ecdh_set_key_to_ec_key(EC_KEY *ecdh, struct wd_ecc_req *req)
{
	int key_size_std, key_size_x, key_size_y;
	struct wd_ecc_point *pubkey = NULL;
	const EC_GROUP *group;
	int x_shift, y_shift;
	unsigned char *buff;
	EC_POINT *point;
	int buff_size;
	int ret = 0;

	wd_ecxdh_get_out_params(req->dst, &pubkey);

	group = EC_KEY_get0_group(ecdh);
	point = EC_POINT_new(group);
	if (!point) {
		fprintf(stderr, "failed to EC POINT new\n");
		return ret;
	}

	key_size_std = (unsigned int)(EC_GROUP_get_degree(group) +
			UADK_ECC_PADDING) >> TRANS_BITS_BYTES_SHIFT;
	key_size_x = pubkey->x.dsize;
	key_size_y = pubkey->y.dsize;
	if ((key_size_x > key_size_std) || (key_size_y > key_size_std)) {
		fprintf(stderr, "key size invalid\n");
		goto free_point;
	}

	/*
	 * The public key is composed as: tag + point_x + point_y
	 * tag - 1 byte
	 * point_x - [key_size_std] bytes
	 * point_y - [key_size_std] bytes
	 */
	buff_size = ECC_POINT_SIZE(key_size_std) + 1;
	x_shift = key_size_std - key_size_x + 1;
	y_shift = buff_size - key_size_y;
	buff = (unsigned char *)OPENSSL_malloc(buff_size);
	if (!buff) {
		fprintf(stderr, "failed to alloc buf, buff_size = %d\n",
			buff_size);
		goto free_point;
	}
	memset(buff, 0, buff_size);
	buff[0] = UADK_OCTET_STRING;
	memcpy(buff + x_shift, pubkey->x.data, key_size_x);
	memcpy(buff + y_shift, pubkey->y.data, key_size_y);

	ret = EC_POINT_oct2point(group, point, buff, buff_size, NULL);
	if (!ret) {
		fprintf(stderr, "failed to do EC_POINT_oct2point\n");
		goto free_buf;
	}

	ret = EC_KEY_set_public_key(ecdh, point);
	if (!ret) {
		fprintf(stderr, "failed to do EC_KEY_set_public_key\n");
		goto free_buf;
	}

free_buf:
	OPENSSL_free(buff);
free_point:
	EC_POINT_free(point);

	return ret;
}

static int ecdh_get_shared_key(const EC_KEY *ecdh,
			       unsigned char **out,
			       size_t *outlen,
			       struct wd_ecc_req *req)
{
	struct wd_ecc_point *shared_key = NULL;

	wd_ecxdh_get_out_params(req->dst, &shared_key);

	*outlen = shared_key->x.dsize;

	*out = OPENSSL_zalloc(*outlen);
	if (!*out) {
		fprintf(stderr, "failed to alloc output key, outlen = %lu\n",
			*outlen);
		return 0;
	}

	memcpy(*out, (unsigned char *)shared_key->x.data, *outlen);

	return 1;
}

static int ecdh_generate_key(EC_KEY *ecdh)
{
	struct wd_ecc_req req;
	handle_t sess;
	int ret;

	ret = ecc_genkey_check(ecdh);
	if (ret)
		goto do_soft;

	ret = ecdh_create_key(ecdh);
	if (!ret)
		goto do_soft;

	ret = uadk_init_ecc();
	if (ret)
		goto do_soft;

	sess = ecc_alloc_sess(ecdh, "ecdh");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	ret = ecdh_keygen_init_iot(sess, &req, ecdh);
	if (!ret)
		goto free_sess;

	ret = uadk_ecc_set_private_key(sess, ecdh);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (!ret)
		goto uninit_iot;

	ret = ecdh_set_key_to_ec_key(ecdh, &req);
	if (!ret)
		goto uninit_iot;

	wd_ecc_del_out(sess, req.dst);
	wd_ecc_free_sess(sess);

	return ret;

uninit_iot:
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_generate(ecdh);
}

static int ecc_generate_key(EC_KEY *eckey)
{
	int cv_nid;

	cv_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey));
	if (cv_nid == NID_sm2)
		return sm2_generate_key(eckey);

	return ecdh_generate_key(eckey);
}

static int openssl_do_compute(unsigned char **pout,
			      size_t *poutlen,
			      const EC_POINT *pub_key,
			      const EC_KEY *ecdh)
{
	PFUNC_COMP_KEY comp_key_pfunc = NULL;
	EC_KEY_METHOD *openssl_meth;

	openssl_meth = (EC_KEY_METHOD *)EC_KEY_OpenSSL();
	EC_KEY_METHOD_get_compute_key(openssl_meth, &comp_key_pfunc);
	if (!comp_key_pfunc) {
		fprintf(stderr, "comp_key_pfunc is NULL\n");
		return -1;
	}

	return (*comp_key_pfunc)(pout, poutlen, pub_key, ecdh);
}

static int ecc_compkey_check(unsigned char **out,
			     size_t *outlen,
			     const EC_POINT *pub_key_b,
			     const EC_KEY *ecdh)
{
	BIGNUM *priv_key_a, *pub_key_a;
	int ret;

	if (!out || !pub_key_b || !outlen)
		return 0;

	ret = eckey_check(ecdh);
	if (ret)
		return 0;

	priv_key_a = (BIGNUM *)EC_KEY_get0_private_key(ecdh);
	if (!priv_key_a)
		return 0;

	pub_key_a = (BIGNUM *)EC_KEY_get0_public_key(ecdh);
	if (!pub_key_a)
		return 0;

	return 1;
}

static int ecdh_compute_key(unsigned char **out, size_t *outlen,
			    const EC_POINT *pub_key, const EC_KEY *ecdh)
{
	struct wd_ecc_req req;
	handle_t sess;
	int ret;

	ret = ecc_compkey_check(out, outlen, pub_key, ecdh);
	if (!ret)
		goto do_soft;

	ret = uadk_init_ecc();
	if (ret)
		goto do_soft;

	sess = ecc_alloc_sess(ecdh, "ecdh");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	ret = ecdh_compkey_init_iot(sess, &req, pub_key, ecdh);
	if (!ret)
		goto free_sess;

	ret = uadk_ecc_set_private_key(sess, ecdh);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_set_public_key(sess, ecdh);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (!ret)
		goto uninit_iot;

	ret = ecdh_get_shared_key(ecdh, out, outlen, &req);
	if (!(*outlen) || !ret)
		goto uninit_iot;

	wd_ecc_del_in(sess, req.src);
	wd_ecc_del_out(sess, req.dst);
	wd_ecc_free_sess(sess);

	return ret;

uninit_iot:
	wd_ecc_del_in(sess, req.src);
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_compute(out, outlen, pub_key, ecdh);
}

static void ec_key_meth_set_ecdsa(EC_KEY_METHOD *meth)
{
	if (!uadk_support_algorithm("ecdsa"))
		return;

	EC_KEY_METHOD_set_sign(meth,
			       ecdsa_sign,
			       NULL,
			       ecdsa_do_sign);
	EC_KEY_METHOD_set_verify(meth,
				 ecdsa_verify,
				 ecdsa_do_verify);
}

static void ec_key_meth_set_ecdh(EC_KEY_METHOD *meth)
{
	if (!uadk_support_algorithm("ecdh") &&
	    !uadk_support_algorithm("sm2"))
		return;

	EC_KEY_METHOD_set_keygen(meth, ecc_generate_key);
	EC_KEY_METHOD_set_compute_key(meth, ecdh_compute_key);
}

static EC_KEY_METHOD *uadk_get_ec_methods(void)
{
	EC_KEY_METHOD *def_ec_method;

	if (uadk_ec_method != NULL)
		return uadk_ec_method;

	def_ec_method = (EC_KEY_METHOD *)EC_KEY_get_default_method();
	uadk_ec_method = EC_KEY_METHOD_new(def_ec_method);
	if (!uadk_ec_method) {
		fprintf(stderr, "failed to EC_KEY_METHOD_new\n");
		return NULL;
	}

	ec_key_meth_set_ecdsa(uadk_ec_method);
	ec_key_meth_set_ecdh(uadk_ec_method);

	return uadk_ec_method;
}

void uadk_ec_delete_meth(void)
{
	if (!uadk_ec_method)
		return;

	EC_KEY_METHOD_free(uadk_ec_method);
	uadk_ec_method = NULL;
}

int uadk_ec_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	if (pkey_meth->ec)
		return 1;

	meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
	if (meth == NULL) {
		fprintf(stderr, "failed to EVP_PKEY_meth_new\n");
		return 0;
	}

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_EC);
	EVP_PKEY_meth_copy(meth, openssl_meth);

	pkey_meth->ec = meth;
	return 1;
}

int uadk_bind_ec(ENGINE *e)
{
	return ENGINE_set_EC(e, uadk_get_ec_methods());
}

