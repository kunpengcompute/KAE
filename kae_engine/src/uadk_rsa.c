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
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <uadk/wd_rsa.h>
#include <uadk/wd_sched.h>
#include "uadk_async.h"
#include "uadk.h"

#define UN_SET				0
#define IS_SET				1
#define BIT_BYTES_SHIFT			3
#define RSA_MIN_MODULUS_BITS		512
#define RSA_MAX_PRIME_NUM		2
#define RSA1024BITS			1024
#define RSA2048BITS			2048
#define RSA3072BITS			3072
#define RSA4096BITS			4096
#define OPENSSLRSA7680BITS		7680
#define OPENSSLRSA15360BITS		15360
#define CTX_ASYNC			1
#define CTX_SYNC			0
#define CTX_NUM				2
#define BN_CONTINUE			1
#define BN_VALID			0
#define BN_ERR				(-1)
#define BN_REDO				(-2)
#define GET_ERR_FINISH			0
#define SOFT				2
#define UNUSED(x)			((void)(x))
#define UADK_E_SUCCESS			1
#define UADK_E_FAIL			0
#define UADK_DO_SOFT			(-0xE0)
#define UADK_E_POLL_SUCCESS		0
#define UADK_E_POLL_FAIL		(-1)
#define UADK_E_INIT_SUCCESS		0
#define CHECK_PADDING_FAIL		(-1)
#define ENV_ENABLED			1
#define PRIME_RETRY_COUNT		4
#define GENCB_NEXT			2
#define GENCB_RETRY			3
#define PRIME_CHECK_BIT_NUM		4

static RSA_METHOD *rsa_hw_meth;

struct bignum_st {
	BN_ULONG *d;
	int top;
	int dmax;
	int neg;
	int flags;
};

struct rsa_keypair {
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
};

struct rsa_keygen_param {
	struct wd_dtb *wd_e;
	struct wd_dtb *wd_p;
	struct wd_dtb *wd_q;
};

struct rsa_keygen_param_bn {
	BIGNUM *e;
	BIGNUM *p;
	BIGNUM *q;
};

struct rsa_pubkey_param {
	const BIGNUM *e;
	const BIGNUM *n;
};

struct rsa_prikey_param {
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;
	const BIGNUM *p;
	const BIGNUM *q;
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;
	int is_crt;
};

struct rsa_prime_param {
	BIGNUM *r1;
	BIGNUM *r2;
	BIGNUM *rsa_p;
	BIGNUM *rsa_q;
	BIGNUM *prime;
};

struct uadk_rsa_sess {
	handle_t sess;
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	RSA *alg;
	int is_pubkey_ready;
	int is_prikey_ready;
	int key_size;
};

struct rsa_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct rsa_res_config {
	struct rsa_sched sched;
};

/* Save rsa global hardware resource */
struct rsa_res {
	struct wd_ctx_config *ctx_res;
	int pid;
	int numa_id;
	pthread_spinlock_t lock;
} g_rsa_res;

enum {
	INVALID = 0,
	PUB_ENC,
	PUB_DEC,
	PRI_ENC,
	PRI_DEC,
	MAX_CODE,
};

static int uadk_e_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

static int rsa_check_bit_useful(const int bits, int flen)
{
	if (flen > bits)
		return SOFT;

	if (bits < RSA_MIN_MODULUS_BITS)
		return UADK_E_FAIL;

	switch (bits) {
	case RSA1024BITS:
	case RSA2048BITS:
	case RSA3072BITS:
	case RSA4096BITS:
		return UADK_E_SUCCESS;
	case OPENSSLRSA7680BITS:
	case OPENSSLRSA15360BITS:
	case RSA_MIN_MODULUS_BITS:
		return SOFT;
	default:
		return SOFT;
	}
}

static int rsa_prime_mul_res(int num, struct rsa_prime_param *param,
			     BN_CTX *ctx, BN_GENCB *cb)
{
	if (num == 1) {
		if (!BN_mul(param->r1, param->rsa_p, param->rsa_q, ctx))
			return BN_ERR;
	} else {
		if (!BN_GENCB_call(cb, GENCB_RETRY, num))
			return BN_ERR;
		return BN_CONTINUE;
	}

	return BN_VALID;
}

static int check_rsa_prime_sufficient(int *num, const int *bitsr,
				      int *bitse, const int *n,
				      struct rsa_prime_param *param,
				      BN_CTX *ctx, BN_GENCB *cb)
{
	static int retries;
	BN_ULONG bitst;
	int ret;

	ret = rsa_prime_mul_res(*num, param, ctx, cb);
	if (ret)
		return ret;
	/*
	 * If |r1|, product of factors so far, is not as long as expected
	 * (by checking the first 4 bits are less than 0x9 or greater than
	 * 0xF). If so, re-generate the last prime.
	 *
	 * NOTE: This actually can't happen in two-prime case, because of
	 * the way factors are generated.
	 *
	 * Besides, another consideration is, for multi-prime case, even the
	 * length modulus is as long as expected, the modulus could start at
	 * 0x8, which could be utilized to distinguish a multi-prime private
	 * key by using the modulus in a certificate. This is also covered
	 * by checking the length should not be less than 0x9.
	 */
	if (!BN_rshift(param->r2, param->r1, *bitse - PRIME_CHECK_BIT_NUM))
		return BN_ERR;

	bitst = BN_get_word(param->r2);
	if (bitst < 0x9 || bitst > 0xF) {
	/*
	 * For keys with more than 4 primes, we attempt longer factor to
	 * meet length requirement.
	 * Otherwise, we just re-generate the prime with the same length.
	 * This strategy has the following goals:
	 * 1. 1024-bit factors are efficient when using 3072 and 4096-bit key
	 * 2. stay the same logic with normal 2-prime key
	 */
		if (*num < RSA_MAX_PRIME_NUM)
			*bitse -= bitsr[*num];
		else
			return -1;

		ret = BN_GENCB_call(cb, GENCB_NEXT, *n++);
		if (!ret)
			return -1;

		if (retries == PRIME_RETRY_COUNT) {
			*num = -1;
			*bitse = 0;
			retries = 0;
			return BN_CONTINUE;
		}
		retries++;
		return BN_REDO;
	}

	ret = BN_GENCB_call(cb, GENCB_RETRY, *num);
	if (!ret)
		return BN_ERR;
	retries = 0;

	return BN_VALID;
}

static void rsa_set_primes(int num, BIGNUM *rsa_p, BIGNUM *rsa_q,
			   BIGNUM **prime)
{
	if (num == 0)
		*prime = rsa_p;
	else
		*prime = rsa_q;
	/* Set BN_FLG_CONSTTIME to prime exponent */
	BN_set_flags(*prime, BN_FLG_CONSTTIME);
}

static int check_rsa_prime_equal(int num, BIGNUM *rsa_p, BIGNUM *rsa_q,
				 BIGNUM *prime)
{
	BIGNUM *prev_prime;
	int j;

	for (j = 0; j < num; j++) {
		prev_prime = NULL;
		if (j == 0)
			prev_prime = rsa_p;
		else
			prev_prime = rsa_q;
		/*
		 * BN_cmp(a,b) returns -1 if a < b;
		 * returns 0 if a == b;
		 * returns 1 if a > b.
		 */
		if (!BN_cmp(prime, prev_prime))
			return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int check_rsa_prime_useful(const int *n, struct rsa_prime_param *param,
				  BIGNUM *e_pub, BN_CTX *ctx, BN_GENCB *cb)
{
	unsigned long err;

	/*
	 * BN_sub(r,a,b) substracts b from a and place the result in r,
	 * r = a-b.
	 * BN_value_one() returns a BIGNUM constant of value 1.
	 * r2 = prime - 1.
	 */
	if (!BN_sub(param->r2, param->prime, BN_value_one()))
		return -1;
	ERR_set_mark();
	BN_set_flags(param->r2, BN_FLG_CONSTTIME);
	/*
	 * BN_mod_inverse(r,a,n,ctx) used to compute inverse modulo n.
	 * Precisely, it computes the inverse of "a" modulo "n", and places
	 * the result in "r", which means (a * r) % n==1.
	 * If r == NULL, error. If r != NULL, success.
	 * The expected result: (r2 * r1) % e_pub ==1,
	 * the inverse of r2 exist, that is r1.
	 */
	if (BN_mod_inverse(param->r1, param->r2, e_pub, ctx))
		return UADK_E_SUCCESS;

	err = ERR_peek_last_error();
	if (ERR_GET_LIB(err) == ERR_LIB_BN &&
	    ERR_GET_REASON(err) == BN_R_NO_INVERSE)
		ERR_pop_to_mark();
	else
		return BN_ERR;

	if (!BN_GENCB_call(cb, GENCB_NEXT, *n++))
		return BN_ERR;

	return GET_ERR_FINISH;
}

static int get_rsa_prime_once(int num, const int *bitsr, const int *n,
			      BIGNUM *e_pub, struct rsa_prime_param *param,
			      BN_CTX *ctx, BN_GENCB *cb)
{
	int ret = -1;

	if (num >= RSA_MAX_PRIME_NUM)
		return ret;
	while (1) {
		/* Generate prime with bitsr[num] len. */
		if (!BN_generate_prime_ex(param->prime, bitsr[num],
					  0, NULL, NULL, cb))
			return BN_ERR;
		if (!check_rsa_prime_equal(num, param->rsa_p, param->rsa_q,
					   param->prime))
			continue;
		ret = check_rsa_prime_useful(n, param, e_pub, ctx, cb);
		if (ret == BN_ERR)
			return BN_ERR;
		else if (ret == UADK_E_SUCCESS)
			break;
	}

	return ret;
}

static void rsa_switch_p_q(BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *p, BIGNUM *q)
{
	BIGNUM *tmp;

	if (BN_cmp(rsa_p, rsa_q) < 0) {
		tmp = rsa_p;
		rsa_p = rsa_q;
		rsa_q = tmp;
	}

	BN_copy(q, rsa_q);
	BN_copy(p, rsa_p);
}

static int check_rsa_is_crt(RSA *rsa)
{
	const BIGNUM *p = NULL;
	const BIGNUM *q = NULL;
	const BIGNUM *dmp1 = NULL;
	const BIGNUM *dmq1 = NULL;
	const BIGNUM *iqmp = NULL;
	int version;

	if (RSA_test_flags(rsa, RSA_FLAG_EXT_PKEY))
		return IS_SET;

	version = RSA_get_version(rsa);
	if (version == RSA_ASN1_VERSION_MULTI)
		return IS_SET;

	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if ((p != NULL) && (q != NULL) && (dmp1 != NULL) &&
	    (dmq1 != NULL) && (iqmp != NULL))
		return IS_SET;

	return UN_SET;
}

static int get_rsa_prime_param(struct rsa_prime_param *param, BN_CTX *ctx)
{
	param->r1 = BN_CTX_get(ctx);
	if (!param->r1)
		goto end;

	param->r2 = BN_CTX_get(ctx);
	if (!param->r2)
		goto end;

	param->rsa_p = BN_CTX_get(ctx);
	if (!param->rsa_p)
		goto end;

	param->rsa_q = BN_CTX_get(ctx);
	if (!param->rsa_q)
		goto end;

	return UADK_E_SUCCESS;

end:
	fprintf(stderr, "failed to allocate rsa prime params\n");
	return -ENOMEM;
}

static int rsa_primes_gen(int bits, BIGNUM *e_pub, BIGNUM *p,
			  BIGNUM *q, BN_GENCB *cb)
{
	struct rsa_prime_param *param = NULL;
	int bitsr[RSA_MAX_PRIME_NUM] = {0};
	int flag, quo, rmd, i;
	BN_CTX *ctx;
	int bitse = 0;
	int ret = 0;
	/* n: modulo n, a part of public key */
	int n = 0;

	ctx = BN_CTX_new();
	if (!ctx)
		return ret;

	BN_CTX_start(ctx);
	param = OPENSSL_zalloc(sizeof(struct rsa_prime_param));
	if (!param)
		goto free_ctx;

	ret = get_rsa_prime_param(param, ctx);
	if (ret != UADK_E_SUCCESS)
		goto free_param;

	/* Divide bits into 'primes' pieces evenly */
	quo = bits / RSA_MAX_PRIME_NUM;
	rmd = bits % RSA_MAX_PRIME_NUM;
	for (i = 0; i < RSA_MAX_PRIME_NUM; i++)
		bitsr[i] = (i < rmd) ? quo + 1 : quo;

	/* Generate p, q and other primes (if any) */
	for (i = 0; i < RSA_MAX_PRIME_NUM; i++) {
		/* flag: whether primes are generated correctely. */
		flag = 1;
		/* Set flag for primes rsa_p and rsa_q separately. */
		rsa_set_primes(i, param->rsa_p, param->rsa_q, &param->prime);
		while (flag == 1) {
			ret = get_rsa_prime_once(i, bitsr, &n, e_pub, param,
						 ctx, cb);
			if (ret == -1)
				goto free_param;
			bitse += bitsr[i];
			ret = check_rsa_prime_sufficient(&i, bitsr, &bitse, &n,
							 param, ctx, cb);
			if (ret == BN_ERR)
				goto free_param;
			else if (ret == BN_REDO)
				continue;
			else
				flag = 0;
		}
	}
	rsa_switch_p_q(param->rsa_p, param->rsa_q, p, q);

	ret = UADK_E_SUCCESS;

free_param:
	OPENSSL_free(param);
free_ctx:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}

static int add_rsa_pubenc_padding(int flen, const unsigned char *from,
				  unsigned char *buf, int num, int padding)
{
	int ret;

	if (!buf || !num) {
		fprintf(stderr, "buf or num is invalid\n");
		return UADK_E_FAIL;
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_PADDING err\n");
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_OAEP_PADDING err\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}

	return ret;
}

static int check_rsa_pridec_padding(unsigned char *to, int num,
				    const unsigned char *buf, int len,
				    int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_2(to, num, buf, len, num);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_PADDING err\n");
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, len, num,
						   NULL, 0);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_OAEP_PADDING err\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}

	if (ret == CHECK_PADDING_FAIL)
		ret = UADK_E_FAIL;

	return ret;
}

static int add_rsa_prienc_padding(int flen, const unsigned char *from,
				  unsigned char *to_buf, int tlen,
				  int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_1(to_buf, tlen, from, flen);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_PADDING err\n");
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_add_X931(to_buf, tlen, from, flen);
		if (!ret)
			fprintf(stderr, "RSA_X931_PADDING err\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}
	if (ret <= 0)
		ret = UADK_E_FAIL;

	return ret;
}

static int check_rsa_pubdec_padding(unsigned char *to, int num,
				    const unsigned char *buf, int len,
				    int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_1(to, num, buf, len, num);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_PADDING err\n");
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_check_X931(to, num, buf, len, num);
		if (!ret)
			fprintf(stderr, "RSA_X931_PADDING err\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}

	if (ret == CHECK_PADDING_FAIL)
		ret = UADK_E_FAIL;

	return ret;
}

static int check_rsa_input_para(const int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa)
{
	if (!rsa || !from || !to || flen <= 0) {
		fprintf(stderr, "input param invalid\n");
		return UADK_E_FAIL;
	}

	return rsa_check_bit_useful(RSA_bits(rsa), flen);
}

static BN_ULONG *bn_get_words(const BIGNUM *a)
{
	return a->d;
}

static int rsa_get_sign_res(int padding, BIGNUM *to_bn, const BIGNUM *n,
			    BIGNUM *ret_bn, BIGNUM **res)
{
	if (padding == RSA_X931_PADDING) {
		if (!BN_sub(to_bn, n, ret_bn))
			return UADK_E_FAIL;
		if (BN_cmp(ret_bn, to_bn) > 0)
			*res = to_bn;
		else
			*res = ret_bn;
	} else {
		*res = ret_bn;
	}

	return UADK_E_SUCCESS;
}

static int rsa_get_verify_res(int padding, const BIGNUM *n, BIGNUM *ret_bn)
{
	BIGNUM *to_bn = NULL;

	if ((padding == RSA_X931_PADDING) && ((bn_get_words(ret_bn)[0] & 0xf)
	    != 0x0c)) {
		if (!BN_sub(to_bn, n, ret_bn))
			return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static handle_t rsa_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 rsa_pick_next_ctx(handle_t sched_ctx,
		void *sched_key, const int sched_mode)
{
	if (sched_mode)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

static int rsa_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return UADK_E_POLL_SUCCESS;
}

static int uadk_e_rsa_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	int expt = 1;
	int ret;

	do {
		ret = wd_rsa_poll_ctx(CTX_ASYNC, expt, &recv);
		if (!ret && recv == expt)
			return UADK_E_POLL_SUCCESS;
		else if (ret == -EAGAIN)
			rx_cnt++;
		else
			return UADK_E_POLL_FAIL;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to recv msg: timeout!\n");

	return -ETIMEDOUT;
}

static struct rsa_res_config rsa_res_config = {
	.sched = {
		.sched_type = -1,
		.wd_sched = {
			.name = "RSA RR",
			.sched_init = rsa_sched_init,
			.pick_next_ctx = rsa_pick_next_ctx,
			.poll_policy = rsa_poll_policy,
			.h_sched_ctx = 0,
		},
	},
};

static int uadk_e_rsa_env_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_rsa_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static int uadk_e_wd_rsa_env_init(struct uacce_dev *dev)
{
	int ret;

	ret = uadk_e_set_env("WD_RSA_CTX_NUM", dev->numa_id);
	if (ret)
		return ret;

	ret = wd_rsa_env_init(NULL);
	if (ret)
		return ret;

	async_register_poll_fn(ASYNC_TASK_RSA, uadk_e_rsa_env_poll);

	return 0;
}

static int uadk_e_wd_rsa_init(struct rsa_res_config *config,
			      struct uacce_dev *dev)
{
	struct wd_sched *sched = &config->sched.wd_sched;
	struct wd_ctx_config *ctx_cfg;
	int ret;
	int i;

	ret = uadk_e_is_env_enabled("rsa");
	if (ret == ENV_ENABLED)
		return uadk_e_wd_rsa_env_init(dev);

	ctx_cfg = calloc(1, sizeof(struct wd_ctx_config));
	if (!ctx_cfg)
		return -ENOMEM;

	g_rsa_res.ctx_res = ctx_cfg;
	ctx_cfg->ctx_num = CTX_NUM;
	ctx_cfg->ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!ctx_cfg->ctxs) {
		ret = -ENOMEM;
		goto free_cfg;
	}

	for (i = 0; i < CTX_NUM; i++) {
		ctx_cfg->ctxs[i].ctx = wd_request_ctx(dev);
		if (!ctx_cfg->ctxs[i].ctx) {
			ret = -ENOMEM;
			goto free_ctx;
		}
		ctx_cfg->ctxs[i].ctx_mode = (i == 0) ? CTX_SYNC : CTX_ASYNC;
	}

	ret = wd_rsa_init(ctx_cfg, sched);
	if (ret)
		goto free_ctx;

	async_register_poll_fn(ASYNC_TASK_RSA, uadk_e_rsa_poll);

	return 0;

free_ctx:
	for (i = 0; i < CTX_NUM; i++) {
		if (ctx_cfg->ctxs[i].ctx) {
			wd_release_ctx(ctx_cfg->ctxs[i].ctx);
			ctx_cfg->ctxs[i].ctx = 0;
		}
	}

	free(ctx_cfg->ctxs);
free_cfg:
	free(ctx_cfg);
	return ret;
}

static int uadk_e_rsa_init(void)
{
	struct uacce_dev *dev;
	int ret;

	if (g_rsa_res.pid != getpid()) {
		pthread_spin_lock(&g_rsa_res.lock);
		if (g_rsa_res.pid == getpid()) {
			pthread_spin_unlock(&g_rsa_res.lock);
			return UADK_E_INIT_SUCCESS;
		}

		dev = wd_get_accel_dev("rsa");
		if (!dev) {
			pthread_spin_unlock(&g_rsa_res.lock);
			fprintf(stderr, "failed to get device for rsa\n");
			return -ENOMEM;
		}

		ret = uadk_e_wd_rsa_init(&rsa_res_config, dev);
		if (ret)
			goto err_unlock;

		g_rsa_res.numa_id = dev->numa_id;
		g_rsa_res.pid = getpid();
		pthread_spin_unlock(&g_rsa_res.lock);
		free(dev);
	}

	return UADK_E_INIT_SUCCESS;

err_unlock:
	pthread_spin_unlock(&g_rsa_res.lock);
	free(dev);
	(void)fprintf(stderr, "failed to init rsa(%d)\n", ret);

	return ret;
}

static void uadk_e_rsa_uninit(void)
{
	struct wd_ctx_config *ctx_cfg = g_rsa_res.ctx_res;
	int i, ret;

	if (g_rsa_res.pid == getpid()) {
		ret = uadk_e_is_env_enabled("rsa");
		if (ret == ENV_ENABLED) {
			wd_rsa_env_uninit();
		} else {
			wd_rsa_uninit();
			for (i = 0; i < ctx_cfg->ctx_num; i++)
				wd_release_ctx(ctx_cfg->ctxs[i].ctx);
			free(ctx_cfg->ctxs);
			free(ctx_cfg);
		}

		g_rsa_res.pid = 0;
	}
}

static struct uadk_rsa_sess *rsa_new_eng_session(RSA *rsa)
{
	struct uadk_rsa_sess *rsa_sess;

	rsa_sess = OPENSSL_malloc(sizeof(struct uadk_rsa_sess));
	if (!rsa_sess)
		return NULL;

	memset(rsa_sess, 0, sizeof(struct uadk_rsa_sess));
	rsa_sess->alg = rsa;
	rsa_sess->is_prikey_ready = UN_SET;
	rsa_sess->is_pubkey_ready = UN_SET;

	return rsa_sess;
}

static void rsa_free_eng_session(struct uadk_rsa_sess *rsa_sess)
{
	if (!rsa_sess)
		return;

	rsa_sess->alg = NULL;
	rsa_sess->is_prikey_ready = UN_SET;
	rsa_sess->is_pubkey_ready = UN_SET;

	wd_rsa_free_sess(rsa_sess->sess);
	OPENSSL_free(rsa_sess);
}

static struct uadk_rsa_sess *rsa_get_eng_session(RSA *rsa, unsigned int bits,
						 int is_crt)
{
	unsigned int key_size =  bits >> BIT_BYTES_SHIFT;
	struct sched_params params = {0};
	struct uadk_rsa_sess *rsa_sess;

	rsa_sess =  rsa_new_eng_session(rsa);
	if (!rsa_sess)
		return NULL;

	rsa_sess->key_size = key_size;
	rsa_sess->setup.key_bits = key_size << BIT_BYTES_SHIFT;

	/* Use the default numa parameters */
	params.numa_id = -1;
	rsa_sess->setup.sched_param = &params;
	rsa_sess->setup.is_crt = is_crt;

	rsa_sess->sess = wd_rsa_alloc_sess(&rsa_sess->setup);
	if (!rsa_sess->sess) {
		rsa_free_eng_session(rsa_sess);
		return NULL;
	}

	return rsa_sess;
}

static int rsa_fill_pubkey(struct rsa_pubkey_param *pubkey_param,
			   struct uadk_rsa_sess *rsa_sess,
			   unsigned char *in_buf, unsigned char *to)
{
	struct wd_rsa_pubkey *pubkey = NULL;
	struct wd_dtb *wd_e = NULL;
	struct wd_dtb *wd_n = NULL;

	if (!rsa_sess->is_pubkey_ready) {
		wd_rsa_get_pubkey(rsa_sess->sess, &pubkey);
		wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
		wd_e->dsize = BN_bn2bin(pubkey_param->e,
					(unsigned char *)wd_e->data);
		wd_n->dsize = BN_bn2bin(pubkey_param->n,
					(unsigned char *)wd_n->data);
		rsa_sess->is_pubkey_ready = IS_SET;
		rsa_sess->req.src_bytes = rsa_sess->key_size;
		rsa_sess->req.dst_bytes = rsa_sess->key_size;
		rsa_sess->req.op_type = WD_RSA_VERIFY;
		rsa_sess->req.src = in_buf;
		rsa_sess->req.dst = to;

		return UADK_E_SUCCESS;
	}

	return UADK_E_FAIL;
}

static int rsa_fill_prikey(RSA *rsa, struct uadk_rsa_sess *rsa_sess,
			   struct rsa_prikey_param *pri,
			   unsigned char *in_buf, unsigned char *to)
{
	struct wd_rsa_prikey *prikey = NULL;
	struct wd_dtb *wd_qinv = NULL;
	struct wd_dtb *wd_dq = NULL;
	struct wd_dtb *wd_dp = NULL;
	struct wd_dtb *wd_q = NULL;
	struct wd_dtb *wd_p = NULL;
	struct wd_dtb *wd_d = NULL;
	struct wd_dtb *wd_n = NULL;

	if (!(rsa_sess->is_prikey_ready) && (pri->is_crt)) {
		wd_rsa_get_prikey(rsa_sess->sess, &prikey);
		wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp,
					     &wd_qinv, &wd_q, &wd_p);
		wd_dq->dsize = BN_bn2bin(pri->dmq1,
					 (unsigned char *)wd_dq->data);
		wd_dp->dsize = BN_bn2bin(pri->dmp1,
					 (unsigned char *)wd_dp->data);
		wd_q->dsize = BN_bn2bin(pri->q,
					(unsigned char *)wd_q->data);
		wd_p->dsize = BN_bn2bin(pri->p,
					(unsigned char *)wd_p->data);
		wd_qinv->dsize = BN_bn2bin(pri->iqmp,
					   (unsigned char *)wd_qinv->data);
	} else if (!(rsa_sess->is_prikey_ready) && !(pri->is_crt)) {
		wd_rsa_get_prikey(rsa_sess->sess, &prikey);
		wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
		wd_d->dsize = BN_bn2bin(pri->d,
					(unsigned char *)wd_d->data);
		wd_n->dsize = BN_bn2bin(pri->n,
					(unsigned char *)wd_n->data);
	} else {
		return UADK_E_FAIL;
	}
	rsa_sess->is_prikey_ready = IS_SET;
	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.op_type = WD_RSA_SIGN;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	rsa_sess->req.src = in_buf;
	rsa_sess->req.dst = to;

	return UADK_E_SUCCESS;
}

static int rsa_get_keygen_param(struct wd_rsa_req *req, handle_t ctx, RSA *rsa,
				struct rsa_keygen_param_bn *bn_param, BN_CTX **bn_ctx_in)
{
	struct wd_rsa_kg_out *out = (struct wd_rsa_kg_out *)req->dst;
	struct wd_dtb wd_d, wd_n, wd_qinv, wd_dq, wd_dp;
	BIGNUM *dmp1, *dmq1, *iqmp, *n, *d;
	unsigned int key_bits, key_size;
	BN_CTX *bn_ctx = *bn_ctx_in;

	key_bits = wd_rsa_get_key_bits(ctx);
	if (!key_bits)
		return UADK_E_FAIL;

	key_size = key_bits >> BIT_BYTES_SHIFT;
	wd_rsa_get_kg_out_params(out, &wd_d, &wd_n);
	wd_rsa_get_kg_out_crt_params(out, &wd_qinv, &wd_dq, &wd_dp);

	dmp1 = BN_CTX_get(bn_ctx);
	if (!dmp1)
		return UADK_E_FAIL;

	dmq1 = BN_CTX_get(bn_ctx);
	if (!dmq1)
		return UADK_E_FAIL;

	iqmp = BN_CTX_get(bn_ctx);
	if (!iqmp)
		return UADK_E_FAIL;

	n = BN_CTX_get(bn_ctx);
	if (!n)
		return UADK_E_FAIL;

	d = BN_CTX_get(bn_ctx);
	if (!d)
		return UADK_E_FAIL;

	BN_bin2bn((unsigned char *)wd_d.data, key_size, d);
	BN_bin2bn((unsigned char *)wd_n.data, key_size, n);
	BN_bin2bn((unsigned char *)wd_qinv.data, wd_qinv.dsize, iqmp);
	BN_bin2bn((unsigned char *)wd_dq.data, wd_dq.dsize, dmq1);
	BN_bin2bn((unsigned char *)wd_dp.data, wd_dp.dsize, dmp1);

	if (!(RSA_set0_key(rsa, n, bn_param->e, d) &&
	    RSA_set0_factors(rsa, bn_param->p, bn_param->q) &&
	    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)))
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;
}

static void uadk_e_rsa_cb(void *req_t)
{
	struct wd_rsa_req *req_new = (struct wd_rsa_req *)req_t;
	struct uadk_e_cb_info *cb_param;
	struct wd_rsa_req *req_origin;
	struct async_op *op;

	if (!req_new)
		return;

	cb_param = req_new->cb_param;
	if (!cb_param)
		return;

	req_origin = cb_param->priv;
	if (!req_origin)
		return;

	req_origin->status = req_new->status;

	op = cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		async_wake_job(op->job);
	}
}

static int rsa_do_crypto(struct uadk_rsa_sess *rsa_sess)
{
	struct uadk_e_cb_info cb_param;
	struct async_op op;
	int idx, ret;

	ret = async_setup_async_event_notification(&op);
	if (!ret) {
		fprintf(stderr, "failed to setup async event notification.\n");
		return UADK_E_FAIL;
	}

	if (!op.job) {
		ret = wd_do_rsa_sync(rsa_sess->sess, &(rsa_sess->req));
		if (!ret)
			return UADK_E_SUCCESS;
		else
			goto err;
	}
	cb_param.op = &op;
	cb_param.priv = &(rsa_sess->req);
	rsa_sess->req.cb = (void *)uadk_e_rsa_cb;
	rsa_sess->req.cb_param = &cb_param;
	rsa_sess->req.status = -1;

	ret = async_get_free_task(&idx);
	if (ret == 0)
		goto err;

	op.idx = idx;
	do {
		ret = wd_do_rsa_async(rsa_sess->sess, &(rsa_sess->req));
		if (ret < 0 && ret != -EBUSY) {
			async_free_poll_task(op.idx, 0);
			goto err;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(rsa_sess, &op, ASYNC_TASK_RSA, idx);
	if (!ret)
		goto err;

	if (rsa_sess->req.status)
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;

err:
	(void)async_clear_async_event_notification();
	return UADK_E_FAIL;
}

static int uadk_e_soft_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	const RSA_METHOD *default_meth = RSA_PKCS1_OpenSSL();
	int ret;

	if (!default_meth) {
		fprintf(stderr, "failed to get soft method.\n");
		return UADK_E_FAIL;
	}

	UNUSED(cb);
	(void)RSA_meth_set_keygen(rsa_hw_meth,
				  RSA_meth_get_keygen(default_meth));
	ret = RSA_generate_key_ex(rsa, bits, e, NULL);
	(void)RSA_meth_set_keygen(rsa_hw_meth, uadk_e_rsa_keygen);

	return ret;
}

static int rsa_fill_keygen_data(struct uadk_rsa_sess *rsa_sess,
				struct rsa_keypair *key_pair,
				struct rsa_keygen_param *keygen_param,
				struct rsa_keygen_param_bn *bn_param)
{
	wd_rsa_get_pubkey(rsa_sess->sess, &key_pair->pubkey);
	if (!key_pair->pubkey)
		return UADK_E_FAIL;

	wd_rsa_get_pubkey_params(key_pair->pubkey, &keygen_param->wd_e, NULL);
	if (!keygen_param->wd_e)
		return UADK_E_FAIL;

	keygen_param->wd_e->dsize = BN_bn2bin(bn_param->e,
				    (unsigned char *)keygen_param->wd_e->data);

	wd_rsa_get_prikey(rsa_sess->sess, &key_pair->prikey);
	if (!key_pair->prikey)
		return UADK_E_FAIL;

	wd_rsa_get_crt_prikey_params(key_pair->prikey, NULL, NULL, NULL,
				     &keygen_param->wd_q, &keygen_param->wd_p);
	if (!keygen_param->wd_q || !keygen_param->wd_p)
		return UADK_E_FAIL;

	keygen_param->wd_q->dsize = BN_bn2bin(bn_param->q,
				    (unsigned char *)keygen_param->wd_q->data);
	keygen_param->wd_p->dsize = BN_bn2bin(bn_param->p,
				    (unsigned char *)keygen_param->wd_p->data);

	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	rsa_sess->req.op_type = WD_RSA_GENKEY;
	rsa_sess->req.src = wd_rsa_new_kg_in(rsa_sess->sess,
					     keygen_param->wd_e,
					     keygen_param->wd_p,
					     keygen_param->wd_q);
	if (!rsa_sess->req.src)
		return UADK_E_FAIL;

	rsa_sess->req.dst = wd_rsa_new_kg_out(rsa_sess->sess);
	if (!rsa_sess->req.dst)
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;
}

static void rsa_free_keygen_data(struct uadk_rsa_sess *rsa_sess)
{
	if (!rsa_sess)
		return;

	wd_rsa_del_kg_in(rsa_sess->sess, rsa_sess->req.src);
	wd_rsa_del_kg_out(rsa_sess->sess, rsa_sess->req.dst);
}

static int rsa_keygen_param_alloc(struct rsa_keygen_param **keygen_param,
				  struct rsa_keygen_param_bn **keygen_bn_param,
				  struct rsa_keypair **key_pair, BN_CTX **bn_ctx_in)
{
	BN_CTX *bn_ctx;

	*keygen_param = OPENSSL_malloc(sizeof(struct rsa_keygen_param));
	if (!(*keygen_param))
		goto err;

	*keygen_bn_param = (struct rsa_keygen_param_bn *)
			   OPENSSL_malloc(sizeof(struct rsa_keygen_param_bn));
	if (!(*keygen_bn_param))
		goto free_keygen_param;

	*key_pair = OPENSSL_malloc(sizeof(struct rsa_keypair));
	if (!(*key_pair))
		goto free_keygen_bn_param;

	bn_ctx = BN_CTX_new();
	if (!bn_ctx)
		goto free_key_pair;

	BN_CTX_start(bn_ctx);
	*bn_ctx_in = bn_ctx;

	(*keygen_bn_param)->e = BN_CTX_get(bn_ctx);
	if (!(*keygen_bn_param)->e)
		goto free_bn_ctx;

	(*keygen_bn_param)->p = BN_CTX_get(bn_ctx);
	if (!(*keygen_bn_param)->p)
		goto free_bn_ctx;

	(*keygen_bn_param)->q = BN_CTX_get(bn_ctx);
	if (!(*keygen_bn_param)->q)
		goto free_bn_ctx;

	return UADK_E_SUCCESS;

free_bn_ctx:
	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);
free_key_pair:
	OPENSSL_free(*key_pair);
free_keygen_bn_param:
	OPENSSL_free(*keygen_bn_param);
free_keygen_param:
	OPENSSL_free(*keygen_param);
err:
	return -ENOMEM;
}

static void rsa_keygen_param_free(struct rsa_keygen_param **keygen_param,
				  struct rsa_keygen_param_bn **keygen_bn_param,
				  struct rsa_keypair **key_pair, BN_CTX **bn_ctx,
				  int free_bn_ctx_tag)
{
	/*
	 * When an abnormal situation occurs, uadk engine needs
	 * to switch to software keygen function, so we need to
	 * free BN ctx we alloced before. But in normal situation,
	 * the BN ctx should be freed by OpenSSL tools or users.
	 * Therefore, we use a tag to distinguish these cases.
	 */
	if (free_bn_ctx_tag == UADK_DO_SOFT) {
		BN_CTX_end(*bn_ctx);
		BN_CTX_free(*bn_ctx);
	}

	OPENSSL_free(*keygen_bn_param);
	OPENSSL_free(*keygen_param);
	OPENSSL_free(*key_pair);
}

static int rsa_pkey_param_alloc(struct rsa_pubkey_param **pub,
				struct rsa_prikey_param **pri)
{
	if (pub) {
		*pub = OPENSSL_malloc(sizeof(struct rsa_pubkey_param));
		if (!(*pub))
			return -ENOMEM;
	}

	if (pri) {
		*pri = OPENSSL_malloc(sizeof(struct rsa_prikey_param));
		if (!(*pri)) {
			if (pub)
				OPENSSL_free(*pub);
			return -ENOMEM;
		}
	}

	return UADK_E_SUCCESS;
}

static void rsa_pkey_param_free(struct rsa_pubkey_param **pub,
				struct rsa_prikey_param **pri)
{
	if (pub)
		OPENSSL_free(*pub);
	if (pri)
		OPENSSL_free(*pri);
}

static int rsa_create_pub_bn_ctx(RSA *rsa, struct rsa_pubkey_param *pub,
				 unsigned char **from_buf, int *num_bytes)
{
	RSA_get0_key(rsa, &pub->n, &pub->e, NULL);
	if (!(pub->n) || !(pub->e))
		return UADK_E_FAIL;

	*num_bytes = BN_num_bytes(pub->n);
	if (!(*num_bytes))
		return UADK_E_FAIL;

	*from_buf = OPENSSL_malloc(*num_bytes);
	if (!(*from_buf))
		return -ENOMEM;

	return UADK_E_SUCCESS;
}

static void rsa_free_pub_bn_ctx(unsigned char **from_buf)
{
	OPENSSL_free(*from_buf);
}

static int rsa_create_pri_bn_ctx(RSA *rsa, struct rsa_prikey_param *pri,
				 unsigned char **from_buf, int *num_bytes)
{
	RSA_get0_key(rsa, &pri->n, &pri->e, &pri->d);
	if (!(pri->n) || !(pri->e) || !(pri->d))
		return UADK_E_FAIL;

	RSA_get0_factors(rsa, &pri->p, &pri->q);
	if (!(pri->p) || !(pri->q))
		return UADK_E_FAIL;

	RSA_get0_crt_params(rsa, &pri->dmp1, &pri->dmq1, &pri->iqmp);
	if (!(pri->dmp1) || !(pri->dmq1) || !(pri->iqmp))
		return UADK_E_FAIL;

	*num_bytes = BN_num_bytes(pri->n);
	if (!(*num_bytes))
		return UADK_E_FAIL;

	*from_buf = OPENSSL_malloc(*num_bytes);
	if (!(*from_buf))
		return -ENOMEM;

	return UADK_E_SUCCESS;
}

static void rsa_free_pri_bn_ctx(unsigned char **from_buf)
{
	OPENSSL_free(*from_buf);
}

static int uadk_e_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	struct rsa_keygen_param *keygen_param = NULL;
	struct rsa_keygen_param_bn *bn_param = NULL;
	struct uadk_rsa_sess *rsa_sess = NULL;
	struct rsa_keypair *key_pair = NULL;
	BN_CTX *bn_ctx = NULL;
	int is_crt = 1;
	int ret;

	ret = rsa_check_bit_useful(bits, 0);
	if (!ret || ret == SOFT)
		goto exe_soft;

	ret = uadk_e_rsa_init();
	if (ret)
		goto exe_soft;

	ret = rsa_keygen_param_alloc(&keygen_param, &bn_param, &key_pair, &bn_ctx);
	if (ret == -ENOMEM)
		goto exe_soft;

	rsa_sess = rsa_get_eng_session(rsa, bits, is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_keygen;
	}

	ret = rsa_primes_gen(bits, e, bn_param->p, bn_param->q, cb);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	if (!BN_copy(bn_param->e, e)) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = rsa_fill_keygen_data(rsa_sess, key_pair, keygen_param, bn_param);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_kg_in_out;
	}

	ret = rsa_get_keygen_param(&rsa_sess->req, rsa_sess->sess, rsa, bn_param, &bn_ctx);
	if (!ret)
		ret = UADK_DO_SOFT;

free_kg_in_out:
	rsa_free_keygen_data(rsa_sess);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_keygen:
	rsa_keygen_param_free(&keygen_param, &bn_param, &key_pair, &bn_ctx, ret);
	if (ret != UADK_DO_SOFT)
		return ret;
exe_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return uadk_e_soft_rsa_keygen(rsa, bits, e, cb);
}

static int uadk_e_rsa_public_encrypt(int flen, const unsigned char *from,
				     unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_pubkey_param *pub_enc = NULL;
	struct uadk_rsa_sess *rsa_sess = NULL;
	unsigned char *from_buf = NULL;
	int num_bytes, is_crt, ret;
	BIGNUM *enc_bn = NULL;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (!ret || ret == SOFT)
		goto exe_soft;

	ret = uadk_e_rsa_init();
	if (ret)
		goto exe_soft;

	ret = rsa_pkey_param_alloc(&pub_enc, NULL);
	if (ret == -ENOMEM)
		goto exe_soft;

	is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, RSA_bits(rsa), is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pub_bn_ctx(rsa, pub_enc, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = add_rsa_pubenc_padding(flen, from, from_buf, num_bytes, padding);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = rsa_fill_pubkey(pub_enc, rsa_sess, from_buf, to);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	enc_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			   rsa_sess->req.dst_bytes, NULL);
	if (!enc_bn) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = BN_bn2binpad(enc_bn, to, num_bytes);
	if (ret == -1)
		ret = UADK_DO_SOFT;

	BN_free(enc_bn);

free_buf:
	rsa_free_pub_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(&pub_enc, NULL);
	if (ret != UADK_DO_SOFT)
		return ret;
exe_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
				   (flen, from, to, rsa, padding);
}

static int uadk_e_rsa_private_decrypt(int flen, const unsigned char *from,
				      unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_prikey_param *pri = NULL;
	unsigned char *from_buf = NULL;
	struct uadk_rsa_sess *rsa_sess;
	int num_bytes, len, ret;
	BIGNUM *dec_bn = NULL;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (!ret || ret == SOFT)
		goto exe_soft;

	ret = uadk_e_rsa_init();
	if (ret)
		goto exe_soft;

	ret = rsa_pkey_param_alloc(NULL, &pri);
	if (ret == -ENOMEM)
		goto exe_soft;

	pri->is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, RSA_bits(rsa), pri->is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pri_bn_ctx(rsa, pri, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = rsa_fill_prikey(rsa, rsa_sess, pri, from_buf, to);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	dec_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			   rsa_sess->req.dst_bytes, NULL);
	if (!dec_bn) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	len = BN_bn2binpad(dec_bn, from_buf, num_bytes);
	if (!len) {
		ret = UADK_DO_SOFT;
		goto free_dec_bn;
	}

	ret = check_rsa_pridec_padding(to, num_bytes, from_buf, len, padding);
	if (!ret)
		ret = UADK_DO_SOFT;

free_dec_bn:
	BN_free(dec_bn);
free_buf:
	rsa_free_pri_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(NULL, &pri);
	if (ret != UADK_DO_SOFT)
		return ret;
exe_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
				    (flen, from, to, rsa, padding);
}

static int uadk_e_rsa_private_sign(int flen, const unsigned char *from,
				   unsigned char *to, RSA *rsa, int padding)
{
	struct uadk_rsa_sess *rsa_sess = NULL;
	struct rsa_prikey_param *pri = NULL;
	unsigned char *from_buf = NULL;
	BIGNUM *sign_bn = NULL;
	BIGNUM *to_bn = NULL;
	BIGNUM *res = NULL;
	int num_bytes, ret;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (!ret || ret == SOFT)
		goto exe_soft;

	ret = uadk_e_rsa_init();
	if (ret)
		goto exe_soft;

	ret = rsa_pkey_param_alloc(NULL, &pri);
	if (ret == -ENOMEM)
		goto exe_soft;

	pri->is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, RSA_bits(rsa), pri->is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pri_bn_ctx(rsa, pri, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = add_rsa_prienc_padding(flen, from, from_buf, num_bytes, padding);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = rsa_fill_prikey(rsa, rsa_sess, pri, from_buf, to);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	sign_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			   rsa_sess->req.dst_bytes, NULL);
	if (!sign_bn) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	to_bn = BN_bin2bn(from_buf, num_bytes, NULL);
	if (!to_bn) {
		ret = UADK_DO_SOFT;
		goto free_sign_bn;
	}

	ret = rsa_get_sign_res(padding, to_bn, pri->n, sign_bn, &res);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_to_bn;
	}

	ret = BN_bn2binpad(res, to, num_bytes);

free_to_bn:
	BN_free(to_bn);
free_sign_bn:
	BN_free(sign_bn);
free_buf:
	rsa_free_pri_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(NULL, &pri);
	if (ret != UADK_DO_SOFT)
		return ret;
exe_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
				    (flen, from, to, rsa, padding);
}

static int uadk_e_rsa_public_verify(int flen, const unsigned char *from,
				    unsigned char *to, RSA *rsa, int padding)
{
	struct uadk_rsa_sess *rsa_sess = NULL;
	struct rsa_pubkey_param *pub = NULL;
	int num_bytes, is_crt, len, ret;
	unsigned char *from_buf = NULL;
	BIGNUM *verify_bn = NULL;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (!ret)
		return UADK_E_FAIL;
	else if (ret == SOFT)
		goto exe_soft;

	ret = uadk_e_rsa_init();
	if (ret)
		goto exe_soft;

	ret = rsa_pkey_param_alloc(&pub, NULL);
	if (ret == -ENOMEM)
		goto exe_soft;

	is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, RSA_bits(rsa), is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pub_bn_ctx(rsa, pub, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = rsa_fill_pubkey(pub, rsa_sess, from_buf, to);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);
	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	verify_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			    rsa_sess->req.dst_bytes, NULL);
	if (!verify_bn) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = rsa_get_verify_res(padding, pub->n, verify_bn);
	if (!ret) {
		ret = UADK_DO_SOFT;
		goto free_verify_bn;
	}

	len = BN_bn2binpad(verify_bn, from_buf, num_bytes);
	if (!len) {
		ret = UADK_DO_SOFT;
		goto free_verify_bn;
	}

	ret = check_rsa_pubdec_padding(to, num_bytes, from_buf, len, padding);
	if (!ret)
		ret = UADK_DO_SOFT;

free_verify_bn:
	BN_free(verify_bn);
free_buf:
	rsa_free_pub_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(&pub, NULL);
	if (ret != UADK_DO_SOFT)
		return ret;
exe_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
				   (flen, from, to, rsa, padding);
}

/**
 * uadk_get_rsa_method() - Set rsa hardware methods of the RSA implementation which
 * can be called from ENGINE structure.
 */
static RSA_METHOD *uadk_e_get_rsa_methods(void)
{
	if (rsa_hw_meth)
		return rsa_hw_meth;

	rsa_hw_meth = RSA_meth_new("uadk hardware rsa method", 0);
	if (!rsa_hw_meth) {
		fprintf(stderr, "failed to allocate rsa hardware method\n");
		return NULL;
	}

	/* Set RSA hardware methods. */
	(void)RSA_meth_set_keygen(rsa_hw_meth, uadk_e_rsa_keygen);
	(void)RSA_meth_set_pub_enc(rsa_hw_meth, uadk_e_rsa_public_encrypt);
	(void)RSA_meth_set_priv_dec(rsa_hw_meth, uadk_e_rsa_private_decrypt);
	(void)RSA_meth_set_priv_enc(rsa_hw_meth, uadk_e_rsa_private_sign);
	(void)RSA_meth_set_pub_dec(rsa_hw_meth, uadk_e_rsa_public_verify);
	(void)RSA_meth_set_bn_mod_exp(rsa_hw_meth, RSA_meth_get_bn_mod_exp(
				      RSA_PKCS1_OpenSSL()));
	(void)RSA_meth_set_mod_exp(rsa_hw_meth, RSA_meth_get_mod_exp(
				   RSA_PKCS1_OpenSSL()));

	return rsa_hw_meth;
}

static void uadk_e_delete_rsa_meth(void)
{
	if (rsa_hw_meth) {
		RSA_meth_free(rsa_hw_meth);
		rsa_hw_meth = NULL;
	}
}

/**
 * uadk_e_bind_rsa() - Set the access to get rsa methods to the ENGINE.
 * @e: uadk engine
 */
int uadk_e_bind_rsa(ENGINE *e)
{
	return ENGINE_set_RSA(e, uadk_e_get_rsa_methods());
}

void uadk_e_destroy_rsa(void)
{
	pthread_spin_destroy(&g_rsa_res.lock);
	uadk_e_delete_rsa_meth();
	uadk_e_rsa_uninit();
}

void uadk_e_rsa_lock_init(void)
{
	pthread_spin_init(&g_rsa_res.lock, PTHREAD_PROCESS_PRIVATE);
}
