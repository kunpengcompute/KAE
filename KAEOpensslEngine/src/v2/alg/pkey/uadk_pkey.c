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
#include <openssl/engine.h>
#include <uadk/wd.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "v2/async/uadk_async.h"
#include "v2/uadk.h"
#include "v2/alg/pkey/uadk_pkey.h"
#include "utils/engine_log.h"

#define ECC_MAX_DEV_NUM		16
#define CTX_ASYNC		1
#define CTX_SYNC		0
#define CTX_NUM			2
#define GET_RAND_MAX_CNT	100

static int pkey_nids[] = {
	EVP_PKEY_EC,
	EVP_PKEY_SM2,
	EVP_PKEY_X25519,
	EVP_PKEY_X448
};

struct ecc_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct ecc_res_config {
	struct ecc_sched sched;
	int numa_id;
};

/* ECC global hardware resource is saved here */
struct ecc_res {
	struct wd_ctx_config *ctx_res;
	int pid;
	pthread_spinlock_t lock;
} ecc_res;

static struct uadk_pkey_meth pkey_meth;

static handle_t ecc_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 ecc_pick_next_ctx(handle_t sched_ctx,
		void *sched_key, const int sched_mode)
{
	if (sched_mode)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

static int ecc_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return 0;
}

void uadk_ecc_cb(void *req_t)
{
	struct wd_ecc_req *req_new = (struct wd_ecc_req *)req_t;
	struct uadk_e_cb_info *cb_param;
	struct wd_ecc_req *req_origin;
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
		op->ret = 0;
		async_free_poll_task(op->idx, 1);
		async_wake_job(op->job);
	}
}

static int uadk_ecc_poll(void *ctx)
{
	unsigned int recv = 0;
	__u64 rx_cnt = 0;
	int expt = 1;
	int ret;

	do {
		ret = wd_ecc_poll_ctx(CTX_ASYNC, expt, &recv);
		if (!ret && recv == expt)
			return 0;
		else if (ret == -EAGAIN)
			rx_cnt++;
		else
			return -1;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to recv msg: timeout!\n");

	return -ETIMEDOUT;
}

/* Make resource configure static */
struct ecc_res_config ecc_res_config = {
	.sched = {
		.sched_type = -1,
		.wd_sched = {
			.name = "ECC RR",
			.sched_init = ecc_sched_init,
			.pick_next_ctx = ecc_pick_next_ctx,
			.poll_policy = ecc_poll_policy,
			.h_sched_ctx = 0,
		},
	},
	.numa_id = 0,
};

int uadk_e_ecc_get_numa_id(void)
{
	return ecc_res_config.numa_id;
}

static int uadk_e_ecc_env_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_ecc_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static int uadk_e_wd_ecc_env_init(struct uacce_dev *dev)
{
	int ret;

	ret = uadk_e_set_env("WD_ECC_CTX_NUM", dev->numa_id);
	if (ret)
		return ret;

	ret = wd_ecc_env_init(NULL);
	if (ret)
		return ret;

	async_register_poll_fn(ASYNC_TASK_ECC, uadk_e_ecc_env_poll);

	return 0;
}

static int uadk_e_wd_ecc_general_init(struct uacce_dev *dev,
				      struct wd_sched *sched)
{
	struct wd_ctx_config *ctx_cfg;
	int ret, i;

	ctx_cfg = calloc(1, sizeof(struct wd_ctx_config));
	if (!ctx_cfg)
		return -ENOMEM;

	ecc_res.ctx_res = ctx_cfg;
	ctx_cfg->ctx_num = CTX_NUM;
	ctx_cfg->ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!ctx_cfg->ctxs) {
		ret = -ENOMEM;
		goto free_cfg;
	}

	for (i = 0; i < CTX_NUM; i++) {
		ctx_cfg->ctxs[i].ctx = wd_request_ctx(dev);
		if (!ctx_cfg->ctxs[i].ctx) {
			ret = -EINVAL;
			goto free_ctx;
		}
		ctx_cfg->ctxs[i].ctx_mode = (i == 0) ? CTX_SYNC : CTX_ASYNC;
	}

	ret = wd_ecc_init(ctx_cfg, sched);
	if (ret)
		goto free_ctx;

	async_register_poll_fn(ASYNC_TASK_ECC, uadk_ecc_poll);

	return 0;

free_ctx:
	for (i = 0; i < CTX_NUM; i++) {
		if (ctx_cfg->ctxs[i].ctx)
			wd_release_ctx(ctx_cfg->ctxs[i].ctx);
	}
	free(ctx_cfg->ctxs);
free_cfg:
	free(ctx_cfg);
	ecc_res.ctx_res = NULL;

	return ret;
}

static int uadk_wd_ecc_init(struct ecc_res_config *config)
{
	struct wd_sched *sched = &config->sched.wd_sched;
	struct uacce_dev *dev;
	int ret;

	/* The ctx is no difference for sm2/ecdsa/ecdh/x25519/x448 */
	dev = wd_get_accel_dev("ecdsa");
	if (!dev)
		return -ENOMEM;

	config->numa_id = dev->numa_id;

	ret = uadk_e_is_env_enabled("ecc");
	if (ret)
		ret = uadk_e_wd_ecc_env_init(dev);
	else
		ret = uadk_e_wd_ecc_general_init(dev, sched);

	free(dev);

	return ret;
}

static void uadk_wd_ecc_uninit(void)
{
	struct wd_ctx_config *ctx_cfg = ecc_res.ctx_res;
	int i, ret;

	if (ecc_res.pid != getpid())
		return;

	ret = uadk_e_is_env_enabled("ecc");
	if (ret == ENV_ENABLED) {
		wd_ecc_env_uninit();
	} else {
		wd_ecc_uninit();
		for (i = 0; i < ctx_cfg->ctx_num; i++)
			wd_release_ctx(ctx_cfg->ctxs[i].ctx);
		free(ctx_cfg->ctxs);
		free(ctx_cfg);
		ecc_res.ctx_res = NULL;
	}
	ecc_res.pid = 0;
}

int uadk_ecc_crypto(handle_t sess, struct wd_ecc_req *req, void *usr)
{
	US_DEBUG("uadk_ecc_crypto start");
	struct uadk_e_cb_info cb_param;
	struct async_op op;
	int idx, ret;

	ret = async_setup_async_event_notification(&op);
	if (!ret) {
		fprintf(stderr, "failed to setup async event notification.\n");
		return 0;
	}

	if (op.job != NULL) {
		cb_param.op = &op;
		cb_param.priv = req;
		req->cb_param = &cb_param;
		req->cb = (void *)uadk_ecc_cb;
		req->status = -1;
		ret = async_get_free_task(&idx);
		if (!ret)
			goto err;

		op.idx = idx;

		do {
			ret = wd_do_ecc_async(sess, req);
			if (ret < 0 && ret != -EBUSY) {
				async_free_poll_task(op.idx, 0);
				goto err;
			}
		} while (ret == -EBUSY);

		ret = async_pause_job((void *)usr, &op, ASYNC_TASK_ECC, idx);
		if (!ret)
			goto err;
		if (req->status)
			return 0;
		US_DEBUG("do ecc job async successed");
	} else {
		ret = wd_do_ecc_sync(sess, req);
		if (ret < 0){
			US_DEBUG("wd_do_ecc_sync failed");
			return 0;
		}
		US_DEBUG("wd_do_ecc_sync successed");
	}
	return 1;
err:
	US_DEBUG("wd_do_ecc_sync failed");
	(void)async_clear_async_event_notification();
	return 0;
}

bool uadk_is_all_zero(const unsigned char *data, size_t dlen)
{
	int i;

	for (i = 0; i < dlen; i++) {
		if (data[i])
			return false;
	}

	return true;
}

int uadk_ecc_set_public_key(handle_t sess, const EC_KEY *eckey)
{
	unsigned char *point_bin = NULL;
	struct wd_ecc_point pubkey;
	struct wd_ecc_key *ecc_key;
	const EC_POINT *point;
	const EC_GROUP *group;
	int ret, len;

	point = EC_KEY_get0_public_key(eckey);
	if (!point) {
		fprintf(stderr, "pubkey not set!\n");
		return -EINVAL;
	}

	group = EC_KEY_get0_group(eckey);
	len = EC_POINT_point2buf(group, point, UADK_OCTET_STRING,
				 &point_bin, NULL);
	if (!len) {
		fprintf(stderr, "EC_POINT_point2buf error.\n");
		return -EINVAL;
	}

	len /= UADK_ECC_PUBKEY_PARAM_NUM;
	pubkey.x.data = (char *)point_bin + 1;
	pubkey.x.dsize = len;
	pubkey.y.data = pubkey.x.data + len;
	pubkey.y.dsize = len;
	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_pubkey(ecc_key, &pubkey);
	if (ret) {
		fprintf(stderr, "failed to set ecc pubkey\n");
		ret = UADK_DO_SOFT;
	}

	free(point_bin);

	return ret;
}

int uadk_ecc_set_private_key(handle_t sess, const EC_KEY *eckey)
{
	unsigned char bin[UADK_ECC_MAX_KEY_BYTES];
	struct wd_ecc_key *ecc_key;
	const EC_GROUP *group;
	struct wd_dtb prikey;
	const BIGNUM *d;
	size_t degree;
	int buflen;
	int ret;

	d = EC_KEY_get0_private_key(eckey);
	if (!d) {
		fprintf(stderr, "private key not set\n");
		return -EINVAL;
	}

	group = EC_KEY_get0_group(eckey);
	if (!group) {
		fprintf(stderr, "failed to get ecc group\n");
		return -EINVAL;
	}

	degree = EC_GROUP_get_degree(group);
	buflen = BITS_TO_BYTES(degree);
	ecc_key = wd_ecc_get_key(sess);
	prikey.data = (void *)bin;
	prikey.dsize = BN_bn2binpad(d, bin, buflen);

	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		ret = UADK_DO_SOFT;
	}

	return ret;
}

int uadk_ecc_get_rand(char *out, size_t out_len, void *usr)
{
	int count = GET_RAND_MAX_CNT;
	BIGNUM *k;
	int ret;

	if (!out) {
		fprintf(stderr, "out is NULL\n");
		return -1;
	}

	k = BN_new();
	if (!k)
		return -ENOMEM;

	do {
		ret = BN_priv_rand_range(k, usr);
		if (!ret) {
			fprintf(stderr, "failed to BN_priv_rand_range\n");
			ret = -EINVAL;
			goto err;
		}

		ret = BN_bn2binpad(k, (void *)out, (int)out_len);
		if (ret < 0) {
			ret = -EINVAL;
			fprintf(stderr, "failed to BN_bn2binpad\n");
			goto err;
		}
	} while (--count >= 0 && BN_is_zero(k));

	ret = 0;
	if (count < 0)
		ret = -1;
err:
	BN_free(k);

	return ret;
}

bool uadk_prime_field(const EC_GROUP *group)
{
	int type = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

	return type == NID_X9_62_prime_field;
}

int uadk_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
		     BIGNUM *b, BN_CTX *ctx)
{
# if OPENSSL_VERSION_NUMBER > 0x10101000L
	if (!EC_GROUP_get_curve(group, p, a, b, ctx))
		return -1;
# else
	if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx))
		return -1;
# endif
	return 0;
}

int uadk_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p,
				BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
# if OPENSSL_VERSION_NUMBER > 0x10101000L
	if (!EC_POINT_get_affine_coordinates(group, p, x, y, ctx))
		return -1;
# else
	if (!EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx))
		return -1;
# endif
	return 0;
}

void uadk_ecc_fill_req(struct wd_ecc_req *req, unsigned int op,
		       void *in, void *out)
{
	req->op_type = op;
	req->src = in;
	req->dst = out;
}

bool uadk_support_algorithm(const char *alg)
{
	struct uacce_dev_list *list = wd_get_accel_list(alg);

	if (list) {
		wd_free_list_accels(list);
		US_DEBUG("uadk support alg: %s", alg);
		return true;
	}

	US_DEBUG("uadk not support alg: %s", alg);
	return false;
}

int uadk_init_ecc(void)
{
	int ret;

	if (!uadk_support_algorithm("sm2") &&
	    !uadk_support_algorithm("ecdsa") &&
	    !uadk_support_algorithm("ecdh") &&
	    !uadk_support_algorithm("x25519") &&
	    !uadk_support_algorithm("x448"))
		return -EINVAL;

	if (ecc_res.pid != getpid()) {
		pthread_spin_lock(&ecc_res.lock);
		if (ecc_res.pid == getpid()) {
			pthread_spin_unlock(&ecc_res.lock);
			return 0;
		}

		ret = uadk_wd_ecc_init(&ecc_res_config);
		if (ret) {
			fprintf(stderr, "failed to init ec(%d).\n", ret);
			goto err_unlock;
		}

		ecc_res.pid = getpid();
		pthread_spin_unlock(&ecc_res.lock);
	}

	return 0;

err_unlock:
	pthread_spin_unlock(&ecc_res.lock);
	return ret;
}

static void uadk_uninit_ecc(void)
{
	uadk_wd_ecc_uninit();
}

const EVP_PKEY_METHOD *get_openssl_pkey_meth(int nid)
{
	size_t count = EVP_PKEY_meth_get_count();
	const EVP_PKEY_METHOD *pmeth;
	int pkey_id = -1;
	int i;

	for (i = 0; i < count; i++) {
		pmeth = EVP_PKEY_meth_get0(i);
		EVP_PKEY_meth_get0_info(&pkey_id, NULL, pmeth);
		if (nid == pkey_id)
			return pmeth;
	}

	fprintf(stderr, "not find openssl method %d\n", nid);
	return NULL;
}

static int get_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
			  const int **nids, int nid)
{
	US_DEBUG("get_pkey_meths start\n");
	int ret;

	if (!pmeth) {
		US_DEBUG("pmeth is NULL");
		*nids = pkey_nids;
		return ARRAY_SIZE(pkey_nids);
	}

	US_DEBUG("switch alg to create EVP_PKEY_METHOD by nids\n");
	switch (nid) {
	case EVP_PKEY_SM2:
		ret = uadk_sm2_create_pmeth(&pkey_meth);
		if (!ret) {
			fprintf(stderr, "failed to register sm2 pmeth.\n");
			return 0;
		}
		US_DEBUG("successed to register sm2 pmeth.\n");
		*pmeth = pkey_meth.sm2;
		break;
	case EVP_PKEY_EC:
		ret = uadk_ec_create_pmeth(&pkey_meth);
		if (!ret) {
			fprintf(stderr, "failed to register ec pmeth.\n");
			return 0;
		}
		US_DEBUG("successed to register ec pmeth.\n");
		*pmeth = pkey_meth.ec;
		break;
	case EVP_PKEY_X448:
		ret = uadk_x448_create_pmeth(&pkey_meth);
		if (!ret) {
			fprintf(stderr, "failed to register x448 pmeth.\n");
			return 0;
		}
		US_DEBUG("successed to register x448 pmeth.\n");
		*pmeth = pkey_meth.x448;
		break;
	case EVP_PKEY_X25519:
		ret = uadk_x25519_create_pmeth(&pkey_meth);
		if (!ret) {
			fprintf(stderr, "failed to register x25519 pmeth.\n");
			return 0;
		}
		US_DEBUG("successed to register x25519 pmeth.\n");
		*pmeth = pkey_meth.x25519;
		break;
	default:
		fprintf(stderr, "not find nid %d\n", nid);
		return 0;
	}

	US_DEBUG("successed to get_pkey_meths");
	return 1;
}

static int uadk_ecc_bind_pmeth(ENGINE *e)
{
	US_DEBUG("uadk_e_bind_dh to set the implementation of the pkey method");
	return ENGINE_set_pkey_meths(e, get_pkey_meths);
}

void uadk_e_ecc_lock_init(void)
{
	pthread_spin_init(&ecc_res.lock, PTHREAD_PROCESS_PRIVATE);
}

int uadk_e_bind_ecc(ENGINE *e)
{
	US_DEBUG("uadk_e_bind_ecc start.\n");
	int ret;

	ret = uadk_ecc_bind_pmeth(e);
	if (!ret) {
		fprintf(stderr, "failed to bind ecc pmeth\n");
		US_ERR("failed to bind ecc pmeth\n");		
		return ret;
	}

	ret = uadk_bind_ec(e);
	if (!ret) {
		fprintf(stderr, "failed to bind ec\n");
		US_ERR("failed to bind ec\n");
		return ret;
	}
	US_DEBUG("uadk_e_bind_ecc successed.\n");
	return ret;
}

void uadk_e_destroy_ecc(void)
{
	pthread_spin_destroy(&ecc_res.lock);
	uadk_ec_delete_meth();
	uadk_uninit_ecc();
}
