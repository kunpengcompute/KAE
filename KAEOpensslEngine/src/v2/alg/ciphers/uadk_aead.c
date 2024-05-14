/*
 * Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <uadk/wd_aead.h>
#include <uadk/wd_sched.h>
#include "uadk_cipher_adapter.h"
#include "v2/uadk.h"
#include "v2/async/uadk_async.h"
#include "v2/utils/uadk_utils.h"

#define RET_FAIL		(-1)
#define STATE_FAIL		0xFFFF
#define CTX_SYNC_ENC		0
#define CTX_SYNC_DEC		1
#define CTX_ASYNC_ENC		2
#define CTX_ASYNC_DEC		3
#define CTX_NUM			4
#define AES_GCM_CTR_LEN		4
#define AES_GCM_BLOCK_SIZE	16
#define AES_GCM_IV_LEN		12
#define AES_GCM_TAG_LEN		16
#define GCM_FLAG	(EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_GCM_MODE \
			| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_AEAD_CIPHER \
			| EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT)
/* The max data length is 16M-512B */
#define AEAD_BLOCK_SIZE		0xFFFE00

struct aead_priv_ctx {
	handle_t sess;
	struct wd_aead_sess_setup setup;
	struct wd_aead_req req;
	unsigned char *data;
	unsigned char iv[AES_GCM_BLOCK_SIZE];
	unsigned char mac[AES_GCM_TAG_LEN];
	int taglen;
};

struct aead_engine {
	struct wd_ctx_config ctx_cfg;
	struct wd_sched sched;
	int numa_id;
	int pid;
	pthread_spinlock_t lock;
};

static struct aead_engine g_aead_engine;

static EVP_CIPHER *uadk_aes_128_gcm;
static EVP_CIPHER *uadk_aes_192_gcm;
static EVP_CIPHER *uadk_aes_256_gcm;

static int uadk_e_aead_env_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_aead_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static int uadk_e_aead_poll(void *ctx)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *) ctx;
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret, idx;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION_DIGEST)
		idx = CTX_ASYNC_ENC;
	else
		idx = CTX_ASYNC_DEC;

	do {
		ret = wd_aead_poll_ctx(idx, expt, &recv);
		if (!ret && recv == expt)
			return 0;
		else if (ret == -EAGAIN)
			rx_cnt++;
		else
			return RET_FAIL;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to recv msg: timeout!\n");

	return -ETIMEDOUT;
}

static handle_t sched_single_aead_init(handle_t h_sched_ctx, void *sched_param)
{
	struct sched_params *param = (struct sched_params *)sched_param;
	struct sched_params *skey;

	skey = malloc(sizeof(struct sched_params));
	if (!skey) {
		fprintf(stderr, "fail to alloc aead sched key!\n");
		return (handle_t)0;
	}

	skey->numa_id = param->numa_id;
	skey->type = param->type;

	return (handle_t)skey;
}

static __u32 sched_single_pick_next_ctx(handle_t sched_ctx, void *sched_key, const int sched_mode)
{
	struct sched_params *key = (struct sched_params *)sched_key;

	if (sched_mode) {
		if (key->type == WD_CIPHER_ENCRYPTION_DIGEST)
			return CTX_ASYNC_ENC;
		else
			return CTX_ASYNC_DEC;
	} else {
		if (key->type == WD_CIPHER_ENCRYPTION_DIGEST)
			return CTX_SYNC_ENC;
		else
			return CTX_SYNC_DEC;
	}
}

static int sched_single_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return 0;
}

static int uadk_e_wd_aead_cipher_env_init(struct uacce_dev *dev)
{
	int ret;

	ret = uadk_e_set_env("WD_AEAD_CTX_NUM", dev->numa_id);
	if (ret)
		return ret;

	ret = wd_aead_env_init(NULL);

	async_register_poll_fn(ASYNC_TASK_AEAD, uadk_e_aead_env_poll);

	return ret;
}

static int uadk_e_wd_aead_cipher_init(struct uacce_dev *dev)
{
	__u32 i, j;
	int ret;

	g_aead_engine.numa_id = dev->numa_id;

	ret = uadk_e_is_env_enabled("aead");
	if (ret)
		return uadk_e_wd_aead_cipher_env_init(dev);

	memset(&g_aead_engine.ctx_cfg, 0, sizeof(struct wd_ctx_config));
	g_aead_engine.ctx_cfg.ctx_num = CTX_NUM;
	g_aead_engine.ctx_cfg.ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!g_aead_engine.ctx_cfg.ctxs)
		return -ENOMEM;

	for (i = 0; i < CTX_NUM; i++) {
		g_aead_engine.ctx_cfg.ctxs[i].ctx = wd_request_ctx(dev);
		if (!g_aead_engine.ctx_cfg.ctxs[i].ctx) {
			ret = -ENOMEM;
			goto err_freectx;
		}
	}

	g_aead_engine.ctx_cfg.ctxs[CTX_SYNC_ENC].op_type = CTX_TYPE_ENCRYPT;
	g_aead_engine.ctx_cfg.ctxs[CTX_SYNC_DEC].op_type = CTX_TYPE_DECRYPT;
	g_aead_engine.ctx_cfg.ctxs[CTX_SYNC_ENC].ctx_mode = CTX_MODE_SYNC;
	g_aead_engine.ctx_cfg.ctxs[CTX_SYNC_DEC].ctx_mode = CTX_MODE_SYNC;

	g_aead_engine.ctx_cfg.ctxs[CTX_ASYNC_ENC].op_type = CTX_TYPE_ENCRYPT;
	g_aead_engine.ctx_cfg.ctxs[CTX_ASYNC_DEC].op_type = CTX_TYPE_DECRYPT;
	g_aead_engine.ctx_cfg.ctxs[CTX_ASYNC_ENC].ctx_mode = CTX_MODE_ASYNC;
	g_aead_engine.ctx_cfg.ctxs[CTX_ASYNC_DEC].ctx_mode = CTX_MODE_ASYNC;

	g_aead_engine.sched.name = "sched_single";
	g_aead_engine.sched.pick_next_ctx = sched_single_pick_next_ctx;
	g_aead_engine.sched.poll_policy = sched_single_poll_policy;
	g_aead_engine.sched.sched_init = sched_single_aead_init;

	ret = wd_aead_init(&g_aead_engine.ctx_cfg, &g_aead_engine.sched);
	if (ret)
		goto err_freectx;

	async_register_poll_fn(ASYNC_TASK_AEAD, uadk_e_aead_poll);
	return ret;

err_freectx:
	for (j = 0; j < i; j++)
		wd_release_ctx(g_aead_engine.ctx_cfg.ctxs[j].ctx);

	free(g_aead_engine.ctx_cfg.ctxs);

	return ret;
}

static int uadk_e_init_aead_cipher(void)
{
	struct uacce_dev *dev;
	int ret;

	if (g_aead_engine.pid != getpid()) {
		pthread_spin_lock(&g_aead_engine.lock);
		if (g_aead_engine.pid == getpid()) {
			pthread_spin_unlock(&g_aead_engine.lock);
			return 1;
		}

		dev = wd_get_accel_dev("aead");
		if (!dev) {
			pthread_spin_unlock(&g_aead_engine.lock);
			fprintf(stderr, "failed to get device for aead.\n");
			return 0;
		}

		ret = uadk_e_wd_aead_cipher_init(dev);
		if (ret < 0) {
			pthread_spin_unlock(&g_aead_engine.lock);
			fprintf(stderr, "failed to initiate aead cipher.\n");
			free(dev);
			return 0;
		}

		g_aead_engine.pid = getpid();
		pthread_spin_unlock(&g_aead_engine.lock);
		free(dev);
	}

	return 1;
}

static int uadk_e_ctx_init(struct aead_priv_ctx *priv, const unsigned char *ckey, int ckey_len)
{
	struct sched_params params = {0};
	int ret;

	ret = uadk_e_init_aead_cipher();
	if (!ret)
		return 0;

	params.type = priv->req.op_type;
	ret = uadk_e_is_env_enabled("aead");
	if (ret)
		params.type = 0;

	params.numa_id = g_aead_engine.numa_id;
	priv->setup.sched_param = &params;
	if (!priv->sess) {
		priv->sess = wd_aead_alloc_sess(&priv->setup);
		if (!priv->sess) {
			fprintf(stderr, "uadk engine failed to alloc aead session!\n");
			return 0;
		}
		ret = wd_aead_set_authsize(priv->sess, AES_GCM_TAG_LEN);
		if (ret < 0) {
			fprintf(stderr, "uadk engine failed to set authsize!\n");
			goto out;
		}

		ret = wd_aead_set_ckey(priv->sess, ckey, ckey_len);
		if (ret) {
			fprintf(stderr, "uadk engine failed to set ckey!\n");
			goto out;
		}

		if (ASYNC_get_current_job()) {
			/* Memory needs to be reserved for both input and output. */
			priv->data = malloc(AEAD_BLOCK_SIZE << 1);
			if (unlikely(!priv->data)) {
				fprintf(stderr, "uadk engine failed to alloc data!\n");
				goto out;
			}
		}
	}

	return 1;
out:
	wd_aead_free_sess(priv->sess);
	priv->sess = 0;
	return 0;
}

static int uadk_e_aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *ckey,
			       const unsigned char *iv, int enc)
{
	struct aead_priv_ctx *priv;
	int ret, ckey_len;

	priv = (struct aead_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (!priv) {
		fprintf(stderr, "invalid: aead priv ctx is NULL.\n");
		return 0;
	}

	if (unlikely(!ckey))
		return 1;

	if (iv)
		memcpy(priv->iv, iv, AES_GCM_IV_LEN);

	priv->setup.calg = WD_CIPHER_AES;
	priv->setup.cmode = WD_CIPHER_GCM;
	priv->setup.dalg = 0;
	priv->setup.dmode = 0;

	priv->req.assoc_bytes = 0;
	priv->req.out_bytes = 0;
	priv->req.data_fmt = WD_FLAT_BUF;

	priv->req.iv = priv->iv;
	priv->req.iv_bytes = AES_GCM_IV_LEN;
	memset(priv->iv + AES_GCM_IV_LEN, 0, AES_GCM_CTR_LEN);

	priv->req.mac = priv->mac;
	priv->req.mac_bytes = AES_GCM_TAG_LEN;
	priv->taglen = 0;
	priv->data = NULL;

	if (enc)
		priv->req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	else
		priv->req.op_type = WD_CIPHER_DECRYPTION_DIGEST;

	ckey_len = EVP_CIPHER_CTX_key_length(ctx);
	ret = uadk_e_ctx_init(priv, ckey, ckey_len);
	if (!ret)
		return 0;

	return 1;
}

static int uadk_e_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct aead_priv_ctx *priv;

	priv = (struct aead_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (!priv) {
		fprintf(stderr, "invalid: aead priv ctx is NULL.\n");
		return 0;
	}

	if (priv->sess) {
		wd_aead_free_sess(priv->sess);
		priv->sess = 0;
	}

	if (priv->data) {
		free(priv->data);
		priv->data = NULL;
	}

	return 1;
}

static int uadk_e_aes_gcm_set_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	void *ctx_buf = EVP_CIPHER_CTX_buf_noconst(ctx);
	int enc = EVP_CIPHER_CTX_encrypting(ctx);
	struct aead_priv_ctx *priv;

	priv = (struct aead_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (!priv) {
		fprintf(stderr, "invalid: aead priv ctx is NULL.\n");
		return 0;
	}

	switch (type) {
	case EVP_CTRL_INIT:
		priv->req.iv_bytes = 0;
		return 1;
# if (OPENSSL_VERSION_NUMBER >= 0x1010106fL)
	case EVP_CTRL_GET_IVLEN:
		*(int *)ptr = priv->req.iv_bytes;
		return 1;
#endif
	case EVP_CTRL_GCM_SET_IVLEN:
		if (arg != AES_GCM_IV_LEN) {
			fprintf(stderr, "invalid: aead gcm iv length only support 12B.\n");
			return 0;
		}
		return 1;
	case EVP_CTRL_GCM_GET_TAG:
		if (arg <= 0 || arg > AES_GCM_TAG_LEN || !enc) {
			fprintf(stderr, "cannot get tag when decrypt or arg is invalid.\n");
			return 0;
		}

		if (ctx_buf == NULL || ptr == NULL) {
			fprintf(stderr, "failed to get tag, ctx memory pointer is invalid.\n");
			return 0;
		}

		memcpy(ptr, ctx_buf, arg);
		return 1;
	case EVP_CTRL_GCM_SET_TAG:
		if (arg <= 0 || arg > AES_GCM_TAG_LEN || enc) {
			fprintf(stderr, "cannot set tag when encrypt or arg is invalid.\n");
			return 0;
		}

		if (ctx_buf == NULL || ptr == NULL) {
			fprintf(stderr, "failed to set tag, ctx memory pointer is invalid.\n");
			return 0;
		}

		memcpy(ctx_buf, ptr, arg);
		priv->taglen = arg;
		return 1;
	default:
		fprintf(stderr, "unsupported ctrl type: %d\n", type);
		return 0;
	}
}

static int uadk_e_do_aes_gcm_first(struct aead_priv_ctx *priv, unsigned char *out,
				   const unsigned char *in, size_t inlen)
{
	int ret;

	priv->req.assoc_bytes = inlen;

	/* Asynchronous jobs use the block mode. */
	if (ASYNC_get_current_job()) {
		memcpy(priv->data, in, inlen);
		return 1;
	}

	priv->req.src = (unsigned char *)in;
	priv->req.msg_state = AEAD_MSG_FIRST;

	ret = wd_do_aead_sync(priv->sess, &priv->req);
	if (unlikely(ret < 0)) {
		fprintf(stderr, "do aead first operation failed, ret: %d!\n", ret);
		return RET_FAIL;
	}

	return 1;
}

static int do_aead_sync(struct aead_priv_ctx *priv, unsigned char *out,
			const unsigned char *in, size_t inlen)
{
	int ret;

	/* Due to a hardware limitation, zero-length aad using block mode. */
	if (priv->req.assoc_bytes)
		priv->req.msg_state = AEAD_MSG_MIDDLE;
	else
		priv->req.msg_state = AEAD_MSG_BLOCK;

	priv->req.src = (unsigned char *)in;
	priv->req.dst = out;
	priv->req.in_bytes = inlen;
	priv->req.state = 0;
	ret = wd_do_aead_sync(priv->sess, &priv->req);
	if (ret < 0 || priv->req.state) {
		fprintf(stderr, "do aead update operation failed, ret: %d, state: %u!\n",
			ret, priv->req.state);
		return RET_FAIL;
	}

	return inlen;
}

static void *uadk_e_aead_cb(struct wd_aead_req *req, void *data)
{
	struct uadk_e_cb_info *cb_param;
	struct wd_aead_req *req_origin;
	struct async_op *op;

	if (!req)
		return NULL;

	cb_param = req->cb_param;
	if (!cb_param)
		return NULL;

	req_origin = cb_param->priv;
	req_origin->state = req->state;

	op = cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		async_wake_job(op->job);
	}

	return NULL;
}

static void do_aead_async_prepare(struct aead_priv_ctx *priv, unsigned char *out,
				  const unsigned char *in, size_t inlen)
{
	priv->req.in_bytes = inlen;
	/* AAD data is input or output together with plaintext or ciphertext. */
	if (priv->req.assoc_bytes) {
		memcpy(priv->data + priv->req.assoc_bytes, in, inlen);
		priv->req.src = priv->data;
		priv->req.dst = priv->data + AEAD_BLOCK_SIZE;
	} else {
		priv->req.src = (unsigned char *)in;
		priv->req.dst = out;
	}
}

static int do_aead_async(struct aead_priv_ctx *priv, struct async_op *op,
			 unsigned char *out, const unsigned char *in, size_t inlen)
{
	struct uadk_e_cb_info *cb_param;
	int cnt = 0;
	int ret;

	if (unlikely(priv->req.assoc_bytes + inlen > AEAD_BLOCK_SIZE)) {
		fprintf(stderr, "aead input data length is too long!\n");
		return 0;
	}

	do_aead_async_prepare(priv, out, in, inlen);

	cb_param = malloc(sizeof(struct uadk_e_cb_info));
	if (unlikely(!cb_param)) {
		fprintf(stderr, "failed to alloc cb_param.\n");
		return 0;
	}

	cb_param->op = op;
	cb_param->priv = &priv->req;
	priv->req.cb = uadk_e_aead_cb;
	priv->req.cb_param = cb_param;
	priv->req.msg_state = AEAD_MSG_BLOCK;
	priv->req.state = STATE_FAIL;

	ret = async_get_free_task(&op->idx);
	if (unlikely(!ret))
		goto free_cb_param;

	do {
		ret = wd_do_aead_async(priv->sess, &priv->req);
		if (unlikely(ret < 0)) {
			if (unlikely(ret != -EBUSY))
				fprintf(stderr, "do aead async operation failed.\n");
			else if (unlikely(cnt++ > ENGINE_SEND_MAX_CNT))
				fprintf(stderr, "do aead async operation timeout.\n");
			else
				continue;

			async_free_poll_task(op->idx, 0);
			ret = 0;
			goto free_cb_param;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, op, ASYNC_TASK_AEAD, op->idx);
	if (unlikely(!ret || priv->req.state)) {
		fprintf(stderr, "do aead async job failed, ret: %d, state: %u!\n",
			ret, priv->req.state);
		ret = 0;
		goto free_cb_param;
	}

	if (priv->req.assoc_bytes)
		memcpy(out, priv->req.dst + priv->req.assoc_bytes, inlen);

free_cb_param:
	free(cb_param);
	return ret;
}

static int uadk_e_do_aes_gcm_update(EVP_CIPHER_CTX *ctx, struct aead_priv_ctx *priv,
				    unsigned char *out, const unsigned char *in, size_t inlen)
{
	unsigned char *ctx_buf = EVP_CIPHER_CTX_buf_noconst(ctx);
	struct async_op *op;
	int ret, enc;

	enc = EVP_CIPHER_CTX_encrypting(ctx);
	if (!enc) {
		if (priv->taglen == AES_GCM_TAG_LEN) {
			memcpy(priv->req.mac, ctx_buf, AES_GCM_TAG_LEN);
		} else {
			fprintf(stderr, "invalid: aead gcm mac length only support 16B.\n");
			return RET_FAIL;
		}
	}

	if (ASYNC_get_current_job()) {
		op = malloc(sizeof(struct async_op));
		if (unlikely(!op))
			return RET_FAIL;

		ret = async_setup_async_event_notification(op);
		if (unlikely(!ret)) {
			fprintf(stderr, "failed to setup async event notification.\n");
			free(op);
			return RET_FAIL;
		}

		ret = do_aead_async(priv, op, out, in, inlen);
		if (unlikely(!ret))
			goto out;

		free(op);
		return inlen;
	}

	return do_aead_sync(priv, out, in, inlen);

out:
	(void)async_clear_async_event_notification();
	free(op);
	return RET_FAIL;
}

static int uadk_e_do_aes_gcm_final(EVP_CIPHER_CTX *ctx, struct aead_priv_ctx *priv,
				   unsigned char *out, const unsigned char *in, size_t inlen)
{
	unsigned char *ctx_buf = EVP_CIPHER_CTX_buf_noconst(ctx);
	int ret, enc;

	enc = EVP_CIPHER_CTX_encrypting(ctx);

	if (ASYNC_get_current_job() || !priv->req.assoc_bytes)
		goto out;

	priv->req.msg_state = AEAD_MSG_END;
	priv->req.src = NULL;
	priv->req.in_bytes = 0;
	priv->req.dst = out;
	priv->req.state = 0;
	ret = wd_do_aead_sync(priv->sess, &priv->req);
	if (ret < 0 || priv->req.state) {
		fprintf(stderr, "do aead final operation failed, ret: %d, state: %u!\n",
			ret, priv->req.state);
		return RET_FAIL;
	}

out:
	if (enc)
		memcpy(ctx_buf, priv->req.mac, AES_GCM_TAG_LEN);

	return 0;
}

static int uadk_e_do_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *out,
			     const unsigned char *in, size_t inlen)
{
	struct aead_priv_ctx *priv;

	priv = (struct aead_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (unlikely(!priv)) {
		fprintf(stderr, "invalid: aead priv ctx is NULL.\n");
		return 0;
	}

	if (in) {
		if (out == NULL)
			return uadk_e_do_aes_gcm_first(priv, out, in, inlen);

		return uadk_e_do_aes_gcm_update(ctx, priv, out, in, inlen);
	}

	return uadk_e_do_aes_gcm_final(ctx, priv, out, NULL, 0);
}

#define UADK_AEAD_DESCR(name, block_size, key_size, iv_len, flags, ctx_size,	\
			init, cipher, cleanup, set_params, get_params, ctrl)	\
do {\
	uadk_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);	\
	if (uadk_##name == 0 ||							\
	    !EVP_CIPHER_meth_set_iv_length(uadk_##name, iv_len) ||		\
	    !EVP_CIPHER_meth_set_flags(uadk_##name, flags) ||			\
	    !EVP_CIPHER_meth_set_impl_ctx_size(uadk_##name, ctx_size) ||	\
	    !EVP_CIPHER_meth_set_init(uadk_##name, init) ||			\
	    !EVP_CIPHER_meth_set_do_cipher(uadk_##name, cipher) ||		\
	    !EVP_CIPHER_meth_set_cleanup(uadk_##name, cleanup) ||		\
	    !EVP_CIPHER_meth_set_set_asn1_params(uadk_##name, set_params) ||	\
	    !EVP_CIPHER_meth_set_get_asn1_params(uadk_##name, get_params) ||	\
	    !EVP_CIPHER_meth_set_ctrl(uadk_##name, ctrl))			\
		return 0;\
} while (0)

EVP_CIPHER *uadk_create_gcm_cipher_meth(int nid)
{
	EVP_CIPHER *aead = NULL;

	switch (nid) {
	case NID_aes_128_gcm:
		UADK_AEAD_DESCR(aes_128_gcm, AES_GCM_BLOCK_SIZE, 16, AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx),
				uadk_e_aes_gcm_init, uadk_e_do_aes_gcm,	uadk_e_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				uadk_e_aes_gcm_set_ctrl);
		aead = uadk_aes_128_gcm;
		break;
	case NID_aes_192_gcm:
		UADK_AEAD_DESCR(aes_192_gcm, AES_GCM_BLOCK_SIZE, 24, AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx),
				uadk_e_aes_gcm_init, uadk_e_do_aes_gcm,	uadk_e_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				uadk_e_aes_gcm_set_ctrl);
		aead = uadk_aes_192_gcm;
		break;
	case NID_aes_256_gcm:
		UADK_AEAD_DESCR(aes_256_gcm, AES_GCM_BLOCK_SIZE, 32, AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx),
				uadk_e_aes_gcm_init, uadk_e_do_aes_gcm, uadk_e_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				uadk_e_aes_gcm_set_ctrl);
		aead = uadk_aes_256_gcm;
		break;
	default:
		aead = NULL;
		break;
	}

	return aead;
}

static void destroy_aead(struct engine_cipher_info *info, int num)
{
	__u32 i;

	for (i = 0; i < num; i++) {
		if (info[i].cipher != NULL) {
			EVP_CIPHER_meth_free(info[i].cipher);
			info[i].cipher = NULL;
		}
	}
}

void uadk_e_destroy_aead(struct engine_cipher_info *info, int num)
{
	__u32 i;
	int ret;

	if (g_aead_engine.pid == getpid()) {
		ret = uadk_e_is_env_enabled("aead");
		if (ret) {
			wd_aead_env_uninit();
		} else {
			wd_aead_uninit();
			for (i = 0; i < g_aead_engine.ctx_cfg.ctx_num; i++)
				wd_release_ctx(g_aead_engine.ctx_cfg.ctxs[i].ctx);

			free(g_aead_engine.ctx_cfg.ctxs);
		}
		g_aead_engine.pid = 0;
	}

	pthread_spin_destroy(&g_aead_engine.lock);
	destroy_aead(info, num);
}

void uadk_e_aead_lock_init(void)
{
	pthread_spin_init(&g_aead_engine.lock, PTHREAD_PROCESS_PRIVATE);
}
