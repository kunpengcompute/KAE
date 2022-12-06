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

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <semaphore.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/async.h>

#include "hpre_wd.h"
#include <uadk/v1/wd_rsa.h>
#include "../../async/async_callback.h"
#include "../../async/async_task_queue.h"
#include "../../async/async_event.h"
#include "../../wdmngr/wd_queue_memory.h"
#include "../../utils/engine_types.h"
#include "hpre_rsa_utils.h"
#include "../../utils/engine_check.h"
#include "../../utils/engine_log.h"

static void hpre_rsa_cb(const void *message, void *tag);

KAE_QUEUE_POOL_HEAD_S *g_hpre_rsa_qnode_pool;

void wd_hpre_uninit_qnode_pool(void)
{
	kae_queue_pool_destroy(g_hpre_rsa_qnode_pool, NULL);
	g_hpre_rsa_qnode_pool = NULL;
}

int wd_hpre_init_qnode_pool(void)
{
	kae_queue_pool_destroy(g_hpre_rsa_qnode_pool, NULL);

	g_hpre_rsa_qnode_pool = kae_init_queue_pool(WCRYPTO_RSA);
	if (g_hpre_rsa_qnode_pool == NULL) {
		US_ERR("hpre rsa qnode poll init fail!\n");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;
}

KAE_QUEUE_POOL_HEAD_S *wd_hpre_get_qnode_pool(void)
{
	return g_hpre_rsa_qnode_pool;
}

static hpre_engine_ctx_t *hpre_new_eng_ctx(RSA *rsa_alg)
{
	hpre_engine_ctx_t *eng_ctx = NULL;

	eng_ctx = (hpre_engine_ctx_t *)OPENSSL_malloc(sizeof(hpre_engine_ctx_t));
	if (eng_ctx == NULL) {
		US_ERR("hpre engine_ctx malloc fail");
		return NULL;
	}
	kae_memset(eng_ctx, 0, sizeof(hpre_engine_ctx_t));

	eng_ctx->priv_ctx.ssl_alg = rsa_alg;
	eng_ctx->qlist = kae_get_node_from_pool(g_hpre_rsa_qnode_pool);
	if (eng_ctx->qlist == NULL) {
		US_ERR_LIMIT("error. get hardware queue failed");
		OPENSSL_free(eng_ctx);
		eng_ctx = NULL;
		return NULL;
	}
	eng_ctx->priv_ctx.is_privkey_ready = UNSET;
	eng_ctx->priv_ctx.is_pubkey_ready = UNSET;
	return eng_ctx;
}

static int hpre_init_eng_ctx(hpre_engine_ctx_t *eng_ctx, int bits)
{
	struct wd_queue *q = eng_ctx->qlist->kae_wd_queue;
	struct wd_queue_mempool *pool = eng_ctx->qlist->kae_queue_mem_pool;

	// this is for ctx is in use.we dont need to re create ctx->ctx again
	if (eng_ctx->ctx && eng_ctx->opdata.in) {
		kae_memset(eng_ctx->opdata.in, 0, eng_ctx->opdata.in_bytes);
		return OPENSSL_SUCCESS;
	}
	if (eng_ctx->ctx == NULL) {
		if (bits == 0)
			eng_ctx->priv_ctx.key_size = RSA_size(eng_ctx->priv_ctx.ssl_alg);
		else
			eng_ctx->priv_ctx.key_size = bits >> BIT_BYTES_SHIFT;

		eng_ctx->rsa_setup.key_bits = eng_ctx->priv_ctx.key_size << BIT_BYTES_SHIFT;
		eng_ctx->rsa_setup.is_crt = ISSET;
		eng_ctx->rsa_setup.cb = (wcrypto_cb)hpre_rsa_cb;
		eng_ctx->rsa_setup.br.alloc = kae_wd_alloc_blk;
		eng_ctx->rsa_setup.br.free = kae_wd_free_blk;
		eng_ctx->rsa_setup.br.iova_map = kae_dma_map;
		eng_ctx->rsa_setup.br.iova_unmap = kae_dma_unmap;
		eng_ctx->rsa_setup.br.usr = pool;
		eng_ctx->ctx = wcrypto_create_rsa_ctx(q, &eng_ctx->rsa_setup);

		if (eng_ctx->ctx == NULL) {
			US_ERR("create rsa ctx fail!");
			return OPENSSL_FAIL;
		}
	}

	return OPENSSL_SUCCESS;
}

hpre_engine_ctx_t *hpre_get_eng_ctx(RSA *rsa, int bits)
{
	hpre_engine_ctx_t *eng_ctx = hpre_new_eng_ctx(rsa);

	if (eng_ctx == NULL) {
		US_WARN("new eng ctx fail then switch to soft!");
		return NULL;
	}

	if (hpre_init_eng_ctx(eng_ctx, bits) == 0) {
		hpre_free_eng_ctx(eng_ctx);
		US_WARN("init eng ctx fail then switch to soft!");
		return NULL;
	}
	return eng_ctx;
}

void hpre_free_eng_ctx(hpre_engine_ctx_t *eng_ctx)
{
	US_DEBUG("hpre rsa free engine ctx start!");
	if (eng_ctx == NULL) {
		US_DEBUG("no eng_ctx to free");
		return;
	}

	if (eng_ctx->opdata.op_type != WCRYPTO_RSA_GENKEY) {
		if (eng_ctx->opdata.in)
			eng_ctx->rsa_setup.br.free(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->opdata.in);
		if (eng_ctx->opdata.out) {
			if (eng_ctx->qlist != NULL)
				eng_ctx->rsa_setup.br.free(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->opdata.out);
		}
	} else {
		if (eng_ctx->opdata.in)
			wcrypto_del_kg_in(eng_ctx->ctx, (struct wcrypto_rsa_kg_in *)eng_ctx->opdata.in);
		if (eng_ctx->opdata.out)
			wcrypto_del_kg_out(eng_ctx->ctx, (struct wcrypto_rsa_kg_out *)eng_ctx->opdata.out);
	}

	if (eng_ctx->qlist != NULL) {
		hpre_free_rsa_ctx(eng_ctx->ctx);
		kae_put_node_to_pool(g_hpre_rsa_qnode_pool, eng_ctx->qlist);
	}

	eng_ctx->priv_ctx.ssl_alg = NULL;
	eng_ctx->qlist = NULL;
	eng_ctx->ctx = NULL;
	eng_ctx->opdata.in = NULL;
	eng_ctx->opdata.out = NULL;
	eng_ctx->priv_ctx.is_privkey_ready = UNSET;
	eng_ctx->priv_ctx.is_pubkey_ready = UNSET;
	OPENSSL_free(eng_ctx);
	eng_ctx = NULL;
}

void hpre_free_rsa_ctx(void *ctx)
{
	if (ctx != NULL) {
		wcrypto_del_rsa_ctx(ctx);
		ctx = NULL;
	}
}

void hpre_rsa_fill_pubkey(const BIGNUM *e, const BIGNUM *n, hpre_engine_ctx_t *eng_ctx)
{
	struct wcrypto_rsa_pubkey *pubkey = NULL;
	struct wd_dtb *wd_e = NULL;
	struct wd_dtb *wd_n = NULL;

	wcrypto_get_rsa_pubkey(eng_ctx->ctx, &pubkey);
	wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, &wd_n);
	if (!eng_ctx->priv_ctx.is_pubkey_ready) {
		wd_e->dsize = BN_bn2bin(e, (unsigned char *)wd_e->data);
		wd_n->dsize = BN_bn2bin(n, (unsigned char *)wd_n->data);
		eng_ctx->priv_ctx.is_pubkey_ready = ISSET;
	}
}

/**
 * FILL prikey to rsa_ctx in normal mode
 * @param rsa       get prikey from rsa
 * @param rsa_ctx
 */
static void hpre_rsa_fill_prikey1(RSA *rsa, hpre_engine_ctx_t *eng_ctx)
{
	struct wcrypto_rsa_prikey *prikey = NULL;
	struct wd_dtb *wd_d = NULL;
	struct wd_dtb *wd_n = NULL;
	const BIGNUM *n = (const BIGNUM *)NULL;
	const BIGNUM *e = (const BIGNUM *)NULL;
	const BIGNUM *d = (const BIGNUM *)NULL;

	RSA_get0_key(rsa, &n, &e, &d);
	wcrypto_get_rsa_prikey(eng_ctx->ctx, &prikey);
	wcrypto_get_rsa_prikey_params(prikey, &wd_d, &wd_n);

	if (!eng_ctx->priv_ctx.is_privkey_ready) {
		wd_d->dsize = BN_bn2bin(d, (unsigned char *)wd_d->data);
		wd_n->dsize = BN_bn2bin(n, (unsigned char *)wd_n->data);
		eng_ctx->priv_ctx.is_privkey_ready = ISSET;
	}
}

/**
 * FILL prikey to rsa_ctx in crt mode
 * @param rsa       get prikey from rsa
 * @param rsa_ctx
 */
static void hpre_rsa_fill_prikey2(RSA *rsa, hpre_engine_ctx_t *eng_ctx)
{
	struct wcrypto_rsa_prikey *prikey = NULL;
	struct wd_dtb *wd_dq, *wd_dp, *wd_q, *wd_p, *wd_qinv;
	const BIGNUM *p = NULL;
	const BIGNUM *q = NULL;
	const BIGNUM *dmp1 = NULL;
	const BIGNUM *dmq1 = NULL;
	const BIGNUM *iqmp = NULL;

	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	wcrypto_get_rsa_prikey(eng_ctx->ctx, &prikey);
	wcrypto_get_rsa_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);
	if (!eng_ctx->priv_ctx.is_privkey_ready) {
		wd_dq->dsize = BN_bn2bin(dmq1, (unsigned char *)wd_dq->data);
		wd_dp->dsize = BN_bn2bin(dmp1, (unsigned char *)wd_dp->data);
		wd_q->dsize = BN_bn2bin(q, (unsigned char *)wd_q->data);
		wd_p->dsize = BN_bn2bin(p, (unsigned char *)wd_p->data);
		wd_qinv->dsize = BN_bn2bin(iqmp, (unsigned char *)wd_qinv->data);
		eng_ctx->priv_ctx.is_privkey_ready = ISSET;
	}
}

void hpre_rsa_fill_prikey(RSA *rsa, hpre_engine_ctx_t *eng_ctx, int version, const BIGNUM *p, const BIGNUM *q,
		const BIGNUM *dmp1, const BIGNUM *dmq1, const BIGNUM *iqmp)
{
	if (hpre_rsa_iscrt(rsa))
		hpre_rsa_fill_prikey2(rsa, eng_ctx);
	else
		hpre_rsa_fill_prikey1(rsa, eng_ctx);
}

int hpre_fill_keygen_opdata(void *ctx, struct wcrypto_rsa_op_data *opdata)
{
	struct wd_dtb *wd_e = NULL;
	struct wd_dtb *wd_p = NULL;
	struct wd_dtb *wd_q = NULL;
	struct wcrypto_rsa_pubkey *pubkey = NULL;
	struct wcrypto_rsa_prikey *prikey = NULL;

	wcrypto_get_rsa_pubkey(ctx, &pubkey);
	wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, NULL);
	wcrypto_get_rsa_prikey(ctx, &prikey);
	wcrypto_get_rsa_crt_prikey_params(prikey, NULL, NULL, NULL, &wd_q, &wd_p);
	opdata->in = wcrypto_new_kg_in(ctx, wd_e, wd_p, wd_q);
	if (!opdata->in) {
		US_ERR("create rsa kgen in fail!\n");
		return -ENOMEM;
	}
	opdata->out = wcrypto_new_kg_out(ctx);
	if (!opdata->out) {
		wcrypto_del_kg_in(ctx, (struct wcrypto_rsa_kg_in *)opdata->in);
		US_ERR("create rsa kgen out fail\n");
		return -ENOMEM;
	}

	return 0;
}

int hpre_rsa_get_keygen_param(struct wcrypto_rsa_op_data *opdata, void *ctx,
		RSA *rsa, BIGNUM *e_value, BIGNUM *p, BIGNUM *q)
{
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *dmp1 = BN_new();
	BIGNUM *dmq1 = BN_new();
	BIGNUM *iqmp = BN_new();
	struct wd_dtb wd_d;
	struct wd_dtb wd_n;
	struct wd_dtb wd_qinv;
	struct wd_dtb wd_dq;
	struct wd_dtb wd_dp;
	unsigned int key_bits, key_size;
	struct wcrypto_rsa_kg_out *out = (struct wcrypto_rsa_kg_out *)opdata->out;

	key_bits = wcrypto_rsa_key_bits(ctx);
	key_size = key_bits >> BIT_BYTES_SHIFT;
	wcrypto_get_rsa_kg_out_params(out, &wd_d, &wd_n);
	wcrypto_get_rsa_kg_out_crt_params(out, &wd_qinv, &wd_dq, &wd_dp);

	BN_bin2bn((unsigned char *)wd_d.data, key_size, d);
	BN_bin2bn((unsigned char *)wd_n.data, key_size, n);
	BN_bin2bn((unsigned char *)wd_qinv.data, wd_qinv.dsize, iqmp);
	BN_bin2bn((unsigned char *)wd_dq.data, wd_dq.dsize, dmq1);
	BN_bin2bn((unsigned char *)wd_dp.data, wd_dp.dsize, dmp1);

	if (!(RSA_set0_key(rsa, n, e_value, d) && RSA_set0_factors(rsa, p, q) &&
				RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp))) {
		KAEerr(KAE_F_RSA_FILL_KENGEN_PARAM, KAE_R_RSA_KEY_NOT_COMPELET);
		US_ERR("set key failed!");
		return OPENSSL_FAIL;
	} else {
		return OPENSSL_SUCCESS;
	}
}

static void hpre_rsa_cb(const void *message, void *tag)
{
	if (!message || !tag) {
		US_ERR("hpre cb params err!\n");
		return;
	}
	struct wcrypto_rsa_msg *msg = (struct wcrypto_rsa_msg *)message;
	hpre_engine_ctx_t *eng_ctx = (hpre_engine_ctx_t *)tag;

	eng_ctx->opdata.out = msg->out;
	eng_ctx->opdata.out_bytes = msg->out_bytes;
	eng_ctx->opdata.status = msg->result;
}

int hpre_rsa_sync(void *ctx, struct wcrypto_rsa_op_data *opdata)
{
	void *tag = NULL;
	int ret;

	if (!ctx || !opdata) {
		US_ERR("sync params err!");
		return HPRE_CRYPTO_FAIL;
	}

	ret = wcrypto_do_rsa(ctx, opdata, tag);
	if (ret != WD_SUCCESS) {
		US_ERR("hpre do rsa fail!");
		return HPRE_CRYPTO_FAIL;
	}

	return HPRE_CRYPTO_SUCC;
}

int hpre_rsa_async(hpre_engine_ctx_t *eng_ctx,
		   struct wcrypto_rsa_op_data *opdata, op_done_t *op_done)
{
	int ret = 0;
	int cnt = 0;
	enum task_type type = ASYNC_TASK_RSA;
	void *tag = eng_ctx;

	do {
		if (cnt > MAX_SEND_TRY_CNTS)
			break;
		ret = wcrypto_do_rsa(eng_ctx->ctx, opdata, tag);
		if (ret == WD_STATUS_BUSY) {
			if ((async_wake_job_v1(op_done->job, ASYNC_STATUS_EAGAIN) == 0 ||
						(async_pause_job_v1(op_done->job, ASYNC_STATUS_EAGAIN) == 0))) {
				US_ERR("hpre wake job or hpre pause job fail!");
				ret = 0;
				break;
			}
			cnt++;
		}
	} while (ret == WD_STATUS_BUSY);

	if (ret != WD_SUCCESS)
		return HPRE_CRYPTO_FAIL;

	if (async_add_poll_task_v1(eng_ctx, op_done, type) == 0)
		return HPRE_CRYPTO_FAIL;

	return HPRE_CRYPTO_SUCC;
}

int hpre_rsa_crypto(hpre_engine_ctx_t *eng_ctx, struct wcrypto_rsa_op_data *opdata)
{
	int job_ret;
	op_done_t op_done;

	async_init_op_done_v1(&op_done);

	if (op_done.job != NULL && kae_is_async_enabled()) {
		if (async_setup_async_event_notification_v1(0) == 0) {
			US_ERR("hpre async event notifying failed");
			async_cleanup_op_done_v1(&op_done);
			return HPRE_CRYPTO_FAIL;
		}
	} else {
		US_DEBUG("hpre rsa no async Job or async disable, back to sync!");
		async_cleanup_op_done_v1(&op_done);
		return hpre_rsa_sync(eng_ctx->ctx, opdata);
	}

	if (hpre_rsa_async(eng_ctx, opdata, &op_done) == HPRE_CRYPTO_FAIL)
		goto err;

	do {
		job_ret = async_pause_job_v1(op_done.job, ASYNC_STATUS_OK);
		if (job_ret == 0) {
			US_DEBUG("- pthread_yidle -");
			kae_pthread_yield();
		}
	}

	while (!op_done.flag || ASYNC_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

	if (op_done.verifyRst <= 0) {
		US_ERR("hpre rsa verify result failed with %d", op_done.verifyRst);
		async_cleanup_op_done_v1(&op_done);
		return HPRE_CRYPTO_FAIL;
	}

	async_cleanup_op_done_v1(&op_done);

	US_DEBUG("hpre rsa do async job success!");
	return HPRE_CRYPTO_SUCC;

err:
	US_ERR("hpre rsa do async job err");
	(void)async_clear_async_event_notification_v1();
	async_cleanup_op_done_v1(&op_done);
	return HPRE_CRYPTO_FAIL;
}
