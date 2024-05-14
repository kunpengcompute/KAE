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
#include "sec_ciphers_aead.h"
#include "sec_ciphers_utils.h"

#include "../../utils/engine_check.h"
#include "../../utils/engine_types.h"
#include "../../../utils/engine_log.h"
#include "../../../utils/engine_utils.h"
#include "../../async/async_callback.h"
#include "../../async/async_event.h"
#include "../../async/async_task_queue.h"

#define AEAD_OUTPUT_CACHE_SIZE  (256*1024)
#define AEAD_INPUT_CACHE_SIZE   (256*1024)
#define MAX_KEY_SIZE       64
#define MAX_IV_SIZE        16

#define SEC_AES_GCM_BLOCK_SIZE	16
#define SEC_AES_GCM_IV_LEN		12
#define AES_GCM_TAG_LEN		16
#define GCM_FLAG	(EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_GCM_MODE \
			| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_AEAD_CIPHER \
			| EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT)

static EVP_CIPHER *sec_aes_128_gcm;
static EVP_CIPHER *sec_aes_192_gcm;
static EVP_CIPHER *sec_aes_256_gcm;

KAE_QUEUE_POOL_HEAD_S *g_sec_aeads_qnode_pool;

void wd_aead_free_engine_ctx(void *engine_ctx)
{
	aead_engine_ctx_t *e_aead_ctx = (aead_engine_ctx_t *)engine_ctx;

	if (e_aead_ctx == NULL)
		return;

	// 我理解aead_engine_ctx_t并未申请内存，aead_priv_ctx_t申请的内存在aead_priv_ctx_t处理，后续看下cipher的逻辑
	if (e_aead_ctx->op_data.in && e_aead_ctx->setup.br.usr) {
		e_aead_ctx->setup.br.free(e_aead_ctx->setup.br.usr, (void *)e_aead_ctx->op_data.in);
		e_aead_ctx->op_data.in = NULL;
	}

	if (e_aead_ctx->op_data.out && e_aead_ctx->setup.br.usr) {
		e_aead_ctx->setup.br.free(e_aead_ctx->setup.br.usr, (void *)e_aead_ctx->op_data.out);
		e_aead_ctx->op_data.out = NULL;
	}

	if (e_aead_ctx->op_data.iv && e_aead_ctx->setup.br.usr) {
		e_aead_ctx->setup.br.free(e_aead_ctx->setup.br.usr, (void *)e_aead_ctx->op_data.iv);
		e_aead_ctx->op_data.iv = NULL;
	}

	OPENSSL_free(e_aead_ctx);
	e_aead_ctx = NULL;
}


static aead_engine_ctx_t *wd_aeads_new_engine_ctx(KAE_QUEUE_DATA_NODE_S *q_node, aead_priv_ctx_t *priv_ctx)
{
	aead_engine_ctx_t *e_aead_ctx = NULL;

	e_aead_ctx = (aead_engine_ctx_t *)OPENSSL_malloc(sizeof(aead_engine_ctx_t));
	if (e_aead_ctx == NULL) {
		US_ERR("OPENSSL_malloc ctx failed");
		return NULL;
	}
	kae_memset(e_aead_ctx, 0, sizeof(aead_engine_ctx_t));

	e_aead_ctx->setup.br.alloc = kae_wd_alloc_blk;
	e_aead_ctx->setup.br.free = kae_wd_free_blk;
	e_aead_ctx->setup.br.iova_map = kae_dma_map;
	e_aead_ctx->setup.br.iova_unmap = kae_dma_unmap;
	e_aead_ctx->setup.br.usr = q_node->kae_queue_mem_pool;

	if (e_aead_ctx->op_data.in == NULL) {
		e_aead_ctx->op_data.in = e_aead_ctx->setup.br.alloc(e_aead_ctx->setup.br.usr, INPUT_CACHE_SIZE); //一次性申请20M是不是太大了
	}

	if (e_aead_ctx->op_data.out == NULL) {
		e_aead_ctx->op_data.out = e_aead_ctx->setup.br.alloc(e_aead_ctx->setup.br.usr, OUTPUT_CACHE_SIZE);
	}

	if (e_aead_ctx->op_data.iv == NULL) {
		e_aead_ctx->op_data.iv = e_aead_ctx->setup.br.alloc(e_aead_ctx->setup.br.usr, 12);
	}
	

	e_aead_ctx->priv_ctx = priv_ctx;
	e_aead_ctx->q_node = q_node;
	q_node->engine_ctx = e_aead_ctx;

	return e_aead_ctx;
}

void sec_aead_cb(const void *msg, void *tag)
{
	if (!msg || !tag) {
		US_ERR("sec cb params err!\n");
		return;
	}
	struct wcrypto_aead_msg *message = (struct wcrypto_aead_msg *)msg;
	aead_engine_ctx_t *eng_ctx = (aead_engine_ctx_t *)tag;

	kae_memcpy(eng_ctx->priv_ctx->out_data_buf, message->out, message->out_bytes);
}

static int wd_aeads_init_engine_ctx(aead_engine_ctx_t *e_aead_ctx)
{
	struct wd_queue *q = e_aead_ctx->q_node->kae_wd_queue;
	aead_priv_ctx_t *priv_ctx = e_aead_ctx->priv_ctx;

	if (e_aead_ctx->wd_ctx != NULL) {
		US_WARN("wd ctx is in used by other aeads");

		return KAE_FAIL;
	}

	e_aead_ctx->setup.calg  = (enum wcrypto_cipher_alg)priv_ctx->c_alg;    // for example: WD_aead_SM4;
	e_aead_ctx->setup.cmode = (enum wcrypto_cipher_mode)priv_ctx->c_mode;  // for example: WD_aead_CBC;
	e_aead_ctx->setup.cb = (wcrypto_cb)sec_aead_cb; // 异步使用
	e_aead_ctx->wd_ctx = wcrypto_create_aead_ctx(q, &e_aead_ctx->setup);

	if (e_aead_ctx->wd_ctx == NULL) {
		US_ERR("wd create sec aead ctx fail!");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;
}

void wd_aeads_put_engine_ctx(aead_engine_ctx_t *e_aead_ctx)
{
	if (unlikely(e_aead_ctx == NULL)) {
		US_WARN("sec cipher engine ctx NULL!");
		return;
	}
    //e_aead_ctx->wd_ctx
	if (e_aead_ctx->wd_ctx != NULL) {
		wcrypto_del_aead_ctx(e_aead_ctx->wd_ctx);
		e_aead_ctx->wd_ctx = NULL;
	}

	if (e_aead_ctx->q_node != NULL) {
		(void)kae_put_node_to_pool(g_sec_aeads_qnode_pool, e_aead_ctx->q_node);
	}

	e_aead_ctx = NULL;
	return;
}

aead_engine_ctx_t *wd_aead_get_engine_ctx(aead_priv_ctx_t *priv_ctx)
{
	KAE_QUEUE_DATA_NODE_S *q_node = NULL;
	aead_engine_ctx_t *e_aead_ctx = NULL;

	if (unlikely(priv_ctx == NULL)) {
		US_ERR("sec aead priv ctx NULL!");
		return NULL;
	}

    //KAE_QUEUE_DATA_NODE_S
	q_node = kae_get_node_from_pool(g_sec_aeads_qnode_pool);
	if (q_node == NULL) {
		US_ERR("failed to get hardware queue");
		return NULL;
	}

    // wcrypto_aead_ctx_setup wcrypto_aead_op_data
	e_aead_ctx = (aead_engine_ctx_t *)q_node->engine_ctx;
	if (e_aead_ctx == NULL) {
		e_aead_ctx = wd_aeads_new_engine_ctx(q_node, priv_ctx);
		if (e_aead_ctx == NULL) {
			US_WARN("sec new engine ctx fail!");
			(void)kae_put_node_to_pool(g_sec_aeads_qnode_pool, q_node);
			return NULL;
		}
	}

	e_aead_ctx->priv_ctx = priv_ctx;

	if (wd_aeads_init_engine_ctx(e_aead_ctx) == KAE_FAIL) {
		US_WARN("init engine ctx fail!");
		wd_aeads_put_engine_ctx(e_aead_ctx);
		return NULL;
	}

	return e_aead_ctx;
}

static int sec_aead_engine_cleanup(aead_priv_ctx_t *priv_ctx)
{
	if (unlikely(priv_ctx == NULL)) {
		US_WARN("ctx is NULL");
		return OPENSSL_FAIL;
	}

	if (priv_ctx->e_aead_ctx != NULL){
		wd_aeads_put_engine_ctx(priv_ctx->e_aead_ctx);
		priv_ctx->e_aead_ctx = NULL;
	}

	if (priv_ctx->key != NULL) {
		kae_free(priv_ctx->key);
	}

	US_DEBUG("AEAD Cleanup success, ctx=%p", priv_ctx);

	return OPENSSL_SUCCESS;
}

static int sec_aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *ckey,
			       const unsigned char *iv, int encrypt)
{
    int nid = 0;
    int ret, ckey_len;
	aead_priv_ctx_t *priv_ctx = NULL;

	if (unlikely((ctx == NULL))) {
		US_ERR("ctx or key is NULL.");
		return OPENSSL_FAIL;
	}

	if (unlikely(!ckey))
		return OPENSSL_SUCCESS;

	if (encrypt != EVP_CIPHER_CTX_encrypting(ctx)) {
		US_ERR("encrypt different, ctx=%p", ctx);
		return OPENSSL_FAIL;
	}

    priv_ctx = (aead_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (unlikely(priv_ctx == NULL)) {
		US_ERR("sec private ctx is NULL");
		return OPENSSL_FAIL;
	}

    // init cipher mode and alg of private ctx
	nid = EVP_CIPHER_CTX_nid(ctx);
	priv_ctx->c_mode = sec_ciphers_get_cipher_mode(nid);
	priv_ctx->c_alg = sec_ciphers_get_cipher_alg(nid);

    //iv
    if (iv) {
		memset(priv_ctx->iv, 0, 16);
		memcpy(priv_ctx->iv, iv, 12);//AES_GCM_IV_LEN
	}
	priv_ctx->iv_len = 12; //AES_GCM_IV_LEN

    // engine_ctx
    if (priv_ctx->e_aead_ctx == NULL) {
		priv_ctx->e_aead_ctx = wd_aead_get_engine_ctx(priv_ctx);
		if (priv_ctx->e_aead_ctx == NULL) {
			US_WARN("failed to get engine ctx, switch to soft cipher");
			goto ERR;
		}
	}

    //encrypt ==> optype
    if (encrypt)
		priv_ctx->e_aead_ctx->op_data.op_type = WCRYPTO_CIPHER_ENCRYPTION_DIGEST; // aad + plen + authsize;
	else
		priv_ctx->e_aead_ctx->op_data.op_type = WCRYPTO_CIPHER_DECRYPTION_DIGEST; // aad + plen;

    // opdata
	priv_ctx->data_buf = priv_ctx->e_aead_ctx->op_data.in;
	priv_ctx->out_data_buf = priv_ctx->e_aead_ctx->op_data.out;
	priv_ctx->iv = priv_ctx->e_aead_ctx->op_data.iv;
    // ckey akey
    if (ckey) {
        ckey_len = EVP_CIPHER_CTX_key_length(ctx);
		priv_ctx->key = (uint8_t *)kae_malloc(ckey_len); 
		kae_memcpy(priv_ctx->key, ckey, ckey_len);
        wcrypto_set_aead_ckey(priv_ctx->e_aead_ctx->wd_ctx, priv_ctx->key, ckey_len);
        priv_ctx->key_len = ckey_len;  //感觉多余，考虑是否删除该成员变量
    }

    ret = wcrypto_aead_setauthsize(priv_ctx->e_aead_ctx->wd_ctx, 16);
	if (ret) {
		US_WARN("wd set authsize fail!\n");
		goto ERR;
	}
    
	US_DEBUG("init success, ctx=%p", ctx);
#ifdef KAE_DEBUG_KEY_ENABLE
	dump_data("key", priv_ctx->key, priv_ctx->key_len);
	dump_data("iv", priv_ctx->iv, priv_ctx->iv_len);
#endif
	return OPENSSL_SUCCESS;
ERR:
	sec_aead_engine_cleanup(priv_ctx);
    //do soft?
	return OPENSSL_FAIL;
}

int wd_aead_do_crypto_impl(struct aead_priv_ctx *priv)
{
	int ret = -WD_EINVAL;
	int trycount = 0;
	
	if (unlikely(priv == NULL) || unlikely(priv->e_aead_ctx == NULL)) {
		US_ERR("do cipher priv or e_aead_ctx NULL!");
		return KAE_FAIL;
	}

	aead_engine_ctx_t *e_aead_ctx = priv->e_aead_ctx;

	// 输入参数
	e_aead_ctx->op_data.in_bytes = priv->aad_len + priv->data_len + priv->mac_len;
	e_aead_ctx->op_data.out_buf_bytes = OUTPUT_CACHE_SIZE;
	e_aead_ctx->op_data.iv_bytes = priv->iv_len;

again:
	ret = wcrypto_do_aead(e_aead_ctx->wd_ctx, &e_aead_ctx->op_data, NULL);
	if (ret != WD_SUCCESS) {
		if (ret == -WD_EBUSY && trycount <= 5) { // try 5 times
			US_WARN("do cipher busy, retry again!");
			trycount++;
			goto again;
		} else {
			US_ERR("do cipher failed! ret is %d.", ret);
			return KAE_FAIL;
		}
	}

	return KAE_SUCCESS;
}

// 当前支持同步，异步之后再说,只输出
int wd_aead_do_crypto_impl_async(struct aead_priv_ctx *priv, op_done_t *op_done)
{
	int ret = -WD_EINVAL;
	int cnt = 0;
	enum task_type type = ASYNC_TASK_AEAD;
	
	if (unlikely(priv == NULL) || unlikely(priv->e_aead_ctx == NULL)) {
		US_ERR("do cipher priv or e_aead_ctx NULL!");
		return KAE_FAIL;
	}

	aead_engine_ctx_t *e_aead_ctx = priv->e_aead_ctx;

	// 输入参数
	e_aead_ctx->op_data.in_bytes = priv->aad_len + priv->data_len + priv->mac_len;
	e_aead_ctx->op_data.out_buf_bytes = OUTPUT_CACHE_SIZE;
	e_aead_ctx->op_data.iv_bytes = priv->iv_len;

	do {
		if (cnt > MAX_SEND_TRY_CNTS)
			break;

		ret = wcrypto_do_aead(e_aead_ctx->wd_ctx, &e_aead_ctx->op_data, e_aead_ctx);
		if (ret == -WD_EBUSY) {
			if ((async_wake_job_v1(op_done->job, ASYNC_STATUS_EAGAIN) == 0 ||
						async_pause_job_v1(op_done->job, ASYNC_STATUS_EAGAIN) == 0)) {
				US_ERR("sec wake job or sec pause job fail!\n");
				ret = 0;
				break;
			}
			cnt++;
		}
	} while (ret == -WD_EBUSY);

	if (ret != WD_SUCCESS) {
		US_ERR("sec async wcryto do cipher failed");
		return KAE_FAIL;
	}

	if (async_add_poll_task_v1(e_aead_ctx, op_done, type) == 0) {
		US_ERR("sec add task failed ");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;

}

// 获取add头信息
static int sec_aes_do_aes_gcm_first(struct aead_priv_ctx *priv, unsigned char *out,
				   const unsigned char *in, size_t inlen)
{
	memcpy(priv->data_buf, in, inlen);
	priv->aad_len = inlen;

	return 1;
}

static int do_aes_aead(EVP_CIPHER_CTX *ctx, struct aead_priv_ctx *priv,
				    unsigned char *out, const unsigned char *in, size_t inlen, op_done_t *op_done)
{
	unsigned char *ctx_buf = EVP_CIPHER_CTX_buf_noconst(ctx);
	int enc;

	// 得预处理，把输出的数据按uadk要求准备
	memcpy(priv->data_buf + priv->aad_len, in, inlen);
	priv->data_len = inlen;
	enc = EVP_CIPHER_CTX_encrypting(ctx);
	priv->e_aead_ctx->op_data.out_bytes = priv->aad_len + priv->data_len + priv->mac_len;
	if (!enc) {
		memcpy(priv->data_buf + priv->aad_len + priv->data_len, ctx_buf, AES_GCM_TAG_LEN);
		priv->mac_len = AES_GCM_TAG_LEN;
		priv->e_aead_ctx->op_data.out_bytes = priv->aad_len + priv->data_len;
	}

	//给硬件计算数据
	if (op_done) {
		// async
		wd_aead_do_crypto_impl_async(priv, op_done);
	} else {
		// sync
		wd_aead_do_crypto_impl(priv);
	}

	memcpy(out, priv->out_data_buf + priv->aad_len, inlen);

	if (enc) {
		memcpy(priv->mac, priv->out_data_buf + priv->aad_len + priv->data_len, AES_GCM_TAG_LEN);
		priv->mac_len = AES_GCM_TAG_LEN;
	}

	return inlen; // 成功就返回out数据长度
}

static int sec_aes_do_aes_gcm_update(EVP_CIPHER_CTX *ctx, struct aead_priv_ctx *priv,
				    unsigned char *out, const unsigned char *in, size_t inlen)
{
	// add async parm
	int job_ret;
	op_done_t op_done;

	// async
	async_init_op_done_v1(&op_done);

	if (op_done.job != NULL && kae_is_async_enabled()) {
		if (async_setup_async_event_notification_v1(0) == 0) {
			US_ERR("sec async event notifying failed");
			async_cleanup_op_done_v1(&op_done);
			return KAE_FAIL;
		}
	} else {
		US_DEBUG("NO ASYNC Job or async disable, back to SYNC!");
		async_cleanup_op_done_v1(&op_done);
		return do_aes_aead(ctx, priv, out, in, inlen, NULL); //sync
	}

	// async
	if (do_aes_aead(ctx, priv, out, in, inlen, &op_done) == KAE_FAIL) 
		goto err;
	
	do {
		job_ret = async_pause_job_v1(op_done.job, ASYNC_STATUS_OK);
		if ((job_ret == 0)) {
			US_DEBUG("- pthread_yidle -");
			kae_pthread_yield();
		}
	} while (!op_done.flag || ASYNC_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

	if (op_done.verifyRst < 0) {
		US_ERR("verify result failed with %d", op_done.verifyRst);
		async_cleanup_op_done_v1(&op_done);
		return KAE_FAIL;
	}

	async_cleanup_op_done_v1(&op_done);

	US_DEBUG(" Cipher Async Job Finish! priv_ctx = %p\n", priv);
	return 1;
err:
	US_ERR("async job err");
	(void)async_clear_async_event_notification_v1();
	async_cleanup_op_done_v1(&op_done);
	return KAE_FAIL;
}

static int sec_aes_do_aes_gcm_final(EVP_CIPHER_CTX *ctx, struct aead_priv_ctx *priv,
				   unsigned char *out, const unsigned char *in, size_t inlen)
{
	unsigned char *ctx_buf = EVP_CIPHER_CTX_buf_noconst(ctx);
	int enc;

	enc = EVP_CIPHER_CTX_encrypting(ctx);
	if (enc)
		memcpy(ctx_buf, priv->mac, priv->mac_len);

	return 0;
}

static int sec_aes_do_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *out,
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
			return sec_aes_do_aes_gcm_first(priv, out, in, inlen);
		return sec_aes_do_aes_gcm_update(ctx, priv, out, in, inlen);
	}
	return sec_aes_do_aes_gcm_final(ctx, priv, out, NULL, 0);
}

static int sec_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct aead_priv_ctx *priv;

	priv = (struct aead_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (!priv) {
		fprintf(stderr, "invalid: aead priv ctx is NULL.\n");
		return 0;
	}

	sec_aead_engine_cleanup(priv);

	return 1;
}

static int sec_aes_gcm_set_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
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
		priv->e_aead_ctx->op_data.iv_bytes = 0;
		return 1;
# if (OPENSSL_VERSION_NUMBER >= 0x1010106fL)
	case EVP_CTRL_GET_IVLEN:
		*(int *)ptr = priv->e_aead_ctx->op_data.iv_bytes;
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
		priv->mac_len = arg;
		return 1;
	default:
		fprintf(stderr, "unsupported ctrl type: %d\n", type);
		return 0;
	}
}

#define SEC_CIPHERS_AEAD_DESCR(name, block_size, key_size, iv_len, flags, ctx_size,	\
			init, cipher, cleanup, set_params, get_params, ctrl)	\
do {\
	sec_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);	\
	if (sec_##name == 0 ||							\
	    !EVP_CIPHER_meth_set_iv_length(sec_##name, iv_len) ||		\
	    !EVP_CIPHER_meth_set_flags(sec_##name, flags) ||			\
	    !EVP_CIPHER_meth_set_impl_ctx_size(sec_##name, ctx_size) ||	\
	    !EVP_CIPHER_meth_set_init(sec_##name, init) ||			\
	    !EVP_CIPHER_meth_set_do_cipher(sec_##name, cipher) ||		\
	    !EVP_CIPHER_meth_set_cleanup(sec_##name, cleanup) ||		\
	    !EVP_CIPHER_meth_set_set_asn1_params(sec_##name, set_params) ||	\
	    !EVP_CIPHER_meth_set_get_asn1_params(sec_##name, get_params) ||	\
	    !EVP_CIPHER_meth_set_ctrl(sec_##name, ctrl))			\
		return 0;\
} while (0)

EVP_CIPHER *sec_ciphers_set_gcm_method(int nid)
{
	EVP_CIPHER *aead = NULL;

	switch (nid) {
	case NID_aes_128_gcm:
		SEC_CIPHERS_AEAD_DESCR(aes_128_gcm, SEC_AES_GCM_BLOCK_SIZE, 16, SEC_AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx),
				sec_aes_gcm_init, sec_aes_do_aes_gcm, sec_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				sec_aes_gcm_set_ctrl);
		aead = sec_aes_128_gcm;
		break;
	case NID_aes_192_gcm:
		SEC_CIPHERS_AEAD_DESCR(aes_192_gcm, SEC_AES_GCM_BLOCK_SIZE, 24, SEC_AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx),
				sec_aes_gcm_init, sec_aes_do_aes_gcm, sec_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				sec_aes_gcm_set_ctrl);
		aead = sec_aes_192_gcm;
		break;
	case NID_aes_256_gcm:
		SEC_CIPHERS_AEAD_DESCR(aes_256_gcm, SEC_AES_GCM_BLOCK_SIZE, 32, SEC_AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx),
				sec_aes_gcm_init, sec_aes_do_aes_gcm, sec_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				sec_aes_gcm_set_ctrl);
		aead = sec_aes_256_gcm;
		break;
	default:
		aead = NULL;
		break;
	}

	return aead;
}

// async poll thread create
int sec_aead_engine_ctx_poll(void *engnine_ctx)
{
	int ret = 0;
	struct aead_engine_ctx *eng_ctx = (struct aead_engine_ctx *)engnine_ctx;
	struct wd_queue *q = eng_ctx->q_node->kae_wd_queue;

POLL_AGAIN:
	ret = wcrypto_aead_poll(q, 1);
	if (!ret) {
		goto POLL_AGAIN;
	} else if (ret < 0) {
		US_ERR("cipher poll failed\n");
		return ret;
	}
	return ret;
}

KAE_QUEUE_POOL_HEAD_S *wd_aead_get_qnode_pool(void)
{
	return g_sec_aeads_qnode_pool;
}

int wd_aead_init_qnode_pool(void)
{
	kae_queue_pool_destroy(g_sec_aeads_qnode_pool, wd_aead_free_engine_ctx);

	g_sec_aeads_qnode_pool = kae_init_queue_pool(WCRYPTO_AEAD);
	if (g_sec_aeads_qnode_pool == NULL) {
		US_ERR("do cipher ctx NULL!");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;
}

void wd_aead_uninit_qnode_pool(void)
{
	kae_queue_pool_destroy(g_sec_aeads_qnode_pool, wd_aead_free_engine_ctx);
	g_sec_aeads_qnode_pool = NULL;
}