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

void wd_aeads_free_engine_ctx(void *engine_ctx)
{
	if (e_aead_ctx == NULL)
		return;

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

	e_aead_ctx->priv_ctx = priv_ctx;
	e_aead_ctx->q_node = q_node;
	q_node->engine_ctx = e_aead_ctx;

	return e_aead_ctx;

err:
	(void)wd_aeads_free_engine_ctx(e_aead_ctx);

	return NULL;
}

void sec_aead_cb(const void *msg, void *tag)
{
	if (!msg || !tag) {
		US_ERR("sec cb params err!\n");
		return;
	}
	struct wcrypto_aead_msg *message = (struct wcrypto_aead_msg *)msg;
	aead_engine_ctx_t *eng_ctx = (aead_engine_ctx_t *)tag;

	kae_memcpy(eng_ctx->priv_ctx->out, message->out, message->out_bytes);
}

static int wd_aeads_init_engine_ctx(aead_engine_ctx_t *e_aead_ctx)
{
	struct wd_queue *q = e_aead_ctx->q_node->kae_wd_queue;
	aead_priv_ctx_t *priv_ctx = e_aead_ctx->priv_ctx;

	if (e_aead_ctx->wd_ctx != NULL) {
		US_WARN("wd ctx is in used by other aeads");

		return KAE_FAIL;
	}

    e_aead_ctx->setup.br.alloc = kae_wd_alloc_blk;
	e_aead_ctx->setup.br.free = kae_wd_free_blk;
	e_aead_ctx->setup.br.iova_map = kae_dma_map;
	e_aead_ctx->setup.br.iova_unmap = kae_dma_unmap;
	e_aead_ctx->setup.br.usr = q_node->kae_queue_mem_pool;

	e_aead_ctx->setup.alg  = (enum wcrypto_cipher_alg)priv_ctx->c_alg;    // for example: WD_aead_SM4;
	e_aead_ctx->setup.mode = (enum wcrypto_cipher_mode)priv_ctx->c_mode;  // for example: WD_aead_CBC;
	e_aead_ctx->setup.cb = (wcrypto_cb)sec_aead_cb; // 异步使用
	e_aead_ctx->wd_ctx = wcrypto_create_aead_ctx(q, &e_aead_ctx->setup);

	if (e_aead_ctx->wd_ctx == NULL) {
		US_ERR("wd create sec aead ctx fail!");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;
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
		US_ERR_LIMIT("failed to get hardware queue");
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


static int sec_aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *ckey,
			       const unsigned char *iv, int encrypt)
{
    int nid = 0;
    int ret, ckey_len;
	aead_priv_ctx_t *priv_ctx = NULL;

	if (unlikely((ctx == NULL) || (key == NULL))) {
		US_ERR("ctx or key is NULL.");
		return OPENSSL_FAIL;
	}

	if (encrypt != EVP_CIPHER_CTX_encrypting(ctx)) {
		US_ERR("encrypt different, ctx=%p", ctx);
		return OPENSSL_FAIL;
	}

    priv_ctx = (aeadr_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (unlikely(priv_ctx == NULL)) {
		US_ERR("sec private ctx is NULL");
		return OPENSSL_FAIL;
	}

    // init cipher mode and alg of private ctx
	nid = EVP_CIPHER_CTX_nid(ctx);
	priv_ctx->c_mode = sec_ciphers_get_cipher_mode(nid);
	priv_ctx->c_alg = sec_ciphers_get_cipher_alg(nid);

    //iv
    if (iv)
		memcpy(priv->iv, iv, 12);//AES_GCM_IV_LEN

    // engine_ctx
    if (priv_ctx->e_aead_ctx == NULL) {
		priv_ctx->e_aead_ctx = wd_aead_get_engine_ctx(priv_ctx);
		if (priv_ctx->e_aead_ctx == NULL) {
			US_WARN("failed to get engine ctx, switch to soft cipher");
			goto do_soft_cipher;
		}
	}

    //encrypt ==> optype
    if (encrypt)
		priv_ctx->e_aead_ctx->op_data.op_type = WD_CIPHER_ENCRYPTION_DIGEST; // aad + plen + authsize;
	else
		priv_ctx->e_aead_ctx->op_data.op_type = WD_CIPHER_DECRYPTION_DIGEST; // aad + plen;

    // opdata的基本参数设置
	priv_ctx->e_aead_ctx->op_data.in = priv_ctx->in;
	priv_ctx->e_aead_ctx->op_data.out = priv_ctx->out;
	priv_ctx->e_aead_ctx->op_data.iv = priv_ctx->iv[0];
    priv_ctx->e_aead_ctx->op_data.assoc_size = 16

    // ckey akey
    if (ckey) {
        ckey_len = EVP_CIPHER_CTX_key_length(ctx);
        wcrypto_set_aead_ckey(priv_ctx->e_aead_ctx->wd_ctx, ckey, ckey_len);
        priv_ctx->key = ckey; //感觉多余，考虑是否删除该成员变量
        priv_ctx->key_len = ckey_len;  //感觉多余，考虑是否删除该成员变量
    }

    ret = wcrypto_aead_setauthsize(priv_ctx->e_aead_ctx->wd_ctx, 16);
	if (ret) {
		US_WARN("wd set authsize fail!\n");
		wcrypto_del_aead_ctx(priv_ctx->e_aead_ctx->wd_ctx);
		goto do_soft_cipher;
	}
    
	US_DEBUG("init success, ctx=%p", ctx);
#ifdef KAE_DEBUG_KEY_ENABLE
	dump_data("key", priv_ctx->key, priv_ctx->key_len);
	dump_data("iv", priv_ctx->iv, priv_ctx->iv_len);
#endif
	return OPENSSL_SUCCESS;
ERR:
	sec_ciphers_cleanup(ctx);
	return OPENSSL_SUCCESS;
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
				GCM_FLAG, sizeof(struct aead_priv_ctx_t),
				sec_aes_gcm_init, uadk_e_do_aes_gcm,	uadk_e_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				uadk_e_aes_gcm_set_ctrl);
		aead = sec_aes_128_gcm;
		break;
	case NID_aes_192_gcm:
		SEC_CIPHERS_AEAD_DESCR(aes_192_gcm, SEC_AES_GCM_BLOCK_SIZE, 24, SEC_AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx_t),
				sec_aes_gcm_init, uadk_e_do_aes_gcm,	uadk_e_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				uadk_e_aes_gcm_set_ctrl);
		aead = sec_aes_192_gcm;
		break;
	case NID_aes_256_gcm:
		SEC_CIPHERS_AEAD_DESCR(aes_256_gcm, SEC_AES_GCM_BLOCK_SIZE, 32, SEC_AES_GCM_IV_LEN,
				GCM_FLAG, sizeof(struct aead_priv_ctx_t),
				sec_aes_gcm_init, uadk_e_do_aes_gcm, uadk_e_aes_gcm_cleanup,
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
				(EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
				uadk_e_aes_gcm_set_ctrl);
		aead = sec_aes_256_gcm;
		break;
	default:
		aead = NULL;
		break;
	}

	return aead;
}