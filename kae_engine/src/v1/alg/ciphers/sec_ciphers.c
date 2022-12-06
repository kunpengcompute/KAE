/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:    This file provides the implementation for KAE engine ciphers
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

/*****************************************************************************
 * @file sec_ciphers.c
 *
 * This file provides the implementation for ciphers
 *
*****************************************************************************/
#include "sec_ciphers.h"
#include "sec_ciphers_soft.h"
#include "sec_ciphers_utils.h"
#include "sec_ciphers_wd.h"

#include "../../utils/engine_check.h"
#include "../../utils/engine_types.h"
#include "../../utils/engine_log.h"
#include "../../utils/engine_utils.h"
#include "../../async/async_callback.h"
#include "../../async/async_event.h"
#include "../../async/async_task_queue.h"

#define INPUT_CACHE_SIZE (256 * 1024)

struct cipher_info {
	int nid;
	int blocksize;
	int keylen;
	int ivlen;
	int flags;
	int is_enabled;
	EVP_CIPHER *cipher;
};
typedef struct cipher_info cipher_info_t;

static cipher_info_t g_sec_ciphers_info[] = {
	{NID_aes_128_ecb, 16, 16, 0, EVP_CIPH_ECB_MODE, 1, NULL},
	{NID_aes_192_ecb, 16, 24, 0, EVP_CIPH_ECB_MODE, 1, NULL},
	{NID_aes_256_ecb, 16, 32, 0, EVP_CIPH_ECB_MODE, 1, NULL},
	{NID_aes_128_cbc, 16, 16, 16, EVP_CIPH_CBC_MODE, 1, NULL},
	{NID_aes_192_cbc, 16, 24, 16, EVP_CIPH_CBC_MODE, 1, NULL},
	{NID_aes_256_cbc, 16, 32, 16, EVP_CIPH_CBC_MODE, 1, NULL},
	{NID_aes_128_ctr, 1, 16, 16, EVP_CIPH_CTR_MODE, 1, NULL},
	{NID_aes_192_ctr, 1, 24, 16, EVP_CIPH_CTR_MODE, 1, NULL},
	{NID_aes_256_ctr, 1, 32, 16, EVP_CIPH_CTR_MODE, 1, NULL},
	{NID_aes_128_xts, 1, 32, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV, 1, NULL},
	{NID_aes_256_xts, 1, 64, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV, 1, NULL},

	{NID_sm4_ctr, 1, 16, 16, EVP_CIPH_CTR_MODE, 1, NULL},
	{NID_sm4_cbc, 16, 16, 16, EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1, 1, NULL},
	{NID_sm4_ofb128, 1, 16, 16, EVP_CIPH_OFB_MODE, 1, NULL},
	{NID_sm4_ecb, 16, 16, 0, EVP_CIPH_CTR_MODE, 1, NULL},
};

#define CIPHERS_COUNT (BLOCKSIZES_OF(g_sec_ciphers_info))

static int g_known_cipher_nids[CIPHERS_COUNT] = {
	NID_aes_128_ecb,
	NID_aes_192_ecb,
	NID_aes_256_ecb,
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_aes_128_xts,
	NID_aes_256_xts,

	NID_sm4_ctr,
	NID_sm4_cbc,
	NID_sm4_ofb128,
	NID_sm4_ecb,
};

#define SEC_CIPHERS_RETURN_FAIL_IF(cond, mesg, ret) \
	do { \
		if (unlikely(cond)) { \
			US_ERR(mesg); \
				return (ret); \
		} \
	} while (0)

#define SEC_CIPHERS_GOTO_FAIL_IF(cond, mesg, tag) \
	do { \
		if (unlikely(cond)) { \
			US_ERR(mesg); \
				goto tag; \
		} \
	} while (0)

static int sec_ciphers_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int encrypt);
static int sec_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
static int sec_ciphers_cleanup(EVP_CIPHER_CTX *ctx);
static int sec_ciphers_priv_ctx_cleanup(EVP_CIPHER_CTX *ctx);
static int sec_ciphers_is_check_valid(EVP_CIPHER_CTX *ctx, cipher_priv_ctx_t *priv_ctx);
static int sec_ciphers_async_do_crypto(cipher_engine_ctx_t *e_cipher_ctx, op_done_t *op_done);

void sec_ciphers_set_enabled(int nid, int enabled)
{
	unsigned int i = 0;

	for (i = 0; i < CIPHERS_COUNT; i++) {
		if (g_sec_ciphers_info[i].nid == nid)
			g_sec_ciphers_info[i].is_enabled = enabled;
	}
}

static int sec_ciphers_sync_do_crypto(EVP_CIPHER_CTX *ctx, cipher_engine_ctx_t *e_cipher_ctx,
		cipher_priv_ctx_t *priv_ctx);

static int sec_ciphers_init_priv_ctx(cipher_priv_ctx_t *priv_ctx, EVP_CIPHER_CTX *ctx,
		const unsigned char *key, const unsigned char *iv)
{
	int nid = 0;
	int ret = KAE_FAIL;

	SEC_CIPHERS_RETURN_FAIL_IF(ctx == NULL || priv_ctx == NULL, "null ctx or priv ctx", KAE_FAIL);

	// init encrypt of private ctx
	priv_ctx->encrypt = EVP_CIPHER_CTX_encrypting(ctx);
	// init offset of private ctx
	priv_ctx->offset = 0;
	// init key of private ctx
	if (priv_ctx->key == NULL) {
		priv_ctx->key = (uint8_t *)kae_malloc(EVP_CIPHER_CTX_key_length(ctx));
		SEC_CIPHERS_GOTO_FAIL_IF(priv_ctx->key == NULL, "malloc key failed", ERR);
	}

	kae_memcpy(priv_ctx->key, key, EVP_CIPHER_CTX_key_length(ctx));
	priv_ctx->key_len = EVP_CIPHER_CTX_key_length(ctx);

	// init iv of private ctx
	if (priv_ctx->iv == NULL) {
		priv_ctx->iv = (uint8_t *)kae_malloc(EVP_CIPHER_CTX_iv_length(ctx));
		SEC_CIPHERS_GOTO_FAIL_IF(priv_ctx->iv == NULL, "malloc iv failed.", ERR);
	}
	if (iv != NULL)
		kae_memcpy(priv_ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
	else
		kae_memcpy(priv_ctx->iv, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_iv_length(ctx));

	priv_ctx->iv_len = EVP_CIPHER_CTX_iv_length(ctx);

	if (priv_ctx->next_iv == NULL) {
		priv_ctx->next_iv = (uint8_t *)kae_malloc(priv_ctx->iv_len);
		SEC_CIPHERS_GOTO_FAIL_IF(priv_ctx->next_iv == NULL, "malloc next iv failed.", ERR);
	}

	// init cipher mode and alg of private ctx
	nid = EVP_CIPHER_CTX_nid(ctx);
	priv_ctx->c_mode = sec_ciphers_get_cipher_mode(nid);
	priv_ctx->c_alg = sec_ciphers_get_cipher_alg(nid);
	SEC_CIPHERS_GOTO_FAIL_IF(priv_ctx->c_mode == NO_C_MODE || priv_ctx->c_alg == NO_C_ALG,
			"unsupport the cipher nid", ERR);

	if (priv_ctx->ecb_encryto == NULL && priv_ctx->c_mode == XTS) {
		// set XTS PARAM
		priv_ctx->ecb_encryto = (xts_ecb_data *)kae_malloc(sizeof(xts_ecb_data));
		SEC_CIPHERS_GOTO_FAIL_IF(priv_ctx->ecb_encryto == NULL, "malloc ecb ctx", ERR);

		priv_ctx->ecb_encryto->ecb_ctx = EVP_CIPHER_CTX_new();
		priv_ctx->ecb_encryto->key2_len = priv_ctx->key_len >> 1;
		priv_ctx->ecb_encryto->key2 = (uint8_t *)kae_malloc(priv_ctx->key_len >> 1);
		priv_ctx->ecb_encryto->encryto_iv = (uint8_t *)kae_malloc(priv_ctx->iv_len);
		priv_ctx->ecb_encryto->iv_out = (uint8_t *)kae_malloc(priv_ctx->iv_len);
		if (priv_ctx->ecb_encryto->ecb_ctx == NULL
				|| priv_ctx->ecb_encryto->key2 == NULL
				|| priv_ctx->ecb_encryto->encryto_iv == NULL
				|| priv_ctx->ecb_encryto->iv_out == NULL) {
			if (priv_ctx->ecb_encryto->ecb_ctx != NULL) {
				EVP_CIPHER_CTX_free(priv_ctx->ecb_encryto->ecb_ctx);
				priv_ctx->ecb_encryto->ecb_ctx = NULL;
			}

			kae_free(priv_ctx->ecb_encryto->key2);
			kae_free(priv_ctx->ecb_encryto->encryto_iv);
			kae_free(priv_ctx->ecb_encryto->iv_out);
			kae_free(priv_ctx->ecb_encryto);
			goto ERR;
		}

		if (priv_ctx->ecb_encryto->key2_len == 32) { // 256-xts key2len is 32
			priv_ctx->ecb_encryto->cipher_type = EVP_aes_256_ecb();
		} else {
			priv_ctx->ecb_encryto->cipher_type = EVP_aes_128_ecb();
		}
		priv_ctx->ecb_encryto->countNum = 0;
		kae_memcpy(priv_ctx->ecb_encryto->key2,
				priv_ctx->key + priv_ctx->ecb_encryto->key2_len,
				priv_ctx->ecb_encryto->key2_len);
	}

#ifndef OPENSSL_ENABLE_KAE_SMALL_PACKKET_CIPHER_OFFLOADS
	ret = sec_ciphers_sw_impl_init(ctx, key, iv, priv_ctx->encrypt);
	SEC_CIPHERS_GOTO_FAIL_IF(ret != KAE_SUCCESS, "kae sw iml init failed", ERR);

	priv_ctx->switch_threshold =
		(size_t)sec_ciphers_sw_get_threshold(EVP_CIPHER_CTX_nid(ctx));
#endif

	return KAE_SUCCESS;

ERR:
	US_ERR("sec_ciphers_sec_state_init failed. ctx=%p", ctx);
	(void)sec_ciphers_priv_ctx_cleanup(ctx);
	return KAE_FAIL;
}

static int sec_ciphers_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int encrypt)
{
	cipher_priv_ctx_t *priv_ctx = NULL;

	if (unlikely((ctx == NULL) || (key == NULL))) {
		US_ERR("ctx or key is NULL.");
		return OPENSSL_FAIL;
	}

	if (encrypt != EVP_CIPHER_CTX_encrypting(ctx)) {
		US_ERR("encrypt different, ctx=%p", ctx);
		return OPENSSL_FAIL;
	}

	priv_ctx = (cipher_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (unlikely(priv_ctx == NULL)) {
		US_ERR("sec private ctx is NULL");
		return OPENSSL_FAIL;
	}

	if (sec_ciphers_init_priv_ctx(priv_ctx, ctx, key, iv) != KAE_SUCCESS) {
		US_ERR("init failed. ctx=%p", ctx);
		goto ERR;
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

static void sec_ciphers_update_priv_ctx(cipher_priv_ctx_t *priv_ctx)
{
	uint32_t do_cipher_len = priv_ctx->do_cipher_len;
	uint32_t increase_counter = 0;

	if (do_cipher_len == 0)
		return;

	priv_ctx->in += priv_ctx->do_cipher_len;
	priv_ctx->out += priv_ctx->do_cipher_len;
	priv_ctx->left_len -= priv_ctx->do_cipher_len;

	switch (priv_ctx->c_mode) {
	case ECB:
		break;
	case CBC:
		if (priv_ctx->encrypt == OPENSSL_ENCRYPTION)
			kae_memcpy(priv_ctx->iv, priv_ctx->out - 16, 16);  // hardware need 16-byte alignment
		else
			kae_memcpy(priv_ctx->iv, priv_ctx->next_iv, 16);  // hardware need 16-byte alignment
		break;
	case CTR:
		increase_counter = (do_cipher_len + priv_ctx->offset) >> 4; // right shift 4
		sec_ciphers_ctr_iv_inc(priv_ctx->iv, increase_counter);
		priv_ctx->offset = (priv_ctx->offset + (do_cipher_len & 0xf)) % 16; // hardware need 16-byte alignment
		break;
	case XTS:
		if (priv_ctx->c_alg == AES) {
			priv_ctx->ecb_encryto->countNum = (priv_ctx->do_cipher_len + priv_ctx->offset) >> 4; // right shift 4
			sec_ciphers_xts_iv_inc(priv_ctx);
			priv_ctx->offset = (priv_ctx->offset + (do_cipher_len & 0xf)) % 16; // hardware need 16-byte alignment
		}
		break;
	case OFB:
		kae_memcpy(priv_ctx->iv, (uint8_t *)priv_ctx->e_cipher_ctx->op_data.iv,
				priv_ctx->e_cipher_ctx->op_data.iv_bytes);
		break;
	default:
		US_WARN("mode=%d don't support.", priv_ctx->c_mode);
		break;
	}

	US_DEBUG("update priv_ctx success.");
}

static int sec_ciphers_before_dociphers_cb(cipher_priv_ctx_t *priv_ctx)
{
	// store IV for next cbc decryption operation
	if (priv_ctx->encrypt == OPENSSL_DECRYPTION && priv_ctx->c_mode == CBC)
		kae_memcpy(priv_ctx->next_iv, priv_ctx->in + priv_ctx->do_cipher_len - priv_ctx->iv_len, priv_ctx->iv_len);

	if (priv_ctx->c_mode == XTS && priv_ctx->c_alg == AES) {
		sec_ciphers_ecb_encryt(priv_ctx->ecb_encryto,
				priv_ctx->ecb_encryto->encryto_iv,
				priv_ctx->iv, priv_ctx->iv_len);
	}

	return KAE_SUCCESS;
}

static int sec_ciphers_after_dociphers_cb(EVP_CIPHER_CTX *ctx)
{
	// sync priv ctx to next cipher, in case next cipher may be soft cipher
	return sec_ciphers_sw_hw_ctx_sync(ctx, SEC_CIHPER_SYNC_H2S);
}

/*
 * |<--16*n bytes--> |<----16*n bytes------->|<--16*n bytes--->|
 * |-----------------|<--offset----->|<----->|-----------------|
 * |<--first cipher----------------->|<---next cipher--------->|
 *
 *
 * to make 16*n align to next cipher data copy to hardware addr should start at
 * hardware_addr+offset and get out put at hardware_addr+offset
 *
 * |<----16*n bytes------>|<--16*n bytes--->|
 * |<--offset----->|------------------------+
 *             hardware_addr         |<---next cipher-------->|
 *
 */
static int sec_ciphers_do_crypto(EVP_CIPHER_CTX *ctx, cipher_priv_ctx_t *priv_ctx)
{
	int ret = KAE_FAIL;

	// add async parm
	int job_ret;
	op_done_t op_done;

	SEC_CIPHERS_RETURN_FAIL_IF(priv_ctx == NULL, "priv_ctx is NULL.", KAE_FAIL);
	cipher_engine_ctx_t *e_cipher_ctx = priv_ctx->e_cipher_ctx;

	SEC_CIPHERS_RETURN_FAIL_IF(e_cipher_ctx == NULL, "e_cipher_ctx is NULL", KAE_FAIL);

	SEC_CIPHERS_RETURN_FAIL_IF(priv_ctx->inl <= 0, "in length less than or equal to zero.", KAE_FAIL);
	// packageSize>input_cache_size
	if (priv_ctx->left_len > INPUT_CACHE_SIZE - priv_ctx->offset) {
		ret = sec_ciphers_sync_do_crypto(ctx, e_cipher_ctx, priv_ctx);
		if (ret != 0) {
			US_ERR("sec sync crypto fail");
			return ret;
		}
		return KAE_SUCCESS;
	}

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
		return sec_ciphers_sync_do_crypto(ctx, e_cipher_ctx, priv_ctx);
	}

	if (sec_ciphers_async_do_crypto(e_cipher_ctx, &op_done) == KAE_FAIL)
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

	US_DEBUG(" Cipher Async Job Finish! priv_ctx = %p\n", priv_ctx);

	// after cipher cycle should update: in, out, iv, key, length.
	sec_ciphers_update_priv_ctx(priv_ctx);
	(void)sec_ciphers_after_dociphers_cb(ctx);

	return KAE_SUCCESS;
err:
	US_ERR("async job err");
	(void)async_clear_async_event_notification_v1();
	async_cleanup_op_done_v1(&op_done);
	return KAE_FAIL;
}

static int sec_ciphers_sync_do_crypto(EVP_CIPHER_CTX *ctx, cipher_engine_ctx_t *e_cipher_ctx,
		cipher_priv_ctx_t *priv_ctx)
{
	int ret = KAE_FAIL;
	int leftlen = priv_ctx->left_len;

	while (leftlen != 0) {
		priv_ctx->do_cipher_len = wd_ciphers_get_do_cipher_len(priv_ctx->offset, leftlen);

		(void)sec_ciphers_before_dociphers_cb(e_cipher_ctx->priv_ctx);

		wd_ciphers_set_input_data(e_cipher_ctx);

		ret = wd_ciphers_do_crypto_impl(e_cipher_ctx);
		if (ret != KAE_SUCCESS)
			return ret;

		wd_ciphers_get_output_data(e_cipher_ctx);

		// after cipher cycle should update: in, out, iv, key, length.
		sec_ciphers_update_priv_ctx(priv_ctx);

		(void)sec_ciphers_after_dociphers_cb(ctx);

		leftlen -= priv_ctx->do_cipher_len;
	}

	US_DEBUG("sec state update success.");

	return KAE_SUCCESS;
}

static int sec_ciphers_async_do_crypto(cipher_engine_ctx_t *e_cipher_ctx, op_done_t *op_done)
{
	int ret = 0;
	int cnt = 0;
	cipher_priv_ctx_t *priv_ctx = e_cipher_ctx->priv_ctx;
	enum task_type type = ASYNC_TASK_CIPHER;
	void *tag = e_cipher_ctx;

	priv_ctx->do_cipher_len = wd_ciphers_get_do_cipher_len(priv_ctx->offset, priv_ctx->left_len);

	(void)sec_ciphers_before_dociphers_cb(e_cipher_ctx->priv_ctx);

	wd_ciphers_set_input_data(e_cipher_ctx);

	do {
		if (cnt > MAX_SEND_TRY_CNTS)
			break;

		ret = wcrypto_do_cipher(e_cipher_ctx->wd_ctx, &e_cipher_ctx->op_data, tag);
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

	if (async_add_poll_task_v1(e_cipher_ctx, op_done, type) == 0) {
		US_ERR("sec add task failed ");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;
}

static int sec_ciphers_is_check_valid(EVP_CIPHER_CTX *ctx, cipher_priv_ctx_t *priv_ctx)
{
	if (priv_ctx->switch_threshold > (size_t)priv_ctx->inl) {
		US_WARN_LIMIT("small packet cipher offload, switch to soft cipher, inl %d", (int)priv_ctx->inl);
		return KAE_FAIL;
	}

	if (sec_ciphers_is_iv_may_overflow(ctx, priv_ctx)) {
		US_WARN("sec do cipher, the iv will overflow");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;
}

static int sec_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
	int ret = KAE_FAIL;
	int num = 0;
	cipher_priv_ctx_t *priv_ctx = NULL;

	SEC_CIPHERS_RETURN_FAIL_IF(ctx == NULL, "ctx is NULL", OPENSSL_FAIL);
	SEC_CIPHERS_RETURN_FAIL_IF(in == NULL, "in is NULL", OPENSSL_FAIL);
	SEC_CIPHERS_RETURN_FAIL_IF(out == NULL, "out is NULL", OPENSSL_FAIL);
	priv_ctx = (cipher_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	SEC_CIPHERS_RETURN_FAIL_IF(priv_ctx == NULL, "ctx cipher data is NULL.", OPENSSL_FAIL);
	priv_ctx->inl = inl;
	priv_ctx->in = in;
	priv_ctx->out = out;
	priv_ctx->left_len = inl;

	num = EVP_CIPHER_CTX_num(ctx);

	ret = sec_ciphers_is_check_valid(ctx, priv_ctx);
	if (ret != KAE_SUCCESS) {
		US_WARN_LIMIT("sec cipher check invalid, switch to soft cipher");
		goto do_soft_cipher;
	}

	if (priv_ctx->e_cipher_ctx == NULL) {
		priv_ctx->e_cipher_ctx = wd_ciphers_get_engine_ctx(priv_ctx);
		if (priv_ctx->e_cipher_ctx == NULL) {
			US_WARN("failed to get engine ctx, switch to soft cipher");
			goto do_soft_cipher;
		}
	}

	ret = sec_ciphers_do_crypto(ctx, priv_ctx);
	if (ret != KAE_SUCCESS) {
		US_WARN("sec cipher do ciphers failed, switch to soft cipher");
		goto do_soft_cipher;
	}

	US_DEBUG("do cipher success. ctx=%p, ctx->num=%d, inl=%d", ctx, num, (int)inl);

	return OPENSSL_SUCCESS;

do_soft_cipher:
	if (priv_ctx->e_cipher_ctx != NULL) {
		wd_ciphers_put_engine_ctx(priv_ctx->e_cipher_ctx);
		priv_ctx->e_cipher_ctx = NULL;
	}

	if (sec_ciphers_software_encrypt(ctx, priv_ctx) != KAE_SUCCESS) {
		US_WARN("sec cipher do soft ciphers failed");
		return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

static int sec_ciphers_priv_ctx_cleanup(EVP_CIPHER_CTX *ctx)
{
	cipher_priv_ctx_t *priv_ctx = NULL;

	priv_ctx = (cipher_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (unlikely(priv_ctx == NULL)) {
		US_WARN("ctx cipher data is NULL.");
		return KAE_FAIL;
	}

	kae_free(priv_ctx->iv);
	kae_free(priv_ctx->key);
	kae_free(priv_ctx->next_iv);
	if (priv_ctx->ecb_encryto) {
		if (priv_ctx->ecb_encryto->ecb_ctx != NULL) {
			EVP_CIPHER_CTX_free(priv_ctx->ecb_encryto->ecb_ctx);
			priv_ctx->ecb_encryto->ecb_ctx = NULL;
		}

		kae_free(priv_ctx->ecb_encryto->key2);
		kae_free(priv_ctx->ecb_encryto->encryto_iv);
		kae_free(priv_ctx->ecb_encryto->iv_out);
		kae_free(priv_ctx->ecb_encryto);
	}

	(void)wd_ciphers_put_engine_ctx(priv_ctx->e_cipher_ctx);
	priv_ctx->e_cipher_ctx = NULL;

	return KAE_SUCCESS;
}

static int sec_ciphers_cleanup(EVP_CIPHER_CTX *ctx)
{
	if (unlikely(ctx == NULL)) {
		US_WARN("ctx is NULL");
		return OPENSSL_FAIL;
	}

	int ret = sec_ciphers_sw_impl_cleanup(ctx);

	if (ret != KAE_SUCCESS)
		US_ERR("Cipher soft impl cleanup failed. ctx=%p", ctx);

	ret = sec_ciphers_priv_ctx_cleanup(ctx);
	if (ret != KAE_SUCCESS)
		return OPENSSL_FAIL;

	US_DEBUG("Cleanup success, ctx=%p", ctx);

	return OPENSSL_SUCCESS;
}

static EVP_CIPHER *sec_ciphers_set_cipher_method(cipher_info_t cipherinfo)
{
	EVP_CIPHER *cipher = EVP_CIPHER_meth_new(cipherinfo.nid, cipherinfo.blocksize, cipherinfo.keylen);
	int ret = 1;

	if (cipher == NULL)
		return NULL;

	ret &= EVP_CIPHER_meth_set_iv_length(cipher, cipherinfo.ivlen);
	ret &= EVP_CIPHER_meth_set_flags(cipher, cipherinfo.flags);
	ret &= EVP_CIPHER_meth_set_init(cipher, sec_ciphers_init);
	ret &= EVP_CIPHER_meth_set_do_cipher(cipher, sec_ciphers_do_cipher);
	ret &= EVP_CIPHER_meth_set_set_asn1_params(cipher, EVP_CIPHER_set_asn1_iv);
	ret &= EVP_CIPHER_meth_set_get_asn1_params(cipher, EVP_CIPHER_get_asn1_iv);
	ret &= EVP_CIPHER_meth_set_cleanup(cipher, sec_ciphers_cleanup);
	ret &= EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(cipher_priv_ctx_t));
	if (ret == 0) {
		US_WARN("Failed to set cipher methods for nid %d\n", cipherinfo.nid);
		return NULL;
	} else {
		return cipher;
	}
}

void sec_create_ciphers(void)
{
	unsigned int i = 0;

	for (i = 0; i < CIPHERS_COUNT; i++) {
		if (g_sec_ciphers_info[i].cipher == NULL)
			g_sec_ciphers_info[i].cipher = sec_ciphers_set_cipher_method(g_sec_ciphers_info[i]);
	}
}

static EVP_CIPHER *get_ciphers_default_method(int nid)
{
	EVP_CIPHER *cipher = NULL;

	switch (nid) {
	case NID_sm4_ctr:
		cipher = (EVP_CIPHER *)EVP_sm4_ctr();
		break;
	case NID_sm4_cbc:
		cipher = (EVP_CIPHER *)EVP_sm4_cbc();
		break;
	case NID_sm4_ofb128:
		cipher = (EVP_CIPHER *)EVP_sm4_ofb();
		break;
	case NID_sm4_ecb:
		cipher = (EVP_CIPHER *)EVP_sm4_ecb();
		break;
	default:
		US_WARN("nid = %d not support.", nid);
		break;
	}
	return cipher;
}

int sec_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	UNUSED(e);
	unsigned int i = 0;

	if (unlikely((nids == NULL) && ((cipher == NULL) || (nid < 0)))) {
		US_WARN("Invalid input param.");
		if (cipher != NULL)
			*cipher = NULL;
		return OPENSSL_FAIL;
	}

	/* No specific cipher => return a list of supported nids ... */
	if (cipher == NULL) {
		if (nids != NULL)
			*nids = g_known_cipher_nids;
		return BLOCKSIZES_OF(g_sec_ciphers_info);
	}

	for (i = 0; i < CIPHERS_COUNT; i++) {
		if (g_sec_ciphers_info[i].nid == nid) {
			if (g_sec_ciphers_info[i].cipher == NULL)
				sec_create_ciphers();
			/*SM4 is disabled*/
			*cipher = g_sec_ciphers_info[i].is_enabled ? g_sec_ciphers_info[i].cipher : get_ciphers_default_method(nid);
			return OPENSSL_SUCCESS;
		}
	}

	US_WARN("nid = %d not support.", nid);
	*cipher = NULL;

	return OPENSSL_FAIL;
}

void sec_ciphers_free_ciphers(void)
{
	unsigned int i = 0;

	for (i = 0; i < CIPHERS_COUNT; i++) {
		if (g_sec_ciphers_info[i].cipher != NULL) {
			EVP_CIPHER_meth_free(g_sec_ciphers_info[i].cipher);
			g_sec_ciphers_info[i].cipher = NULL;
		}
	}
}

void sec_ciphers_cb(const void *msg, void *tag)
{
	if (!msg || !tag) {
		US_ERR("sec cb params err!\n");
		return;
	}
	struct wcrypto_cipher_msg *message = (struct wcrypto_cipher_msg *)msg;
	cipher_engine_ctx_t *eng_ctx = (cipher_engine_ctx_t *)tag;

	kae_memcpy(eng_ctx->priv_ctx->out, message->out, message->out_bytes);
}

// async poll thread create
int sec_cipher_engine_ctx_poll(void *engnine_ctx)
{
	int ret = 0;
	struct cipher_engine_ctx *eng_ctx = (struct cipher_engine_ctx *)engnine_ctx;
	struct wd_queue *q = eng_ctx->q_node->kae_wd_queue;

POLL_AGAIN:
	ret = wcrypto_cipher_poll(q, 1);
	if (!ret) {
		goto POLL_AGAIN;
	} else if (ret < 0) {
		US_ERR("cipher poll failed\n");
		return ret;
	}
	return ret;
}

int cipher_module_init(void)
{
	wd_ciphers_init_qnode_pool();

	sec_create_ciphers();

	// reg async interface here
	async_register_poll_fn_v1(ASYNC_TASK_CIPHER, sec_cipher_engine_ctx_poll);

	return 1;
}
