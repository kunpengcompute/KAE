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
#include "sec_ciphers_aead.h"

#include "../../async/async_callback.h"
#include "../../async/async_event.h"
#include "../../async/async_task_queue.h"
#include "../../async/async_check.h"
#include "../../../common/kae_utils.h"
#include "../../../common/kae_types.h"
#include "../../../common/kae_log.h"

#define SEC_CIPHERS_RETURN_FAIL_IF(cond, mesg, ret) \
    do {                                            \
        if (unlikely(cond)) {                       \
            US_ERR(mesg);                           \
            return (ret);                           \
        }                                           \
    } while (0)

#define SEC_CIPHERS_GOTO_FAIL_IF(cond, mesg, tag) \
    do {                                          \
        if (unlikely(cond)) {                     \
            US_ERR(mesg);                         \
            goto tag;                             \
        }                                         \
    } while (0)

int sec_ciphers_init_priv_ctx(
    cipher_priv_ctx *priv_ctx, const unsigned char *key, size_t key_len, const unsigned char *iv, size_t iv_len)
{
    SEC_CIPHERS_RETURN_FAIL_IF(priv_ctx == NULL, "null ctx or priv ctx", KAE_FAIL);

    priv_ctx->offset = 0;

    if (key) {
        kae_memcpy(priv_ctx->key, key, key_len);
        priv_ctx->key_len = key_len;
    }

    if (iv) {
        kae_memcpy(priv_ctx->iv, iv, iv_len);
        priv_ctx->iv_len = iv_len;
    }
    // else
    // 	kae_memcpy(priv_ctx->iv, EVP_CIPHER_CTX_iv_noconst(ctx), iv_len); // todo ensure

    if (priv_ctx->next_iv == NULL) {
        priv_ctx->next_iv = (uint8_t *)kae_malloc(priv_ctx->iv_len);
        SEC_CIPHERS_GOTO_FAIL_IF(priv_ctx->next_iv == NULL, "malloc next iv failed.", ERR);
    }

    priv_ctx->c_mode = sec_ciphers_get_cipher_mode(priv_ctx->nid);
    priv_ctx->c_alg = sec_ciphers_get_cipher_alg(priv_ctx->nid);
    SEC_CIPHERS_GOTO_FAIL_IF(
        priv_ctx->c_mode == NO_C_MODE || priv_ctx->c_alg == NO_C_ALG, "unsupport the cipher nid", ERR);

    if (priv_ctx->ecb_encryto == NULL && priv_ctx->c_mode == XTS) {
        priv_ctx->ecb_encryto = (xts_ecb_data *)kae_malloc(sizeof(xts_ecb_data));
        SEC_CIPHERS_GOTO_FAIL_IF(priv_ctx->ecb_encryto == NULL, "malloc ecb ctx", ERR);

        priv_ctx->ecb_encryto->ecb_ctx = EVP_CIPHER_CTX_new();
        priv_ctx->ecb_encryto->key2_len = priv_ctx->key_len >> 1;
        priv_ctx->ecb_encryto->key2 = (uint8_t *)kae_malloc(priv_ctx->key_len >> 1);
        priv_ctx->ecb_encryto->encryto_iv = (uint8_t *)kae_malloc(priv_ctx->iv_len);
        priv_ctx->ecb_encryto->iv_out = (uint8_t *)kae_malloc(priv_ctx->iv_len);
        if (priv_ctx->ecb_encryto->ecb_ctx == NULL || priv_ctx->ecb_encryto->key2 == NULL ||
            priv_ctx->ecb_encryto->encryto_iv == NULL || priv_ctx->ecb_encryto->iv_out == NULL) {
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

        if (priv_ctx->ecb_encryto->key2_len == 32) {  // 256-xts key2len is 32
            priv_ctx->ecb_encryto->cipher_type = EVP_aes_256_ecb();
        } else {
            priv_ctx->ecb_encryto->cipher_type = EVP_aes_128_ecb();
        }
        priv_ctx->ecb_encryto->countNum = 0;
        kae_memcpy(priv_ctx->ecb_encryto->key2,
            priv_ctx->key + priv_ctx->ecb_encryto->key2_len,
            priv_ctx->ecb_encryto->key2_len);
    }

    priv_ctx->switch_threshold = (size_t)sec_ciphers_sw_get_threshold(priv_ctx->nid);

    return OPENSSL_SUCCESS;

ERR:
    US_ERR("sec_ciphers_sec_state_init failed. ctx=%p", priv_ctx);
    (void)sec_ciphers_priv_ctx_cleanup(priv_ctx);
    return OPENSSL_FAIL;
}

static void sec_ciphers_update_priv_ctx(cipher_priv_ctx *priv_ctx)
{
    uint32_t do_cipher_len = priv_ctx->do_cipher_len;
    uint32_t increase_counter = 0;

    if (do_cipher_len == 0)
        return;

    int iv_bytes = priv_ctx->e_cipher_ctx->op_data.iv_bytes;  // equels 16
    unsigned char K[iv_bytes];                                // next iv in OFB c_mode
    if (priv_ctx->c_mode == OFB) {
        int ofb_offset = priv_ctx->do_cipher_len - iv_bytes;
        int i;
        for (i = 0; i < iv_bytes; i++) {
            K[i] =
                *((unsigned char *)priv_ctx->in + ofb_offset + i) ^ *((unsigned char *)priv_ctx->out + ofb_offset + i);
        }
    }

    priv_ctx->in += priv_ctx->do_cipher_len;
    priv_ctx->out += priv_ctx->do_cipher_len;
    priv_ctx->left_len -= priv_ctx->do_cipher_len;

    switch (priv_ctx->c_mode) {
        case ECB:
            break;
        case CFB:
        case CBC:
            if (priv_ctx->encrypt == OPENSSL_ENCRYPTION)
                kae_memcpy(priv_ctx->iv, priv_ctx->out - 16, 16);  // hardware need 16-byte alignment
            else
                kae_memcpy(priv_ctx->iv, priv_ctx->in - 16, 16);  // hardware need 16-byte alignment
            break;
        case CTR:
            increase_counter = (do_cipher_len + priv_ctx->offset) >> 4;  // right shift 4
            sec_ciphers_ctr_iv_inc(priv_ctx->iv, increase_counter);
            priv_ctx->offset = (priv_ctx->offset + (do_cipher_len & 0xf)) % 16;  // hardware need 16-byte alignment
            break;
        case XTS:
            if (priv_ctx->c_alg == AES) {
                priv_ctx->ecb_encryto->countNum = (priv_ctx->do_cipher_len + priv_ctx->offset) >> 4;  // right shift 4
                sec_ciphers_xts_iv_inc(priv_ctx);
                priv_ctx->offset = (priv_ctx->offset + (do_cipher_len & 0xf)) % 16;  // hardware need 16-byte alignment
            }
            break;
        case OFB:
            kae_memcpy(priv_ctx->iv, K, priv_ctx->e_cipher_ctx->op_data.iv_bytes);
            break;
        default:
            US_WARN("mode=%d don't support.", priv_ctx->c_mode);
            break;
    }

    US_DEBUG("update priv_ctx success.");
}

static int sec_ciphers_before_dociphers_cb(cipher_priv_ctx *priv_ctx)
{
    if (priv_ctx->c_mode == XTS && priv_ctx->c_alg == AES) {
        sec_ciphers_ecb_encryt(
            priv_ctx->ecb_encryto, priv_ctx->ecb_encryto->encryto_iv, priv_ctx->iv, priv_ctx->iv_len);
    }

    return KAE_SUCCESS;
}

static int sec_ciphers_after_dociphers_cb(EVP_CIPHER_CTX *ctx)
{
    // sync priv ctx to next cipher, in case next cipher may be soft cipher
    return sec_ciphers_sw_hw_ctx_sync(ctx, SEC_CIHPER_SYNC_H2S);
}

int sec_ciphers_sync_do_crypto(cipher_engine_ctx_t *e_cipher_ctx, cipher_priv_ctx *priv_ctx)
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

        // (void)sec_ciphers_after_dociphers_cb(priv_ctx->sw_ctx);  // todo how?

        leftlen -= priv_ctx->do_cipher_len;
    }

    US_DEBUG("sec state update success.");

    return KAE_SUCCESS;
}

int sec_ciphers_async_do_crypto(cipher_engine_ctx_t *e_cipher_ctx, op_done_t *op_done)
{
    int ret = 0;
    int cnt = 0;
    cipher_priv_ctx *priv_ctx = e_cipher_ctx->priv_ctx;
    enum task_type_wd type = ASYNC_TASK_WD_CIPHER;
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

static int sec_ciphers_do_crypto(cipher_priv_ctx *priv_ctx)
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
    if (priv_ctx->left_len > CIPHER_INPUT_CACHE_SIZE - priv_ctx->offset) {
        ret = sec_ciphers_sync_do_crypto(e_cipher_ctx, priv_ctx);
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
        return sec_ciphers_sync_do_crypto(e_cipher_ctx, priv_ctx);
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
    (void)sec_ciphers_after_dociphers_cb(priv_ctx->sw_ctx);

    return KAE_SUCCESS;
err:
    US_ERR("async job err");
    (void)async_clear_async_event_notification_v1();
    async_cleanup_op_done_v1(&op_done);
    return KAE_FAIL;
}

static int sec_ciphers_is_check_valid(cipher_priv_ctx *priv_ctx)
{
    if (priv_ctx->switch_threshold > (size_t)priv_ctx->inl && !priv_ctx->use_hw) {
        US_WARN_LIMIT("small packet cipher offload, switch to soft cipher, inl %d", (int)priv_ctx->inl);
        return KAE_FAIL;
    }

    if (sec_ciphers_is_iv_may_overflow(priv_ctx)) {
        US_WARN("sec do cipher, the iv will overflow");
        return KAE_FAIL;
    }

    return KAE_SUCCESS;
}

int sec_ciphers_do_cipher(
    cipher_priv_ctx *priv_ctx, unsigned char *out, size_t outsize, const unsigned char *in, size_t inl)
{
    int ret;

    if (outsize < priv_ctx->blk_size) {
        // ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return OPENSSL_FAIL;
    }

    SEC_CIPHERS_RETURN_FAIL_IF(in == NULL, "in is NULL", OPENSSL_FAIL);
    SEC_CIPHERS_RETURN_FAIL_IF(out == NULL, "out is NULL", OPENSSL_FAIL);

    priv_ctx->inl = inl;
    priv_ctx->in = in;
    priv_ctx->out = out;
    priv_ctx->left_len = inl;

    ret = sec_ciphers_is_check_valid(priv_ctx);
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

    ret = sec_ciphers_do_crypto(priv_ctx);
    if (ret != KAE_SUCCESS) {
        US_WARN("sec cipher do ciphers failed, switch to soft cipher");
        goto do_soft_cipher;
    }

    priv_ctx->use_hw = 1;
    US_DEBUG("sec cipher success!");

    return OPENSSL_SUCCESS;

do_soft_cipher:
    if (priv_ctx->e_cipher_ctx != NULL) {
        wd_ciphers_put_engine_ctx(priv_ctx->e_cipher_ctx);
        priv_ctx->e_cipher_ctx = NULL;
    }

    return KAE_CRYPTO_FAIL;
}

int sec_ciphers_priv_ctx_cleanup(cipher_priv_ctx *priv_ctx)
{
    if (unlikely(priv_ctx == NULL)) {
        US_WARN("ctx cipher data is NULL.");
        return KAE_FAIL;
    }

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

int sec_cipher_module_init(void)
{
    wd_ciphers_init_qnode_pool();
    wd_aead_init_qnode_pool();

    // reg async interface here
    async_register_poll_fn_v1(ASYNC_TASK_WD_CIPHER, sec_cipher_engine_ctx_poll);
    async_register_poll_fn_v1(ASYNC_TASK_WD_AEAD, sec_aead_engine_ctx_poll);

    return 1;
}
