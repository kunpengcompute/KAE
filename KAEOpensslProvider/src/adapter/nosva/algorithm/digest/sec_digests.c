/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:    This file provides the implementation for KAE engine digests
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

#include <openssl/md5.h>
#include <openssl/evp.h>

#include "sec_digests.h"
#include "sec_digests_wd.h"

#include "../../../common/kae_utils.h"
#include "../../../common/kae_types.h"
#include "../../../common/kae_log.h"
#include "../../async/async_callback.h"
#include "../../async/async_event.h"
#include "../../async/async_task_queue.h"
#include "../../async/async_check.h"

#define DIGEST_SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)
#define DIGEST_MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (8 * 1024)

struct digest_info {
    int nid;
    int is_enabled;
    EVP_MD *digest;
};

static struct digest_threshold_table g_digest_pkt_threshold_table[] = {
    {NID_sm3, DIGEST_SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_md5, DIGEST_MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
};

#define SEC_DIGESTS_RETURN_FAIL_IF(cond, mesg, ret) \
    do {                                            \
        if (unlikely(cond)) {                       \
            US_ERR(mesg);                           \
            return (ret);                           \
        }                                           \
    } while (0)

static int sec_digests_dowork(sec_digest_priv *md_ctx);
static int sec_digests_sync_dowork(sec_digest_priv *md_ctx);
static int sec_digests_async_dowork(sec_digest_priv *md_ctx, op_done_t *op_done);
uint32_t sec_digests_sw_get_threshold(int nid)
{
    int threshold_table_sz = BLOCKSIZES_OF(g_digest_pkt_threshold_table);
    int i = 0;

    do {
        if (g_digest_pkt_threshold_table[i].nid == nid)
            return g_digest_pkt_threshold_table[i].threshold;
    } while (++i < threshold_table_sz);

    US_ERR("nid %d not found in digest threshold table", nid);
    return UINT_MAX;
}

static void sec_digests_get_alg(sec_digest_priv *md_ctx)
{
    switch (md_ctx->e_nid) {
        case NID_sm3:
            md_ctx->d_alg = WCRYPTO_SM3;
            md_ctx->out_len = SM3_LEN;
            break;
        case NID_md5:
            md_ctx->d_alg = WCRYPTO_MD5;
            md_ctx->out_len = MD5_HASH_LEN;
            break;
        default:
            US_WARN("nid=%d don't support by sec engine.", md_ctx->e_nid);
            break;
    }
}

int sec_digests_init(sec_digest_priv *md_ctx)
{

    if (unlikely(md_ctx == NULL)) {
        return OPENSSL_FAIL;
    }
    if (md_ctx->e_digest_ctx) {
        (void)wd_digests_put_engine_ctx(md_ctx->e_digest_ctx);
        md_ctx->e_digest_ctx = NULL;
    }

    sec_digests_get_alg(md_ctx);
    md_ctx->state = SEC_DIGEST_INIT;
    md_ctx->last_update_buff = NULL;
    md_ctx->last_update_bufflen = 0;
    md_ctx->total_data_len = 0;
    md_ctx->long_data_len = 0;
    md_ctx->is_stream_copy = false;
    md_ctx->is_copy = false;
    return OPENSSL_SUCCESS;
}

static void sec_digests_set_msg_state(sec_digest_priv *md_ctx, bool is_end)
{
    if (unlikely(md_ctx->is_stream_copy)) {
        md_ctx->e_digest_ctx->op_data.has_next = is_end ? WCRYPTO_DIGEST_STREAM_END : WCRYPTO_DIGEST_STREAM_DOING;
        md_ctx->is_stream_copy = false;
    } else {
        md_ctx->e_digest_ctx->op_data.has_next = is_end ? WCRYPTO_DIGEST_END : WCRYPTO_DIGEST_DOING;
    }
}

static int sec_digests_update_inner(sec_digest_priv *md_ctx, size_t data_len, const void *data)
{
    int ret = OPENSSL_FAIL;
    size_t left_len = data_len;
    const unsigned char *tmpdata = (const unsigned char *)data;
    while (left_len > DIGEST_INPUT_CACHE_SIZE - md_ctx->last_update_bufflen) {
        int copy_to_bufflen = DIGEST_INPUT_CACHE_SIZE - md_ctx->last_update_bufflen;

        kae_memcpy(md_ctx->last_update_buff + md_ctx->last_update_bufflen, tmpdata, copy_to_bufflen);
        md_ctx->last_update_bufflen = DIGEST_INPUT_CACHE_SIZE;
        left_len -= copy_to_bufflen;
        tmpdata += copy_to_bufflen;

        if (md_ctx->state == SEC_DIGEST_INIT)
            md_ctx->state = SEC_DIGEST_FIRST_UPDATING;
        else if (md_ctx->state == SEC_DIGEST_FIRST_UPDATING)
            md_ctx->state = SEC_DIGEST_DOING;
        else
            (void)md_ctx->state;

        sec_digests_set_msg_state(md_ctx, false);
        ret = sec_digests_sync_dowork(md_ctx);
        if (ret != KAE_SUCCESS) {
            US_WARN("do sec digest failed, switch to soft digest");
            return KAE_CRYPTO_FAIL;
        }

        md_ctx->last_update_bufflen = 0;
        if (left_len <= DIGEST_INPUT_CACHE_SIZE) {
            md_ctx->last_update_bufflen = left_len;
            kae_memcpy(md_ctx->last_update_buff, tmpdata, md_ctx->last_update_bufflen);
            break;
        }
    }

    US_DEBUG("sec digest update success!");
    return OPENSSL_SUCCESS;
}

int sec_digests_update(sec_digest_priv *md_ctx, const void *data, size_t data_len)
{
    // SEC_DIGESTS_RETURN_FAIL_IF(unlikely(!ctx || !data),   "ctx is NULL.", OPENSSL_FAIL);
    // sec_digest_priv *md_ctx = (sec_digest_priv *)EVP_MD_CTX_md_data(ctx);
    // sec_digest_priv *md_ctx = ctx->priv;
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(md_ctx == NULL), "md_ctx is NULL.", OPENSSL_FAIL);
    if (data_len > UINT64_MAX - md_ctx->total_data_len)
        return OPENSSL_FAIL;
    if (md_ctx->e_digest_ctx == NULL && md_ctx->switch_flag != 1) {
        md_ctx->e_digest_ctx = wd_digests_get_engine_ctx(md_ctx);
        if (md_ctx->e_digest_ctx == NULL) {
            US_WARN("failed to get engine ctx");
            md_ctx->switch_flag = 1;
            return KAE_CRYPTO_FAIL;
            // 如果硬件申请不行就走软算
            //  if (sec_digests_soft_init(md_ctx) != OPENSSL_SUCCESS) {
            //      US_ERR("do sec digest soft init failed");
            //      return OPENSSL_FAIL;
            //  }
            //  md_ctx->switch_flag = 1;
        }
    }

    // if (md_ctx->switch_flag == 1) {
    //     return sec_digests_soft_update(md_ctx, data, data_len);
    // }

    if (md_ctx->e_digest_ctx == NULL) {
        US_ERR("digest_ctx is null");
        return OPENSSL_FAIL;
    }
    digest_engine_ctx_t *e_digest_ctx = md_ctx->e_digest_ctx;
    if (md_ctx->last_update_buff == NULL) {
        md_ctx->last_update_buff = e_digest_ctx->op_data.in;
    }

    // int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));
    // md_ctx->e_nid = nid;
    md_ctx->total_data_len += data_len;
    sec_digests_get_alg(md_ctx);
    unsigned char digest[MAX_OUTLEN] = {0};
    md_ctx->out = digest;

    if (data_len <= DIGEST_INPUT_CACHE_SIZE - md_ctx->last_update_bufflen) {
        kae_memcpy(md_ctx->last_update_buff + md_ctx->last_update_bufflen, data, data_len);
        md_ctx->last_update_bufflen += data_len;
        return OPENSSL_SUCCESS;
    }

    return sec_digests_update_inner(md_ctx, data_len, data);
}

int sec_digests_final(sec_digest_priv *md_ctx, unsigned char *digest)
{
    int ret = KAE_FAIL;

    // SEC_DIGESTS_RETURN_FAIL_IF(!ctx || !digest, "ctx is NULL.", OPENSSL_FAIL);
    // sec_digest_priv *md_ctx = ctx->priv;
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(md_ctx == NULL), "md_ctx is NULL.", OPENSSL_FAIL);

    if (md_ctx->switch_flag == 1) {
        // ret = sec_digests_soft_final(md_ctx, digest);
        // sec_digests_soft_cleanup(md_ctx);
        return KAE_CRYPTO_FAIL;
    }

    if (md_ctx->last_update_bufflen == 0) {
        US_WARN("no data input, swich to soft digest");
        return KAE_CRYPTO_FAIL;
        // goto do_soft_digest;
    }

    if (md_ctx->last_update_buff && md_ctx->last_update_bufflen != 0) {
        if (md_ctx->state == SEC_DIGEST_INIT &&
            md_ctx->last_update_bufflen < sec_digests_sw_get_threshold(md_ctx->e_nid)) {
            US_WARN_LIMIT("small package offload, switch to soft digest");
            // goto do_soft_digest;
            return KAE_CRYPTO_FAIL;
        }

        uint32_t tmp = md_ctx->state;
        md_ctx->state = SEC_DIGEST_FINAL;

        md_ctx->out = digest;
        sec_digests_set_msg_state(md_ctx, true);
        ret = sec_digests_dowork(md_ctx);
        if (ret != KAE_SUCCESS) {
            US_WARN("do sec digest failed, switch to soft digest");
            md_ctx->state = tmp;
            // goto do_soft_digest;
            return KAE_CRYPTO_FAIL;
        }
        ret = OPENSSL_SUCCESS;
    }

    US_DEBUG("sec digest final success!");

    // end:
    return ret;

    // do_soft_digest:
    //     if (md_ctx->state == SEC_DIGEST_INIT) {
    //         ret = sec_digests_soft_work(md_ctx, md_ctx->last_update_bufflen, digest);
    //     } else {
    //         US_ERR("do sec digest failed");
    //         ret = OPENSSL_FAIL;
    //     }

    //     return ret;
}
static void sec_digests_update_md_ctx(sec_digest_priv *md_ctx)
{
    if (md_ctx->do_digest_len == 0)
        return;

    md_ctx->in += md_ctx->do_digest_len;
}

static int sec_digests_dowork(sec_digest_priv *md_ctx)
{
    int ret = KAE_FAIL;

    // add async parm
    int job_ret;
    op_done_t op_done;

    SEC_DIGESTS_RETURN_FAIL_IF(md_ctx->last_update_bufflen <= 0, "in length less than or equal to zero.", KAE_FAIL);
    // packageSize>input_cache_size
    if (md_ctx->last_update_bufflen > DIGEST_INPUT_CACHE_SIZE) {
        ret = sec_digests_sync_dowork(md_ctx);
        if (ret != 0) {
            US_ERR("sec digest sync fail");
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
        return sec_digests_sync_dowork(md_ctx);
    }

    if (sec_digests_async_dowork(md_ctx, &op_done) == KAE_FAIL)
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

    US_DEBUG(" Digest Async Job Finish! md_ctx = %p\n", md_ctx);
    return KAE_SUCCESS;
err:
    US_ERR("async job err");
    (void)async_clear_async_event_notification_v1();
    async_cleanup_op_done_v1(&op_done);
    return KAE_FAIL;
}

static int sec_digests_sync_dowork(sec_digest_priv *md_ctx)
{
    SEC_DIGESTS_RETURN_FAIL_IF(md_ctx == NULL, "md_ctx is NULL.", KAE_FAIL);
    digest_engine_ctx_t *e_digest_ctx = md_ctx->e_digest_ctx;
    uint32_t leftlen = md_ctx->last_update_bufflen;
    int ret;

    md_ctx->in = md_ctx->last_update_buff;

    while (leftlen != 0) {
        md_ctx->do_digest_len = wd_digests_get_do_digest_len(e_digest_ctx, leftlen);

        wd_digests_set_input_data(e_digest_ctx);

        ret = wd_digests_doimpl(e_digest_ctx);
        if (ret != KAE_SUCCESS)
            return ret;

        wd_digests_get_output_data(e_digest_ctx);
        sec_digests_update_md_ctx(md_ctx);
        leftlen -= md_ctx->do_digest_len;
    }

    US_DEBUG("sec do digest success.");

    return KAE_SUCCESS;
}

static int sec_digests_async_dowork(sec_digest_priv *md_ctx, op_done_t *op_done)
{
    int ret = 0;
    int cnt = 0;
    enum task_type_wd type = ASYNC_TASK_WD_DIGEST;

    SEC_DIGESTS_RETURN_FAIL_IF(md_ctx == NULL, "md_ctx is NULL.", KAE_FAIL);
    digest_engine_ctx_t *e_digest_ctx = md_ctx->e_digest_ctx;

    SEC_DIGESTS_RETURN_FAIL_IF(e_digest_ctx == NULL, "e_digest_ctx is NULL", KAE_FAIL);
    void *tag = e_digest_ctx;
    uint32_t leftlen = md_ctx->last_update_bufflen;

    md_ctx->in = md_ctx->last_update_buff;
    md_ctx->do_digest_len = wd_digests_get_do_digest_len(e_digest_ctx, leftlen);
    wd_digests_set_input_data(e_digest_ctx);

    do {
        if (cnt > MAX_SEND_TRY_CNTS)
            break;
        ret = wcrypto_do_digest(e_digest_ctx->wd_ctx, &e_digest_ctx->op_data, tag);
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

    if (async_add_poll_task_v1(e_digest_ctx, op_done, type) == 0) {
        US_ERR("sec add task failed ");
        return KAE_FAIL;
    }

    return KAE_SUCCESS;
}

int sec_digests_cleanup(sec_digest_priv *md_ctx)
{
    // SEC_DIGESTS_RETURN_FAIL_IF(!ctx, "ctx is NULL.", OPENSSL_FAIL);
    // sec_digest_priv *md_ctx = (sec_digest_priv *)EVP_MD_CTX_md_data(ctx);

    /* Prevent double-free after the copy is used */
    if (!md_ctx)
        return OPENSSL_SUCCESS;
    // if (md_ctx->switch_flag == 1) {
    //     sec_digests_soft_cleanup(md_ctx);
    // }

    if (md_ctx->e_digest_ctx != NULL) {
        (void)wd_digests_put_engine_ctx(md_ctx->e_digest_ctx);
        md_ctx->e_digest_ctx = NULL;
    }

    return OPENSSL_SUCCESS;
}

int sec_digests_copy(sec_digest_priv *to_ctx, const sec_digest_priv *from_ctx)
{
    // sec_digest_priv *to_ctx = to->priv;
    // sec_digest_priv *from_ctx = from->priv;
    struct wcrypto_digest_op_data *tp;
    struct wcrypto_digest_op_data *fp;

    if (!to_ctx)
        return 1;

    if (!from_ctx) {
        US_ERR("priv get from digest ctx is NULL.\n");
        return OPENSSL_FAIL;
    }

    if (from_ctx->e_digest_ctx) {
        to_ctx->e_digest_ctx = NULL;
        to_ctx->e_digest_ctx = wd_digests_get_engine_ctx(to_ctx);

        if (to_ctx->e_digest_ctx == NULL) {
            US_WARN("failed to get engine ctx");
            return OPENSSL_FAIL;
        }

        tp = &to_ctx->e_digest_ctx->op_data;
        fp = &from_ctx->e_digest_ctx->op_data;
        memcpy(tp->in, fp->in, from_ctx->last_update_bufflen);
        memcpy(tp->out, fp->out, fp->out_bytes);
        memcpy(tp->iv, fp->iv, fp->iv_bytes);
        tp->in_bytes = from_ctx->last_update_bufflen;
        tp->out_bytes = fp->out_bytes;
        tp->status = fp->status;
        tp->has_next = fp->has_next;
        tp->iv_bytes = fp->iv_bytes;

        to_ctx->last_update_buff = tp->in;
        to_ctx->is_copy = true;

        if (to_ctx->state != SEC_DIGEST_INIT) {
            to_ctx->is_stream_copy = true;
            /* Length that the hardware has processed should be equal to
             * total input data length minus software cache data length.
             */

            to_ctx->long_data_len = to_ctx->total_data_len - to_ctx->last_update_bufflen;
            tp->priv = (void *)&to_ctx->long_data_len;
        }
    }

    US_DEBUG("sec digest copy success.");
    return 1;
}

// async poll thread create
int sec_digest_engine_ctx_poll(void *engnine_ctx)
{
    int ret = 0;
    digest_engine_ctx_t *e_digest_ctx = (digest_engine_ctx_t *)engnine_ctx;
    struct wd_queue *q = e_digest_ctx->q_node->kae_wd_queue;

POLL_AGAIN:
    ret = wcrypto_digest_poll(q, 1);
    if (!ret) {
        goto POLL_AGAIN;
    } else if (ret < 0) {
        US_ERR("digest poll failed\n");
        return ret;
    }
    return ret;
}

int sec_digest_module_init(void)
{
    wd_digests_init_qnode_pool();
    async_register_poll_fn_v1(ASYNC_TASK_WD_DIGEST, sec_digest_engine_ctx_poll);

    return 1;
}
