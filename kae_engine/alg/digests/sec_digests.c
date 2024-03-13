/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:    This file provides the implemenation for KAE engine digests 
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

#include "sec_digests.h"
#include "sec_digests_soft.h"
#include "sec_digests_wd.h"

#include "engine_check.h"
#include "engine_utils.h"
#include "engine_types.h"
#include "engine_log.h"
#include "async_callback.h"
#include "async_event.h"
#include "async_task_queue.h"

#define DIGEST_SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)
#define DIGEST_MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (8 * 1024)

struct digest_info {
    int nid;
    int is_enabled;
    EVP_MD *digest;
};

static struct digest_threshold_table g_digest_pkt_threshold_table[] = {
    { NID_sm3, DIGEST_SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_md5, DIGEST_MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
};

static struct digest_info g_sec_digests_info[] = { 
    { NID_sm3, 1, NULL },
    { NID_md5, 1, NULL },
};

#define DIGESTS_COUNT (BLOCKSIZES_OF(g_sec_digests_info))
static int g_known_digest_nids[DIGESTS_COUNT] = {
    NID_sm3,
    NID_md5,
};

#define SEC_DIGESTS_RETURN_FAIL_IF(cond, mesg, ret) \
        if (unlikely(cond)) {\
            US_ERR(mesg); \
            return (ret); \
        }\

static int sec_digests_init(EVP_MD_CTX *ctx);
static int sec_digests_update(EVP_MD_CTX *ctx, const void *data, size_t data_len);
static int sec_digests_final(EVP_MD_CTX *ctx, unsigned char *digest);
static int sec_digests_cleanup(EVP_MD_CTX *ctx);
static int sec_digests_dowork(sec_digest_priv_t *md_ctx);
static int sec_digests_sync_dowork(sec_digest_priv_t *md_ctx);
static int sec_digests_async_dowork(sec_digest_priv_t *md_ctx, op_done_t *op_done);
static uint32_t sec_digests_sw_get_threshold(int nid);

void sec_digests_set_enabled(int nid, int enabled) {
    unsigned int i = 0;
    for (i = 0; i < DIGESTS_COUNT; i++) {
        if (g_sec_digests_info[i].nid == nid) {
            g_sec_digests_info[i].is_enabled = enabled;
        }
    }
}
static uint32_t sec_digests_sw_get_threshold(int nid)
{
    int threshold_table_sz = BLOCKSIZES_OF(g_digest_pkt_threshold_table);
    int i = 0;
    do {
        if (g_digest_pkt_threshold_table[i].nid == nid) {
            return g_digest_pkt_threshold_table[i].threshold;
        }
    } while (++i < threshold_table_sz);

    US_ERR("nid %d not found in digest threshold table", nid);
    return UINT_MAX;
}

static void sec_digests_get_alg(sec_digest_priv_t *md_ctx)
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

int sec_digests_init(EVP_MD_CTX *ctx)
{
    sec_digest_priv_t *md_ctx = NULL;
    if (unlikely(ctx == NULL)) {
        return OPENSSL_FAIL;
    }

    md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);
    if (unlikely(md_ctx == NULL)) {
        return OPENSSL_FAIL;
    }
    memset((void *)md_ctx, 0, sizeof(sec_digest_priv_t));
    int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));
    md_ctx->e_nid = nid;
    sec_digests_get_alg(md_ctx);
    md_ctx->state = SEC_DIGEST_INIT;
    return OPENSSL_SUCCESS;
}

static int sec_digests_update_inner(sec_digest_priv_t *md_ctx, size_t data_len, const void *data)
{
    int ret = OPENSSL_FAIL; 
    size_t left_len = data_len;
    const unsigned char* tmpdata = (const unsigned char *)data;
    while (md_ctx->last_update_bufflen + left_len > INPUT_CACHE_SIZE) {      
        int copy_to_bufflen = INPUT_CACHE_SIZE - md_ctx->last_update_bufflen;
        kae_memcpy(md_ctx->last_update_buff + md_ctx->last_update_bufflen, tmpdata, copy_to_bufflen);
        md_ctx->last_update_bufflen = INPUT_CACHE_SIZE;
        left_len -= copy_to_bufflen;
        tmpdata  += copy_to_bufflen;
        
        if (md_ctx->state == SEC_DIGEST_INIT) {
            md_ctx->state = SEC_DIGEST_FIRST_UPDATING;
        } else if (md_ctx->state == SEC_DIGEST_FIRST_UPDATING) {
            md_ctx->state = SEC_DIGEST_DOING;
        } else {
            (void)md_ctx->state;
        }

        ret = sec_digests_sync_dowork(md_ctx);
        if (ret != KAE_SUCCESS) {
            US_WARN("do sec digest failed, switch to soft digest");
            goto do_soft_digest;
        }

        md_ctx->last_update_bufflen = 0;
        if (left_len <= INPUT_CACHE_SIZE) {
            md_ctx->last_update_bufflen = left_len;
            kae_memcpy(md_ctx->last_update_buff, tmpdata, md_ctx->last_update_bufflen);
            break;    
        }
    }
       
    return OPENSSL_SUCCESS;

do_soft_digest:
    if (md_ctx->state == SEC_DIGEST_FIRST_UPDATING
        && md_ctx->last_update_buff
        && md_ctx->last_update_bufflen != 0) {
        md_ctx->switch_flag = 1;
        sec_digests_soft_init(md_ctx, md_ctx->e_nid);
        ret = sec_digests_soft_update(md_ctx->soft_ctx, md_ctx->last_update_buff, 
                                      md_ctx->last_update_bufflen, md_ctx->e_nid);
        ret &= sec_digests_soft_update(md_ctx->soft_ctx, tmpdata, left_len, md_ctx->e_nid);
        
        return ret;
    } else {
        US_ERR("do sec digest failed");
        return OPENSSL_FAIL;
    }
}

static int sec_digests_update(EVP_MD_CTX *ctx, const void *data, 
                              size_t data_len)
{
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(!ctx || !data),   "ctx is NULL.", OPENSSL_FAIL);
    sec_digest_priv_t *md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(md_ctx == NULL),   "md_ctx is NULL.", OPENSSL_FAIL);

    if (md_ctx->e_digest_ctx == NULL) {
        md_ctx->e_digest_ctx = wd_digests_get_engine_ctx(md_ctx);
        if (md_ctx->e_digest_ctx == NULL) {
            US_WARN("failed to get engine ctx");
            //如果硬件申请不行就走软算
            if (sec_digests_soft_init(md_ctx, md_ctx->e_nid) != OPENSSL_SUCCESS) {
                US_ERR("do sec digest soft init failed");
                return OPENSSL_FAIL;
            }
            md_ctx->switch_flag = 1;
        }
    }
    
    if (md_ctx->switch_flag == 1) {
        return sec_digests_soft_update(md_ctx->soft_ctx, data, data_len, md_ctx->e_nid);
    }

    if (md_ctx->e_digest_ctx == NULL) {
        US_ERR("digest_ctx is null");
        return OPENSSL_FAIL;
    }
    digest_engine_ctx_t *e_digest_ctx = md_ctx->e_digest_ctx;
    if (md_ctx->last_update_buff == NULL) {
        md_ctx->last_update_buff = e_digest_ctx->op_data.in;
    }

    int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));
    md_ctx->e_nid = nid;
    sec_digests_get_alg(md_ctx);
    unsigned char digest[MAX_OUTLEN] = {0};
    md_ctx->out = digest;

    if (md_ctx->last_update_bufflen + data_len <= INPUT_CACHE_SIZE) {
        kae_memcpy(md_ctx->last_update_buff + md_ctx->last_update_bufflen, data, data_len);
        md_ctx->last_update_bufflen += data_len;
        return OPENSSL_SUCCESS;
    }

    return sec_digests_update_inner(md_ctx, data_len, data);
}

static int sec_digests_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
    int ret = KAE_FAIL;

    SEC_DIGESTS_RETURN_FAIL_IF(!ctx || !digest, "ctx is NULL.", OPENSSL_FAIL);
    sec_digest_priv_t *md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(md_ctx == NULL), "md_ctx is NULL.", OPENSSL_FAIL);
    
    if (md_ctx->switch_flag == 1) {
        ret = sec_digests_soft_final(md_ctx->soft_ctx, digest, md_ctx->e_nid);
        sec_digests_soft_cleanup(md_ctx);
        goto end;
    }

    if (md_ctx->last_update_bufflen == 0) {
        US_WARN("no data input, swich to soft digest");
        goto do_soft_digest;
    }

    if (md_ctx->last_update_buff && md_ctx->last_update_bufflen != 0) {
        if (md_ctx->state == SEC_DIGEST_INIT 
                && md_ctx->last_update_bufflen < sec_digests_sw_get_threshold(md_ctx->e_nid)) {
            US_WARN_LIMIT("small package offload, switch to soft digest");
            goto do_soft_digest;
        }
        
        uint32_t tmp = md_ctx->state;
        md_ctx->state = SEC_DIGEST_FINAL;

        md_ctx->out = digest;
        ret = sec_digests_dowork(md_ctx);
        if (ret != KAE_SUCCESS) {
            US_WARN("do sec digest failed, switch to soft digest");
            md_ctx->state = tmp;
            goto do_soft_digest;
        }
        ret = OPENSSL_SUCCESS;
    } 

    US_DEBUG("do digest success. ctx=%p", md_ctx);

end:
    return ret;

do_soft_digest:
    if (md_ctx->state == SEC_DIGEST_INIT) {
        ret = sec_digests_soft_work(md_ctx, md_ctx->last_update_bufflen, digest);
    } else {
        US_ERR("do sec digest failed");
        ret = OPENSSL_FAIL;
    }

    return ret;
}

static void sec_digests_update_md_ctx(sec_digest_priv_t* md_ctx)
{
    if (md_ctx->do_digest_len == 0) {
        return;
    }
    
    md_ctx->in += md_ctx->do_digest_len;
}

static int sec_digests_dowork(sec_digest_priv_t *md_ctx)
{
    int ret = KAE_FAIL;

    // add async parm
    int job_ret;
    op_done_t op_done;

    SEC_DIGESTS_RETURN_FAIL_IF(md_ctx->last_update_bufflen <= 0, "in length less than or equal to zero.", KAE_FAIL);
    // packageSize>input_cache_size
    if (md_ctx->last_update_bufflen > INPUT_CACHE_SIZE) {
        ret = sec_digests_sync_dowork(md_ctx);
        if (ret != 0) {
            US_ERR("sec digest sync fail");
            return ret;
        }
        return KAE_SUCCESS;
    }

    // async
    async_init_op_done(&op_done);

    if (op_done.job != NULL && kae_is_async_enabled()) {
        if (async_setup_async_event_notification(0) == 0) {
            US_ERR("sec async event notifying failed");
            async_cleanup_op_done(&op_done);
            return KAE_FAIL;
        }
    } else {
        US_DEBUG("NO ASYNC Job or async disable, back to SYNC!");
        async_cleanup_op_done(&op_done);
        return sec_digests_sync_dowork(md_ctx);
    }

    if (sec_digests_async_dowork(md_ctx, &op_done) == KAE_FAIL)
        goto err;

    do {
        job_ret = async_pause_job(op_done.job, ASYNC_STATUS_OK);
        if ((job_ret == 0)) {
            US_DEBUG("- pthread_yidle -");
            kae_pthread_yield();
        }
    } while (!op_done.flag || ASYNC_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    if (op_done.verifyRst < 0) {
        US_ERR("verify result failed with %d", op_done.verifyRst);
        async_cleanup_op_done(&op_done);
        return KAE_FAIL;
    }

    async_cleanup_op_done(&op_done);

    US_DEBUG(" Digest Async Job Finish! md_ctx = %p\n", md_ctx);
    return KAE_SUCCESS;
err:
    US_ERR("async job err");
    (void)async_clear_async_event_notification();
    async_cleanup_op_done(&op_done);
    return KAE_FAIL;
}

static int sec_digests_sync_dowork(sec_digest_priv_t *md_ctx)
{
    SEC_DIGESTS_RETURN_FAIL_IF(md_ctx == NULL,   "md_ctx is NULL.", KAE_FAIL);
    digest_engine_ctx_t *e_digest_ctx = md_ctx->e_digest_ctx;
    md_ctx->in = md_ctx->last_update_buff;
    uint32_t leftlen = md_ctx->last_update_bufflen;
    while (leftlen != 0) {
        md_ctx->do_digest_len = wd_digests_get_do_digest_len(e_digest_ctx, leftlen);

        wd_digests_set_input_data(e_digest_ctx);
        
        int ret = wd_digests_doimpl(e_digest_ctx);
        if (ret != KAE_SUCCESS) {
            return ret;
        }
        
        wd_digests_get_output_data(e_digest_ctx);
        sec_digests_update_md_ctx(md_ctx);
        leftlen -= md_ctx->do_digest_len;
    }

    US_DEBUG("sec do digest success.");

    return KAE_SUCCESS;
}

static int sec_digests_async_dowork(sec_digest_priv_t *md_ctx, op_done_t *op_done)
{
    int ret = 0;
    int cnt = 0;
    enum task_type type = ASYNC_TASK_DIGEST;

    SEC_DIGESTS_RETURN_FAIL_IF(md_ctx == NULL, "md_ctx is NULL.", KAE_FAIL);
    digest_engine_ctx_t *e_digest_ctx = md_ctx->e_digest_ctx;
    SEC_DIGESTS_RETURN_FAIL_IF(e_digest_ctx == NULL, "e_digest_ctx is NULL", KAE_FAIL);
    void *tag = e_digest_ctx;

    md_ctx->in = md_ctx->last_update_buff;
    uint32_t leftlen = md_ctx->last_update_bufflen;
    md_ctx->do_digest_len = wd_digests_get_do_digest_len(e_digest_ctx, leftlen);

    wd_digests_set_input_data(e_digest_ctx);

    do {
        if (cnt > MAX_SEND_TRY_CNTS) {
            break;
        }
        ret = wcrypto_do_digest(e_digest_ctx->wd_ctx, &e_digest_ctx->op_data, tag);
        if (ret == -WD_EBUSY) {
            if ((async_wake_job(op_done->job, ASYNC_STATUS_EAGAIN) == 0 ||
                     async_pause_job(op_done->job, ASYNC_STATUS_EAGAIN) == 0)) {
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

    if (async_add_poll_task(e_digest_ctx, op_done, type) == 0) {
        US_ERR("sec add task failed ");
        return KAE_FAIL;
    }

    return KAE_SUCCESS;
}

static int sec_digests_cleanup(EVP_MD_CTX *ctx)
{
    SEC_DIGESTS_RETURN_FAIL_IF(!ctx, "ctx is NULL.", OPENSSL_FAIL);
    sec_digest_priv_t *md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);

	/* Prevent double-free after the copy is used */
	if (!md_ctx || md_ctx->copy)
		return OPENSSL_SUCCESS;
    if (md_ctx->switch_flag == 1) {
        sec_digests_soft_cleanup(md_ctx);
    }
    if (md_ctx->e_digest_ctx != NULL) {
        (void)wd_digests_put_engine_ctx(md_ctx->e_digest_ctx);
        md_ctx->e_digest_ctx = NULL;
    }
    return OPENSSL_SUCCESS;
}

static int sec_digests_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from) // stream mode still has bug maybe
{
    sec_digest_priv_t *to_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(to);
    sec_digest_priv_t *from_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(from);

    if (!to_ctx)
		return 1;
	if (!from_ctx) {
		US_ERR("priv get from digest ctx is NULL.\n");
		return OPENSSL_FAIL;
	}

    if (from_ctx->switch_flag == 1) {
        return sec_digests_soft_copy(to, from);
    }

    if (to_ctx && to_ctx->e_digest_ctx) {
        to_ctx->e_digest_ctx->md_ctx = to_ctx;
    }

	/*
	 * EVP_MD_CTX_copy will copy from->priv to to->priv,
	 * including data pointer. Instead of coping data contents,
	 * add a flag to prevent double-free.
	 */

	if (from_ctx && from_ctx->e_digest_ctx)
		to_ctx->copy = true;

	return 1;
}
/**
 * desc:bind digest func as hardware function
 * @return
 */
static EVP_MD *sec_set_digests_methods(struct digest_info digestinfo)
{
    const EVP_MD *default_digest = NULL;
    if (digestinfo.digest == NULL) {
        switch (digestinfo.nid) {
            case NID_sm3:
                default_digest = EVP_sm3();	
                break;
            case NID_md5:
                default_digest = EVP_md5();	
                break;
            default:
                return NULL;
        }
    }
    digestinfo.digest = (EVP_MD *)EVP_MD_meth_dup(default_digest);
    if (digestinfo.digest == NULL) {
        US_ERR("dup digest failed!");
        return NULL;
    }

    EVP_MD_meth_set_init(digestinfo.digest, sec_digests_init);
    EVP_MD_meth_set_update(digestinfo.digest, sec_digests_update);
    EVP_MD_meth_set_final(digestinfo.digest, sec_digests_final);
    EVP_MD_meth_set_cleanup(digestinfo.digest, sec_digests_cleanup);
    EVP_MD_meth_set_copy(digestinfo.digest, sec_digests_copy);
    EVP_MD_meth_set_app_datasize(digestinfo.digest, sizeof(sec_digest_priv_t));
    return digestinfo.digest;
}

static void sec_create_digests(void)
{
    unsigned int i = 0;
    for (i = 0; i < DIGESTS_COUNT; i++) {
        if (g_sec_digests_info[i].digest == NULL) {
            g_sec_digests_info[i].digest = sec_set_digests_methods(g_sec_digests_info[i]);
        }
    }
}

/******************************************************************************
* function:
*         sec_engine_digests(ENGINE *e,
*                     const EVP_digest **digest,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param digest [IN] - digest structure pointer
* @param nids   [IN] - digest function nids
* @param nid    [IN] - digest operation id
*
* description:
*   kae engine digest operations registrar
******************************************************************************/
int sec_engine_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    UNUSED(e);
    unsigned int i = 0;

    if ((nids == NULL) && ((digest == NULL) || (nid < 0))) {
        US_ERR("sec_engine_digests invalid input param.");
        if (digest != NULL) {
            *digest = NULL;
        }
        return OPENSSL_FAIL;
    }

    /* No specific digest => return a list of supported nids ... */
        /* No specific digest => return a list of supported nids ... */
    if (digest == NULL) {
        if (nids != NULL) {
            *nids = g_known_digest_nids;;
        }
        return BLOCKSIZES_OF(g_sec_digests_info);
    }

    for (i = 0; i < DIGESTS_COUNT; i++) {
        if (g_sec_digests_info[i].nid == nid) {
            if (g_sec_digests_info[i].digest == NULL) {
                sec_create_digests();
            }
            /*SM3 is disabled*/
            *digest = g_sec_digests_info[i].is_enabled 
                ? g_sec_digests_info[i].digest : (EVP_MD *)EVP_MD_meth_dup(EVP_sm3());
            return OPENSSL_SUCCESS;
        }
    }
    
    US_WARN("nid = %d not support.", nid);
    *digest = NULL;

    return OPENSSL_FAIL;
}

void sec_digests_free_methods(void)
{
    unsigned int i = 0;

    for (i = 0; i < DIGESTS_COUNT; i++) {
        if (g_sec_digests_info[i].digest != NULL) {
            EVP_MD_meth_free(g_sec_digests_info[i].digest);
            g_sec_digests_info[i].digest = NULL;
        }
    }
}

void sec_digests_cb(const void *msg, void *tag)
{
    if (!msg || !tag) {
        US_ERR("sec cb params err!\n");
        return;
    }
    struct wcrypto_digest_msg *message = (struct wcrypto_digest_msg *)msg;
    digest_engine_ctx_t *e_digest_ctx = (digest_engine_ctx_t *)tag;
    kae_memcpy(e_digest_ctx->md_ctx->out, message->out, message->out_bytes);
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

int digest_module_init(void)
{
    wd_digests_init_qnode_pool();
    sec_create_digests();
    // reg async interface here
    async_register_poll_fn(ASYNC_TASK_DIGEST, sec_digest_engine_ctx_poll);

    return 1;
}
