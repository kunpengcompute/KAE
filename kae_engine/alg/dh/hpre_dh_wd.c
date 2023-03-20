/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides wd api for DH.
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


#include "hpre_dh_wd.h"
#include "hpre_dh_util.h"
#include "engine_types.h"
#include "engine_log.h"
#include "async_callback.h"
#include "async_task_queue.h"
#include "async_event.h"
#include "utils/engine_check.h"
#include <openssl/bn.h>

#define DH_GENERATOR_2 2
#define DH_GENERATOR_5 5
#define CHAR_BIT_SIZE 3
#define DH_PARAMS_CNT 4
#define MAX_SEND_TRY_CNTS 50
#define WD_STATUS_BUSY      (-EBUSY)

KAE_QUEUE_POOL_HEAD_S* g_hpre_dh_qnode_pool = NULL;

static hpre_dh_engine_ctx_t* hpre_dh_new_eng_ctx(DH* alg);

static int hpre_dh_init_eng_ctx(hpre_dh_engine_ctx_t* eng_ctx, int bits, bool is_g2);

static int hpre_dh_set_g(const BIGNUM* g, const int key_size, unsigned char* ag_bin, hpre_dh_engine_ctx_t* engine_ctx);

static int hpre_dh_fill_g_p_priv_key(
    const BIGNUM* g, const BIGNUM* p, const BIGNUM* priv_key, hpre_dh_engine_ctx_t* engine_ctx, unsigned char* ag_bin);

static int hpre_dh_internal_do(void* ctx, struct wcrypto_dh_op_data* opdata);

static int hpre_dh_fill_pub_key(const BIGNUM* pub_key, hpre_dh_engine_ctx_t* engine_ctx, unsigned char* ag_bin);

static void hpre_dh_free_opdata(hpre_dh_engine_ctx_t* eng_ctx);

static int hpre_internal_do_dh(hpre_dh_engine_ctx_t *eng_ctx, enum wcrypto_dh_op_type op_type);

static int hpre_dh_async(hpre_dh_engine_ctx_t *eng_ctx,
    struct wcrypto_dh_op_data *opdata, op_done_t *op_done);

void wd_hpre_dh_uninit_qnode_pool(void)
{
    kae_queue_pool_destroy(g_hpre_dh_qnode_pool, NULL);
    g_hpre_dh_qnode_pool = NULL;
}

int wd_hpre_dh_init_qnode_pool(void)
{
    kae_queue_pool_destroy(g_hpre_dh_qnode_pool, NULL);

    g_hpre_dh_qnode_pool = kae_init_queue_pool(WCRYPTO_DH);
    if (g_hpre_dh_qnode_pool == NULL) {
        US_ERR("hpre dh qnode poll init fail!\n");
        return KAE_FAIL;
    }

    return KAE_SUCCESS;
}

KAE_QUEUE_POOL_HEAD_S* wd_hpre_dh_get_qnode_pool()
{
    return g_hpre_dh_qnode_pool;
}

hpre_dh_engine_ctx_t* hpre_dh_get_eng_ctx(DH* dh, int bits, bool is_g2)
{
    hpre_dh_engine_ctx_t* eng_ctx = hpre_dh_new_eng_ctx(dh);
    if (eng_ctx == NULL) {
        US_WARN("new eng ctx fail then switch to soft!");
        return NULL;
    }

    if (hpre_dh_init_eng_ctx(eng_ctx, bits, is_g2) == 0) {
        hpre_dh_free_eng_ctx(eng_ctx);
        US_WARN("init eng ctx fail then switch to soft!");
        return NULL;
    }
    return eng_ctx;
}

int hpre_dh_fill_genkey_opdata(
    const BIGNUM* g, const BIGNUM* p, const BIGNUM* priv_key, hpre_dh_engine_ctx_t* engine_ctx)
{
    unsigned char* ag_bin = NULL;
    int key_size = engine_ctx->priv_ctx.key_size;

    // allocate data block
    ag_bin = (unsigned char *)kae_wd_alloc_blk(engine_ctx->qlist->kae_queue_mem_pool, key_size);
    if (!ag_bin) {
        US_ERR("pool alloc ag_bin fail!");
        return -ENOMEM;
    }
    int ret = hpre_dh_fill_g_p_priv_key(g, p, priv_key, engine_ctx, ag_bin);
    if (ret != HPRE_DH_SUCCESS) {
        kae_wd_free_blk(engine_ctx->qlist->kae_queue_mem_pool, ag_bin);
        return ret;
    }
    engine_ctx->priv_ctx.block_addr = ag_bin;

    return HPRE_DH_SUCCESS;
}

int hpre_dh_fill_compkey_opdata(
    const BIGNUM* g, const BIGNUM* p, const BIGNUM* priv_key, const BIGNUM* pub_key, hpre_dh_engine_ctx_t* engine_ctx)
{
    unsigned char* ag_bin = NULL;
    int key_size = engine_ctx->priv_ctx.key_size;

    ag_bin = (unsigned char*)kae_wd_alloc_blk(engine_ctx->qlist->kae_queue_mem_pool, key_size);
    if (!ag_bin) {
        US_ERR("pool alloc ag_bin fail!");
        return -ENOMEM;
    }
    int ret = hpre_dh_fill_g_p_priv_key(g, p, priv_key, engine_ctx, ag_bin);
    if (ret != HPRE_DH_SUCCESS) {
        kae_wd_free_blk(engine_ctx->qlist->kae_queue_mem_pool, ag_bin);
        return ret;
    }

    ret = hpre_dh_fill_pub_key(pub_key, engine_ctx, ag_bin);
    if (ret != HPRE_DH_SUCCESS) {
        return ret;
    }
    engine_ctx->priv_ctx.block_addr = ag_bin;

    return HPRE_DH_SUCCESS;
}

int hpre_dh_genkey(hpre_dh_engine_ctx_t* engine_ctx)
{
    return hpre_internal_do_dh(engine_ctx, WCRYPTO_DH_PHASE1);
}

int hpre_dh_compkey(hpre_dh_engine_ctx_t* engine_ctx)
{
    return hpre_internal_do_dh(engine_ctx, WCRYPTO_DH_PHASE2);
}

int hpre_dh_get_output_chars(hpre_dh_engine_ctx_t* engine_ctx, unsigned char* out)
{
    kae_memcpy(out, engine_ctx->opdata.pri, engine_ctx->opdata.pri_bytes);
    return engine_ctx->opdata.pri_bytes;
}

int hpre_dh_get_pubkey(hpre_dh_engine_ctx_t* engine_ctx, BIGNUM** pubkey)
{
    const unsigned char* pubkey_str = (const unsigned char*)engine_ctx->opdata.pri;
    if (pubkey_str == NULL) {
        return HPRE_DH_FAIL;
    }
    *pubkey = BN_bin2bn(pubkey_str, engine_ctx->opdata.pri_bytes, *pubkey);
    if (*pubkey == NULL) {
        return HPRE_DH_FAIL;
    }

    return HPRE_DH_SUCCESS;
}

void hpre_dh_free_eng_ctx(hpre_dh_engine_ctx_t* eng_ctx)
{
    US_DEBUG("hpre dh free engine ctx start!");
    if (eng_ctx == NULL) {
        US_DEBUG("no eng_ctx to free");
        return;
    }

    if (eng_ctx->qlist != NULL) {
        if (eng_ctx->ctx != NULL) {
            wcrypto_del_dh_ctx(eng_ctx->ctx);
        }
        kae_put_node_to_pool(g_hpre_dh_qnode_pool, eng_ctx->qlist);
    }

    hpre_dh_free_opdata(eng_ctx);

    eng_ctx->priv_ctx.block_addr = NULL;
    eng_ctx->priv_ctx.ssl_alg = NULL;
    eng_ctx->qlist = NULL;
    eng_ctx->ctx = NULL;
    eng_ctx->opdata.pri = NULL;
    eng_ctx->opdata.x_p = NULL;
    eng_ctx->opdata.pv = NULL;
    OPENSSL_free(eng_ctx);
    eng_ctx = NULL;

    return;
}

static int hpre_internal_do_dh(hpre_dh_engine_ctx_t *eng_ctx, enum wcrypto_dh_op_type op_type)
{
    int job_ret;
    op_done_t op_done;

    async_init_op_done(&op_done);

    eng_ctx->opdata.op_type = op_type;
    if (op_done.job != NULL && kae_is_async_enabled()) {
        if (async_setup_async_event_notification(0) == 0) {
            US_ERR("hpre async event notifying failed");
            async_cleanup_op_done(&op_done);
            return HPRE_DH_FAIL;
        }
    } else {
        US_DEBUG("hpre dh no async Job or async disable, back to sync!");
        async_cleanup_op_done(&op_done);
        return hpre_dh_internal_do(eng_ctx->ctx, &eng_ctx->opdata);
    }

    if (hpre_dh_async(eng_ctx, &eng_ctx->opdata, &op_done) == HPRE_DH_FAIL)
        goto err;

    do {
        job_ret = async_pause_job(op_done.job, ASYNC_STATUS_OK);
        if (job_ret == 0) {
            US_DEBUG("- pthread_yidle -");
            kae_pthread_yield();
        }
    }
    while (!op_done.flag ||
            ASYNC_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));

    if (op_done.verifyRst <= 0) {
        US_ERR("hpre dh verify result failed with %d", op_done.verifyRst);
        async_cleanup_op_done(&op_done);
        return HPRE_DH_FAIL;
    }

    async_cleanup_op_done(&op_done);

    US_DEBUG("hpre dh do async job success!");
    return HPRE_DH_SUCCESS;

err:
    US_ERR("hpre dh do async job err");
    (void)async_clear_async_event_notification();
    async_cleanup_op_done(&op_done);
    return HPRE_DH_FAIL;
}

static void hpre_dh_free_opdata(hpre_dh_engine_ctx_t* eng_ctx)
{
    if (eng_ctx->priv_ctx.block_addr != NULL) {
        if (eng_ctx->qlist != NULL) {
            eng_ctx->dh_setup.br.free(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->priv_ctx.block_addr);
        }
    }
}

static hpre_dh_engine_ctx_t* hpre_dh_new_eng_ctx(DH* alg)
{
    hpre_dh_engine_ctx_t* eng_ctx = NULL;
    eng_ctx = (hpre_dh_engine_ctx_t*)OPENSSL_malloc(sizeof(hpre_dh_engine_ctx_t));
    if (eng_ctx == NULL) {
        US_ERR("hpre engine_ctx malloc fail");
        return NULL;
    }
    kae_memset(eng_ctx, 0, sizeof(hpre_dh_engine_ctx_t));

    eng_ctx->priv_ctx.ssl_alg = alg;
    eng_ctx->qlist = kae_get_node_from_pool(g_hpre_dh_qnode_pool);
    if (eng_ctx->qlist == NULL) {
        US_ERR_LIMIT("error. get hardware queue failed");
        OPENSSL_free(eng_ctx);
        eng_ctx = NULL;
        return NULL;
    }
    return eng_ctx;
}

static void hpre_dh_cb(const void *message, void *tag)
{
    if (!message || !tag) {
        US_ERR("hpre cb params err!\n");
        return;
    }
    struct wcrypto_dh_msg *msg = (struct wcrypto_dh_msg *)message;
    hpre_dh_engine_ctx_t *eng_ctx = (hpre_dh_engine_ctx_t *)tag;
    eng_ctx->opdata.pri = msg->out;
    eng_ctx->opdata.pri_bytes = msg->out_bytes;
    eng_ctx->opdata.status = msg->result;
}

static int hpre_dh_init_eng_ctx(hpre_dh_engine_ctx_t* eng_ctx, int bits, bool is_g2)
{
    struct wd_queue* q = eng_ctx->qlist->kae_wd_queue;
    struct wd_queue_mempool* pool = eng_ctx->qlist->kae_queue_mem_pool;

    // this is for ctx is in use.we dont need to re create ctx->ctx again
    if (eng_ctx->ctx) {
        return OPENSSL_SUCCESS;
    }
    if (eng_ctx->ctx == NULL) {
        if (bits == 0) {
            eng_ctx->priv_ctx.key_size = DH_size(eng_ctx->priv_ctx.ssl_alg);
        } else {
            eng_ctx->priv_ctx.key_size = bits >> CHAR_BIT_SIZE;
        }
        eng_ctx->priv_ctx.block_addr = NULL;
        eng_ctx->dh_setup.key_bits = eng_ctx->priv_ctx.key_size << CHAR_BIT_SIZE;
        eng_ctx->dh_setup.cb = hpre_dh_cb;
        eng_ctx->dh_setup.br.alloc = kae_wd_alloc_blk;
        eng_ctx->dh_setup.br.free = kae_wd_free_blk;
        eng_ctx->dh_setup.br.usr = pool;
        eng_ctx->dh_setup.is_g2 = is_g2;
        eng_ctx->ctx = wcrypto_create_dh_ctx(q, &eng_ctx->dh_setup);
        if (eng_ctx->ctx == NULL) {
            US_ERR("create dh ctx fail!");
            return OPENSSL_FAIL;
        }
    }

    return OPENSSL_SUCCESS;
}

static int hpre_dh_set_g(const BIGNUM* g, const int key_size, unsigned char* ag_bin, hpre_dh_engine_ctx_t* engine_ctx)
{
    struct wd_dtb g_dtb;
    __u32 gbytes = BN_bn2bin(g, ag_bin);
    g_dtb.data = (char*)ag_bin;
    g_dtb.bsize = key_size;
    g_dtb.dsize = gbytes;
    int ret = wcrypto_set_dh_g(engine_ctx->ctx, &g_dtb);
    if (ret) {
        US_ERR("wcrypto_set_dh_g fail: %d", ret);
        return HPRE_DH_FAIL;
    }
    return HPRE_DH_SUCCESS;
}

static int hpre_dh_fill_g_p_priv_key(
    const BIGNUM* g, const BIGNUM* p, const BIGNUM* priv_key, hpre_dh_engine_ctx_t* engine_ctx, unsigned char* ag_bin)
{
    unsigned char* apriv_key_bin = NULL;
    unsigned char* ap_bin = NULL;
    int key_size = engine_ctx->priv_ctx.key_size;
    int ret = 0;

    apriv_key_bin = ag_bin + key_size;
    ap_bin = apriv_key_bin + key_size;
    memset(ag_bin, 0, key_size * DH_PARAMS_CNT);

    // construct data block of g
    ret = hpre_dh_set_g(g, key_size, ag_bin, engine_ctx);
    if (ret != HPRE_DH_SUCCESS) {
        return HPRE_DH_FAIL;
    }

    // construct data block of p and private key
    engine_ctx->opdata.pbytes = BN_bn2bin(p, ap_bin);
    engine_ctx->opdata.xbytes = BN_bn2bin(priv_key, apriv_key_bin);

    engine_ctx->opdata.x_p = apriv_key_bin;
    engine_ctx->opdata.pri = ap_bin + key_size;

    return HPRE_DH_SUCCESS;
}

static int hpre_dh_internal_do(void* ctx, struct wcrypto_dh_op_data* opdata)
{
    int ret = wcrypto_do_dh(ctx, opdata, NULL);
    if (ret) {
        US_ERR("wcrypto_do_dh fail: %d", ret);
        return HPRE_DH_FAIL;
    } else if (opdata->pri == NULL) {
        US_ERR("output is empty");
        return HPRE_DH_FAIL;
    } else {
        return HPRE_DH_SUCCESS;
    }
}

static int hpre_dh_fill_pub_key(const BIGNUM* pub_key, hpre_dh_engine_ctx_t* engine_ctx, unsigned char* ag_bin)
{
    engine_ctx->opdata.pvbytes = BN_bn2bin(pub_key, ag_bin);
    engine_ctx->opdata.pv = ag_bin; /* bob's public key here */
    return HPRE_DH_SUCCESS;
}

static int hpre_dh_async(hpre_dh_engine_ctx_t *eng_ctx,
    struct wcrypto_dh_op_data *opdata, op_done_t *op_done)
{
    int ret = 0;
    int cnt = 0;
    enum task_type type = ASYNC_TASK_DH;
    void *tag = eng_ctx;
    do {
        if (cnt > MAX_SEND_TRY_CNTS) {
            break;
        }
        ret = wcrypto_do_dh(eng_ctx->ctx, opdata, tag);
        if (ret == WD_STATUS_BUSY) {
            if ((async_wake_job(op_done->job, ASYNC_STATUS_EAGAIN) == 0 || 
                (async_pause_job(op_done->job, ASYNC_STATUS_EAGAIN) == 0))) {
                US_ERR("hpre wake job or hpre pause job fail!");
                ret = 0;
                break;
            }
            cnt++;
        }
    } while (ret == WD_STATUS_BUSY);

    if (ret != WD_SUCCESS) {
        return HPRE_DH_FAIL;
    }

    if (async_add_poll_task(eng_ctx, op_done, type) == 0) {
        return HPRE_DH_FAIL;
    }

    return HPRE_DH_SUCCESS;
}
