/*
 * Copyright (C) 2019. Huawei Technologies Co., Ltd. All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the zlib License. 
 * You may obtain a copy of the License at
 * 
 *     https://www.zlib.net/zlib_license.html
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * zlib License for more details.
 */

/*****************************************************************************
 * @file kaezip_ctx.h
 *
 * This file provides kaezip ctx control and driver compress funtion;
 *
 *****************************************************************************/

#include "kaezip_ctx.h"
#include "kaezip_common.h"
#include "kaezip_utils.h"
#include "kaezip_log.h"

static KAE_QUEUE_POOL_HEAD_S* g_kaezip_deflate_qp = NULL;
static KAE_QUEUE_POOL_HEAD_S* g_kaezip_inflate_qp = NULL;
static pthread_mutex_t g_kaezip_deflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_kaezip_inflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static KAE_QUEUE_POOL_HEAD_S* kaezip_get_qp(int algtype);
static kaezip_ctx_t* kaezip_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype);
static int kaezip_create_wd_ctx(kaezip_ctx_t *kz_ctx, int alg_comp_type, int comp_optype);
static int kaezip_driver_do_comp_impl(kaezip_ctx_t *kz_ctx);
static void kaezip_set_input_data(kaezip_ctx_t *kz_ctx);
static void kaezip_get_output_data(kaezip_ctx_t *kz_ctx);

void kaezip_free_ctx(void* kz_ctx)
{
    kaezip_ctx_t* kaezip_ctx = (kaezip_ctx_t *)kz_ctx;
    if (kaezip_ctx == NULL) {
        return;
    }

    if (kaezip_ctx->op_data.in && kaezip_ctx->setup.br.usr) {
        kaezip_ctx->setup.br.free(kaezip_ctx->setup.br.usr, (void *)kaezip_ctx->op_data.in); 
        kaezip_ctx->op_data.in = NULL;
    }
    
    if (kaezip_ctx->op_data.out && kaezip_ctx->setup.br.usr) {
        kaezip_ctx->setup.br.free(kaezip_ctx->setup.br.usr, (void *)kaezip_ctx->op_data.out); 
        kaezip_ctx->op_data.out = NULL;
    }

    if (kaezip_ctx->wd_ctx != NULL) {
        wcrypto_del_comp_ctx(kaezip_ctx->wd_ctx);
        kaezip_ctx->wd_ctx = NULL;
    }

    kae_free(kaezip_ctx);

    return;
}

static kaezip_ctx_t* kaezip_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype)
{
    kaezip_ctx_t *kz_ctx = NULL;
    kz_ctx = (kaezip_ctx_t *)kae_malloc(sizeof(kaezip_ctx_t));
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kaezip ctx malloc fail.");
        return NULL;
    }
    memset(kz_ctx, 0, sizeof(kaezip_ctx_t));

    kz_ctx->setup.br.alloc = kaezip_wd_alloc_blk;
    kz_ctx->setup.br.free = kaezip_wd_free_blk;
    kz_ctx->setup.br.iova_map = kaezip_dma_map;
    kz_ctx->setup.br.iova_unmap = kaezip_dma_unmap;
    kz_ctx->setup.br.usr = q_node->kae_queue_mem_pool;

    kz_ctx->op_data.in = kz_ctx->setup.br.alloc(kz_ctx->setup.br.usr, COMP_BLOCK_SIZE); 
    if (kz_ctx->op_data.in == NULL) {
        US_ERR("alloc opdata in buf failed");
        goto err;
    }

    kz_ctx->op_data.out = kz_ctx->setup.br.alloc(kz_ctx->setup.br.usr, COMP_BLOCK_SIZE); 
    if (kz_ctx->op_data.out == NULL) {
        US_ERR("alloc opdata out buf failed");
        goto err;
    }
    
    kz_ctx->q_node = q_node;          
    q_node->priv_ctx = kz_ctx; 

    if (kaezip_create_wd_ctx(kz_ctx, alg_comp_type, comp_optype) == KAEZIP_FAILED) {
        US_ERR("create wd ctx fail!");
        goto err;
    }

    return kz_ctx;
    
err:
    kaezip_free_ctx(kz_ctx);  

    return NULL;
}

static int kaezip_create_wd_ctx(kaezip_ctx_t *kz_ctx, int alg_comp_type, int comp_optype)
{
    if (kz_ctx->wd_ctx != NULL) {
        US_WARN("wd ctx is in used by other comp");
        return KAEZIP_FAILED;
    }

    struct wd_queue *q = kz_ctx->q_node->kae_wd_queue;

    kz_ctx->setup.alg_type  = (enum wcrypto_comp_alg_type)alg_comp_type;
    kz_ctx->setup.op_type = (enum wcrypto_comp_optype)comp_optype;
    kz_ctx->setup.stream_mode = (enum wcrypto_comp_state)WCRYPTO_COMP_STATEFUL;

    kz_ctx->wd_ctx = wcrypto_create_comp_ctx(q, &kz_ctx->setup);
    if (kz_ctx->wd_ctx == NULL) {
        US_ERR("wd create kae comp ctx fail!");
        return KAEZIP_FAILED;
    }

    kz_ctx->comp_alg_type = alg_comp_type;
    kz_ctx->comp_type    = comp_optype;

    return KAEZIP_SUCCESS;
}

kaezip_ctx_t* kaezip_get_ctx(int alg_comp_type, int comp_optype)
{
    KAE_QUEUE_DATA_NODE_S      *q_node = NULL;
    kaezip_ctx_t               *kz_ctx = NULL;

    KAE_QUEUE_POOL_HEAD_S* qp = kaezip_get_qp(comp_optype);
    if(unlikely(!qp)) {
        US_ERR("failed to get hardware queue pool");
        return NULL;
    }

    kaezip_queue_pool_check_and_release(qp, kaezip_free_ctx);

    q_node = kaezip_get_node_from_pool(qp, alg_comp_type, comp_optype);
    if (q_node == NULL) {
        US_ERR("failed to get hardware queue");
        return NULL;
    }

    kz_ctx = (kaezip_ctx_t *)q_node->priv_ctx;
    if (kz_ctx == NULL) {
        kz_ctx = kaezip_new_ctx(q_node, alg_comp_type, comp_optype);
        if (kz_ctx == NULL) {
            US_ERR("kaezip new engine ctx fail!");
            (void)kaezip_put_node_to_pool(qp, q_node);
            return NULL;
        }
    }

    kz_ctx->q_node = q_node;
    kaezip_init_ctx(kz_ctx);

    return kz_ctx;
}

void  kaezip_init_ctx(kaezip_ctx_t* kz_ctx)
{
    if(unlikely(!kz_ctx)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    kz_ctx->in           = NULL;
    kz_ctx->in_len       = 0;   
    kz_ctx->out          = NULL;
    kz_ctx->avail_out    = 0;
    kz_ctx->consumed     = 0;
    kz_ctx->produced     = 0;
    kz_ctx->remain       = 0;

    kz_ctx->header_pos   = 0;
    kz_ctx->flush        = 0;
    kz_ctx->status       = 0;
    
    memset(&kz_ctx->end_block, 0, sizeof(struct wcrypto_end_block));
}

void kaezip_put_ctx(kaezip_ctx_t* kz_ctx)
{
    KAE_QUEUE_DATA_NODE_S* temp = NULL;
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    if (kz_ctx->q_node != NULL) {
        temp = kz_ctx->q_node;
        kz_ctx->q_node = NULL;
        (void)kaezip_put_node_to_pool(kaezip_get_qp(kz_ctx->comp_type), temp);
    }

    kz_ctx = NULL;

    return;
}

static int kaezip_driver_do_comp_impl(kaezip_ctx_t* kz_ctx)
{
    KAEZIP_RETURN_FAIL_IF(kz_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);

    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    int ret = wcrypto_do_comp(kz_ctx->wd_ctx, op_data, NULL);
    if (unlikely(ret < 0)) {
        US_ERR("wd_do_comp fail!");
        return KAEZIP_FAILED;
    }

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    } 

    return KAEZIP_SUCCESS;
}

int kaezip_driver_do_comp(kaezip_ctx_t *kaezip_ctx)
{
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);

    if (kaezip_ctx->remain != 0) {
        return kaezip_get_remain_data(kaezip_ctx);
    }

    if (kaezip_ctx->in_len == 0) {
        US_DEBUG("kaezip do comp impl success, for input len zero, comp type : %s", 
            kaezip_ctx->comp_type == WCRYPTO_DEFLATE ? "deflate" : "inflate");
        return KAEZIP_SUCCESS;
    }

    if (kaezip_ctx->in_len >= KAEZIP_STREAM_CHUNK_IN) {
        kaezip_ctx->do_comp_len = KAEZIP_STREAM_CHUNK_IN;
    } else {
        kaezip_ctx->do_comp_len = kaezip_ctx->in_len;
    }
    
    kaezip_set_input_data(kaezip_ctx);
    int ret = kaezip_driver_do_comp_impl(kaezip_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_DEBUG("kaezip do comp impl success, comp type : %s", 
            kaezip_ctx->comp_type == WCRYPTO_DEFLATE ? "deflate" : "inflate");
        return ret;
    }
    kaezip_get_output_data(kaezip_ctx);

    return KAEZIP_SUCCESS;
}

static void kaezip_set_input_data(kaezip_ctx_t *kz_ctx)
{
    kz_ctx->op_data.in_len = 0;

    memcpy((uint8_t *)kz_ctx->op_data.in, kz_ctx->in, kz_ctx->do_comp_len);
    kz_ctx->op_data.in_len += kz_ctx->do_comp_len;
    kz_ctx->op_data.avail_out = KAEZIP_STREAM_CHUNK_OUT;
    kz_ctx->op_data.flush   = kz_ctx->flush;
    kz_ctx->op_data.alg_type = kz_ctx->comp_alg_type;

    if (kz_ctx->status == KAEZIP_COMP_INIT || kz_ctx->status == KAEZIP_DECOMP_INIT) {
        kz_ctx->op_data.stream_pos = WCRYPTO_COMP_STREAM_NEW;
    }
}

static void kaezip_set_comp_status(kaezip_ctx_t *kz_ctx)
{
    if (kz_ctx->comp_type == WCRYPTO_INFLATE) {
        switch (kz_ctx->op_data.status) {
            case WCRYPTO_DECOMP_END:
                kz_ctx->status = (kz_ctx->remain == 0 ? KAEZIP_DECOMP_END : KAEZIP_DECOMP_END_BUT_DATAREMAIN);
                break;
            case WCRYPTO_STATUS_NULL:
                kz_ctx->status = KAEZIP_DECOMP_DOING;
                break;
            case WD_VERIFY_ERR:
                kz_ctx->status = KAEZIP_DECOMP_VERIFY_ERR;
                break;   
            default:
                kz_ctx->status = KAEZIP_DECOMP_DOING;
                break;
        }
    } else {
        switch (kz_ctx->op_data.status) {
            case WCRYPTO_STATUS_NULL:
                if (kz_ctx->in_len > kz_ctx->consumed) {
                    kz_ctx->status = KAEZIP_COMP_DOING;
                    break;
                }

                if (kz_ctx->flush != WCRYPTO_FINISH) {
                    kz_ctx->status = KAEZIP_COMP_CRC_UNCHECK;
                    break;
                }

                if (kz_ctx->remain != 0) {
                    kz_ctx->status = KAEZIP_COMP_END_BUT_DATAREMAIN;
                } else {
                    kz_ctx->status = KAEZIP_COMP_END;
                }
                break;
            case WD_VERIFY_ERR:
                kz_ctx->status = KAEZIP_COMP_VERIFY_ERR;
                break;   
            default:
                kz_ctx->status = KAEZIP_COMP_DOING;
                break;
        }
    }
}

static void kaezip_get_output_data(kaezip_ctx_t *kz_ctx)
{
    kz_ctx->consumed = kz_ctx->op_data.consumed;

    if (kz_ctx->avail_out < kz_ctx->op_data.produced) {
        kz_ctx->produced = kz_ctx->avail_out;
        kz_ctx->remain = kz_ctx->op_data.produced - kz_ctx->produced;
    } else {
        kz_ctx->produced = kz_ctx->op_data.produced;
    }

    memcpy(kz_ctx->out, (uint8_t*)kz_ctx->op_data.out, kz_ctx->produced);

    kaezip_set_comp_status(kz_ctx);
}

static void kaezip_state_machine_trans(kaezip_ctx_t *kz_ctx)
{
    if (kz_ctx->comp_type == WCRYPTO_INFLATE) {
        switch (kz_ctx->status) {
            case KAEZIP_DECOMP_INIT:               // fall-through, trans to next state
                kz_ctx->status = KAEZIP_DECOMP_DOING;
            case KAEZIP_DECOMP_DOING:
                break;
            case KAEZIP_DECOMP_END_BUT_DATAREMAIN: // fall-through, trans to next state
                kz_ctx->status = (kz_ctx->remain == 0 ? KAEZIP_DECOMP_END : KAEZIP_DECOMP_END_BUT_DATAREMAIN);
            case KAEZIP_DECOMP_END:
                break;
            case KAEZIP_DECOMP_VERIFY_ERR:
                US_ERR("kaezip inflate verify err");
                break;
            default:
                kz_ctx->status = KAEZIP_DECOMP_DOING;
                break;
        }
    } else {
        switch (kz_ctx->status) {
            case KAEZIP_COMP_INIT:                  // fall-through, trans to next state
                kz_ctx->status = KAEZIP_COMP_DOING;
            case KAEZIP_COMP_DOING:                 // fall-through, trans to next state
                kz_ctx->status = KAEZIP_COMP_CRC_UNCHECK;
            case KAEZIP_COMP_CRC_UNCHECK:
                if (kz_ctx->remain == 0 && kz_ctx->flush == WCRYPTO_FINISH && kz_ctx->in_len == 0) {
                    kaezip_deflate_addcrc(kz_ctx);
                    kz_ctx->status = (kz_ctx->end_block.remain == 0 ? KAEZIP_COMP_END : KAEZIP_COMP_END_BUT_DATAREMAIN);
                }
                break;
            case KAEZIP_COMP_END_BUT_DATAREMAIN:    // fall-through, trans to next state
                kz_ctx->status = (kz_ctx->remain == 0 ? KAEZIP_COMP_END : KAEZIP_COMP_END_BUT_DATAREMAIN);
            case KAEZIP_COMP_END:
                break;
            case KAEZIP_COMP_VERIFY_ERR:
                US_ERR("kaezip deflate verify err");
                break;
            default:
                kz_ctx->status = KAEZIP_COMP_DOING;
                break;
        }
    }
}

int kaezip_get_remain_data(kaezip_ctx_t *kz_ctx)
{
    KAEZIP_RETURN_FAIL_IF(kz_ctx->op_data.produced < kz_ctx->remain, "wrong remain data", KAEZIP_FAILED);
    int data_begin = kz_ctx->op_data.produced - kz_ctx->remain;

    if (kz_ctx->remain < kz_ctx->avail_out) {
        kz_ctx->produced = kz_ctx->remain;
        memcpy(kz_ctx->out, (uint8_t*)kz_ctx->op_data.out + data_begin, kz_ctx->produced);
        kz_ctx->remain = 0;
    } else {
        kz_ctx->produced = kz_ctx->avail_out;
        memcpy(kz_ctx->out, (uint8_t*)kz_ctx->op_data.out + data_begin, kz_ctx->produced);
        kz_ctx->remain -= kz_ctx->produced;
    }

    kaezip_state_machine_trans(kz_ctx);

    return KAEZIP_SUCCESS;
}

static KAE_QUEUE_POOL_HEAD_S* kaezip_get_qp(int algtype)
{
    if ((algtype != WCRYPTO_DEFLATE) && (algtype != WCRYPTO_INFLATE) ) {
        US_ERR("kaezip get q pool failed, not a support algtye %d!", algtype);
        return NULL;
    }

    if (algtype == WCRYPTO_DEFLATE) {
        if (g_kaezip_deflate_qp) {
            return g_kaezip_deflate_qp;
        }
        pthread_mutex_lock(&g_kaezip_deflate_pool_init_mutex);
        if (g_kaezip_deflate_qp != NULL) {
            pthread_mutex_unlock(&g_kaezip_deflate_pool_init_mutex);
            return g_kaezip_deflate_qp;
        }
        kaezip_queue_pool_destroy(g_kaezip_deflate_qp, kaezip_free_ctx);
        g_kaezip_deflate_qp = kaezip_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaezip_deflate_pool_init_mutex);

        return g_kaezip_deflate_qp == NULL ? NULL : g_kaezip_deflate_qp;
    } else {
        if (g_kaezip_inflate_qp) {
            return g_kaezip_inflate_qp;
        }
        pthread_mutex_lock(&g_kaezip_inflate_pool_init_mutex);
        if (g_kaezip_inflate_qp != NULL) {
            pthread_mutex_unlock(&g_kaezip_inflate_pool_init_mutex);
            return g_kaezip_inflate_qp;
        }
        kaezip_queue_pool_destroy(g_kaezip_inflate_qp, kaezip_free_ctx);
        g_kaezip_inflate_qp = kaezip_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaezip_inflate_pool_init_mutex);
        
        return g_kaezip_inflate_qp == NULL ? NULL : g_kaezip_inflate_qp;
    }
    
    return NULL;
}
