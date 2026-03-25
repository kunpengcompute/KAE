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
#include "uadk/v1/wd_sgl.h"

static KAE_QUEUE_POOL_HEAD_S* g_kaezip_deflate_qp = NULL;
static KAE_QUEUE_POOL_HEAD_S* g_kaezip_inflate_qp = NULL;
static pthread_mutex_t g_kaezip_deflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_kaezip_inflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static KAE_QUEUE_POOL_HEAD_S* kaezip_get_qp(int algtype);
static kaezip_ctx_t *kaezip_new_ctx(struct kaezip_instance *instance, int alg_comp_type, int comp_optype, int is_sgl);
static int kaezip_create_wd_ctx(struct kaezip_instance *instance, int alg_comp_type, int comp_optype, operation_mode mode);
static int kaezip_driver_do_comp_impl(kaezip_ctx_t *kz_ctx);
static int kaezip_set_comp_input_data(kaezip_ctx_t *kz_ctx);
static void kaezip_get_buffer_remain_data(kaezip_ctx_t *kz_ctx);
static void kaezip_get_comp_output_data(kaezip_ctx_t *kz_ctx);
static void kaezip_get_decomp_output_data(kaezip_ctx_t *kz_ctx);
static void kaezip_prepare_fork(void);
static void kaezip_parent_fork(void);
static void kaezip_child_fork(void);
static void kaezip_free_instance(void *arg);

__attribute__((constructor))
static void kaezip_register_fork_handlers(void) {
    pthread_atfork(kaezip_prepare_fork, kaezip_parent_fork, kaezip_child_fork);
}

static void kaezip_prepare_fork(void) {
    pthread_mutex_lock(&g_kaezip_deflate_pool_init_mutex);
    pthread_mutex_lock(&g_kaezip_inflate_pool_init_mutex);
    if (g_kaezip_deflate_qp) {
        kaezip_queue_pool_destroy(g_kaezip_deflate_qp, kaezip_free_instance);
        g_kaezip_deflate_qp = NULL;
    }
    
    if (g_kaezip_inflate_qp) {
        kaezip_queue_pool_destroy(g_kaezip_inflate_qp, kaezip_free_instance);
        g_kaezip_inflate_qp = NULL;
    }
}

static void kaezip_parent_fork(void) {
    pthread_mutex_unlock(&g_kaezip_inflate_pool_init_mutex);
    pthread_mutex_unlock(&g_kaezip_deflate_pool_init_mutex);
}

static void kaezip_child_fork(void) {
    pthread_mutex_init(&g_kaezip_deflate_pool_init_mutex, NULL);
    pthread_mutex_init(&g_kaezip_inflate_pool_init_mutex, NULL);
    
    pthread_mutex_unlock(&g_kaezip_inflate_pool_init_mutex);
    pthread_mutex_unlock(&g_kaezip_deflate_pool_init_mutex);
}

int kaezip_get_win_size(void)
{
    char *env_str = getenv("KAE_ZLIB_WINTYPE");
    if (env_str == NULL) {
        US_DEBUG("KAE_ZLIB_WINTYPE is NULL, use default winsize 8\n");
        return WCRYPTO_COMP_WS_8K;
    }
    int winsize = atoi(env_str);

    int wintype = 0;

    switch (winsize) {
	case 4:
		wintype = WCRYPTO_COMP_WS_4K;
		break;
	case 8:
		wintype = WCRYPTO_COMP_WS_8K;
		break;
	case 16:
		wintype = WCRYPTO_COMP_WS_16K;
		break;
    case 24:
		wintype = WCRYPTO_COMP_WS_24K;
		break;
    case 32:
		wintype = WCRYPTO_COMP_WS_32K;
		break;
	default:
		wintype = WCRYPTO_COMP_WS_32K;
        US_DEBUG("KAE_ZLIB_WINTYPE value out of range ：%d ,use default winsize 32", winsize);
        break;
	}

    US_DEBUG("KAE_ZLIB_WINTYPE wintype is ：%d ", wintype);
    return wintype;
}

static void kaezip_free_kz_ctx(void* kz_ctx)
{
    kaezip_ctx_t* kaezip_ctx = (kaezip_ctx_t *)kz_ctx;
    if (kaezip_ctx == NULL) {
        return;
    }

    if (!kaezip_ctx->q_node->is_sgl) {
        if (kaezip_ctx->op_data.in && kaezip_ctx->setup.br.usr) {
            kaezip_ctx->setup.br.free(kaezip_ctx->setup.br.usr, (void *)kaezip_ctx->op_data.in);
            kaezip_ctx->op_data.in = NULL;
        }
        if (kaezip_ctx->op_data.out && kaezip_ctx->setup.br.usr) {
            kaezip_ctx->setup.br.free(kaezip_ctx->setup.br.usr, (void *)kaezip_ctx->op_data.out);
            kaezip_ctx->op_data.out = NULL;
        }
    }

    kae_free(kaezip_ctx);

    return;
}

static kaezip_ctx_t *kaezip_new_ctx(struct kaezip_instance *instance,
                                    int alg_comp_type, int comp_optype, int is_sgl)
{
    kaezip_ctx_t *kz_ctx = NULL;
    kz_ctx = (kaezip_ctx_t *)kae_malloc(sizeof(kaezip_ctx_t));
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kaezip ctx malloc fail.");
        return NULL;
    }
    memset(kz_ctx, 0, sizeof(kaezip_ctx_t));

    kz_ctx->setup = instance->setup;
    kz_ctx->comp_alg_type = alg_comp_type;
    kz_ctx->comp_type     = comp_optype;
    kz_ctx->q_node = instance->q_node;
    kz_ctx->wd_ctx = instance->wd_ctx;

    if (is_sgl) {
        // in 以及 out 均为 SGL
        kz_ctx->op_data.in = (void *)kz_ctx->src_sgl_buf;
        kz_ctx->op_data.out = (void *)kz_ctx->dst_sgl_buf;
    } else {
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
        kz_ctx->op_data.avail_out = KAEZIP_STREAM_CHUNK_OUT;
    }

    return kz_ctx;

err:
    kaezip_free_kz_ctx(kz_ctx);

    return NULL;
}

static void kaezip_callback(const void *msg, void *tag)
{
    const struct wcrypto_comp_msg *respmsg = msg;
    kaezip_ctx_t *kz_ctx = (kaezip_ctx_t *)tag;
    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    op_data->consumed   = respmsg->in_cons;
    op_data->produced   = respmsg->produced;
    op_data->status     = respmsg->status;
    op_data->stream_pos = respmsg->stream_pos;
    op_data->flush      = respmsg->flush_type;
    op_data->isize      = respmsg->isize;
    op_data->checksum   = respmsg->checksum;

    if (kz_ctx->callback)
        kz_ctx->callback(respmsg->status, kz_ctx->param);

    return;
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
    kz_ctx->buffer_len   = 0;
    kz_ctx->buffer_remain = 0;

    kz_ctx->header_pos   = 0;
    kz_ctx->flush        = 0;
    kz_ctx->status       = 0;
    kz_ctx->callback     = NULL;
    kz_ctx->param        = NULL;

    memset(&kz_ctx->end_block, 0, sizeof(struct wcrypto_end_block));
}

static int kaezip_driver_do_comp_impl(kaezip_ctx_t* kz_ctx)
{
    KAEZIP_RETURN_FAIL_IF(kz_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);

    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    int ret = wcrypto_do_comp(kz_ctx->wd_ctx, op_data, NULL);
    if (unlikely(ret < 0)) {
        US_ERR("wd_do_comp fail! ret = %d", ret);
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

    if (kaezip_ctx->in_len == 0 && kaezip_ctx->buffer_len == 0) {
        US_DEBUG("kaezip do comp impl success, for input len zero and no remained, comp type : deflate");
        return KAEZIP_SUCCESS;
    }

    int ret = kaezip_set_comp_input_data(kaezip_ctx);
    if (ret == KAEZIP_SAVE_DATA_TO_BUFFER) {
        kaezip_ctx->consumed = kaezip_ctx->in_len;
        kaezip_ctx->produced = 0;
        return KAEZIP_SUCCESS;
    }

    US_DEBUG("kaezip driver do comp task, input length is %uB, buffer remain %uB",
        kaezip_ctx->op_data.in_len, kaezip_ctx->buffer_remain);
    ret = kaezip_driver_do_comp_impl(kaezip_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_DEBUG("kaezip do comp impl fail, comp type : deflate");
        return ret;
    }
    kaezip_get_buffer_remain_data(kaezip_ctx);
    kaezip_get_comp_output_data(kaezip_ctx);

    return KAEZIP_SUCCESS;
}

static int kaezip_set_comp_input_data(kaezip_ctx_t *kz_ctx)
{
    memcpy(kz_ctx->op_data.in + kz_ctx->buffer_len, kz_ctx->in, kz_ctx->in_len);
    kz_ctx->buffer_len += kz_ctx->in_len;
    US_DEBUG("kaezip save %uB input data to buffer, buffer len is %uB now",
            kz_ctx->in_len, kz_ctx->buffer_len);

    if ((kz_ctx->buffer_len >= KAEZIP_STREAM_CHUNK_IN) || (kz_ctx->zflush != 0 /* Z_NO_FLUSH */)) {
        if (unlikely((kz_ctx->buffer_len < 4) && (kz_ctx->flush == WCRYPTO_SYNC_FLUSH))) {
            //  非尾包小于4Byte, 即使flush要求刷新, 也不下发
            return KAEZIP_SAVE_DATA_TO_BUFFER;
        } else if (kz_ctx->flush == WCRYPTO_FINISH) {
            //  尾包没有4Byte对齐约束, 直接下发即可
            kz_ctx->buffer_remain = 0;
        } else {
            //  非尾包, 按4Byte的倍数进行切分, 剩余的长度记录在buffer_remain
            kz_ctx->buffer_remain = kz_ctx->buffer_len & 0x3;
            kz_ctx->buffer_len   -= kz_ctx->buffer_remain;
        }

        kz_ctx->op_data.in_len    = kz_ctx->buffer_len;
        kz_ctx->op_data.flush     = kz_ctx->flush;
        kz_ctx->op_data.alg_type  = kz_ctx->comp_alg_type;

        if (kz_ctx->status == KAEZIP_COMP_INIT) {
            kz_ctx->op_data.stream_pos = WCRYPTO_COMP_STREAM_NEW;
        }
        return KAEZIP_DRIVER_DO_TASK_NOW;
    }
    return KAEZIP_SAVE_DATA_TO_BUFFER;
}

static void kaezip_set_decomp_input_data(kaezip_ctx_t *kz_ctx)
{
    memcpy((uint8_t *)kz_ctx->op_data.in, kz_ctx->in, kz_ctx->in_len);
    kz_ctx->op_data.in_len = kz_ctx->in_len;
    kz_ctx->op_data.flush   = kz_ctx->flush;
    kz_ctx->op_data.alg_type = kz_ctx->comp_alg_type;

    if (kz_ctx->status == KAEZIP_DECOMP_INIT) {
        kz_ctx->op_data.stream_pos = WCRYPTO_COMP_STREAM_NEW;
    }
}

int kaezip_driver_do_decomp(kaezip_ctx_t *kaezip_ctx)
{
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);

    if (kaezip_ctx->remain != 0) {
        return kaezip_get_remain_data(kaezip_ctx);
    }

    if (kaezip_ctx->in_len == 0) {
        US_DEBUG("kaezip do comp impl success, for input len zero, comp type : inflate");
        return KAEZIP_SUCCESS;
    }

    kaezip_set_decomp_input_data(kaezip_ctx);
    int ret = kaezip_driver_do_comp_impl(kaezip_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_DEBUG("kaezip do comp impl success, comp type : inflate");
        return ret;
    }
    kaezip_get_decomp_output_data(kaezip_ctx);

    return KAEZIP_SUCCESS;
}

void kaezip_set_comp_status(kaezip_ctx_t *kz_ctx)
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
            case WCRYPTO_DECOMP_NO_CRC:
                kz_ctx->status = (kz_ctx->remain == 0 ?
                    KAEZIP_DECOMP_NO_CRC :
                    KAEZIP_DECOMP_NO_CRC_BUT_DATAREMAIN);
                break;
            case WCRYPTO_DECOMP_BLK_NOSTART:
                kz_ctx->status = (kz_ctx->remain == 0 ?
                    KAEZIP_DECOMP_BLK_NOSTART :
                    KAEZIP_DECOMP_BLK_NOSTART_BUT_DATAREMAIN);
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

//  buffer切分为4Byte倍数下发后, 将尾部余下的字节搬运到头部
static void kaezip_get_buffer_remain_data(kaezip_ctx_t *kz_ctx)
{
    memcpy(kz_ctx->op_data.in, kz_ctx->op_data.in + kz_ctx->buffer_len, kz_ctx->buffer_remain);
    kz_ctx->buffer_len = kz_ctx->buffer_remain;
    kz_ctx->buffer_remain = 0;
}

static void kaezip_get_decomp_output_data(kaezip_ctx_t *kz_ctx)
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

static void kaezip_get_comp_output_data(kaezip_ctx_t *kz_ctx)
{
    kz_ctx->consumed = kz_ctx->in_len;

    if (kz_ctx->avail_out < kz_ctx->op_data.produced) {
        kz_ctx->produced = kz_ctx->avail_out;
        kz_ctx->remain = kz_ctx->op_data.produced - kz_ctx->produced;
    } else {
        kz_ctx->produced = kz_ctx->op_data.produced;
    }
    memcpy(kz_ctx->out, kz_ctx->op_data.out, kz_ctx->produced);

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
            case KAEZIP_DECOMP_NO_CRC:
                break;
            case KAEZIP_DECOMP_NO_CRC_BUT_DATAREMAIN:
                kz_ctx->status = (kz_ctx->remain == 0 ? 
                    KAEZIP_DECOMP_NO_CRC : 
                    KAEZIP_DECOMP_NO_CRC_BUT_DATAREMAIN);
                break;
            case KAEZIP_DECOMP_BLK_NOSTART_BUT_DATAREMAIN:
                kz_ctx->status = (kz_ctx->remain == 0 ? 
                    KAEZIP_DECOMP_BLK_NOSTART : 
                    KAEZIP_DECOMP_BLK_NOSTART_BUT_DATAREMAIN);
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

static int kaezip_create_wd_ctx(struct kaezip_instance *instance, int alg_comp_type, int comp_optype, operation_mode mode)
{
    if (instance->wd_ctx != NULL) {
        US_WARN("wd ctx is in used by other comp");
        return KAEZIP_FAILED;
    }

    struct wd_queue *q = instance->q_node->kae_wd_queue;

    instance->setup.alg_type  = (enum wcrypto_comp_alg_type)alg_comp_type;
    instance->setup.op_type = (enum wcrypto_comp_optype)comp_optype;

    if (mode == SYNC_MODE) {
        instance->setup.stream_mode = (enum wcrypto_comp_state)WCRYPTO_COMP_STATEFUL;
    } else {
        // ASYNC_MODE only support stateless
        instance->setup.stream_mode = (enum wcrypto_comp_state)WCRYPTO_COMP_STATELESS;
    }

    if (instance->q_node->is_sgl) {
        instance->setup.data_fmt = WD_SGL_BUF;
    }

    instance->wd_ctx = wcrypto_create_comp_ctx(q, &instance->setup);
    if (instance->wd_ctx == NULL) {
        US_ERR("wd create kae comp ctx fail!");
        return KAEZIP_FAILED;
    }

    return KAEZIP_SUCCESS;
}

static struct kaezip_instance *kaezip_new_instance(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype,
                                                    int win_size, int is_sgl, operation_mode mode)
{
    struct kaezip_instance *instance = (struct kaezip_instance *)kae_malloc(sizeof(struct kaezip_instance));

    if (instance == NULL) {
        US_ERR("failed to alloc kaelz4 instance");
        return NULL;
    }

    memset(instance, 0, sizeof(struct kaezip_instance));

    instance->q_node = q_node;
    instance->total_num = (mode == SYNC_MODE ? 1 : MAX_KAE_CTX_DEPTH);
    instance->setup.win_size = win_size;
    instance->setup.br.usr = q_node->kae_queue_mem_pool;
    instance->setup.cb = kaezip_callback;

    if (is_sgl) {
        instance->setup.br.alloc = kaezip_wd_alloc_sgl;
        instance->setup.br.free = kaezip_wd_free_sgl;
        instance->setup.br.iova_map = kaezip_dma_map_sgl;
        instance->setup.br.iova_unmap = kaezip_dma_unmap_sgl;
    } else {
        instance->setup.br.alloc = kaezip_wd_alloc_blk;
        instance->setup.br.free = kaezip_wd_free_blk;
        instance->setup.br.iova_map = kaezip_dma_map;
        instance->setup.br.iova_unmap = kaezip_dma_unmap;
    }

    if (kaezip_create_wd_ctx(instance, alg_comp_type, comp_optype, mode) == KAEZIP_FAILED) {
        US_ERR("create wd ctx fail!");
        kae_free(instance);
        return NULL;
    }
    return instance;
}

static void kaezip_free_instance(void *arg)
{
    struct kaezip_instance *instance = arg;

    for (int i = 0; i < instance->total_num; i++) {
        if (instance->kz_ctx[i]) {
            kaezip_free_kz_ctx(instance->kz_ctx[i]);
            instance->kz_ctx[i] = NULL;
        }
    }

    if (instance->wd_ctx != NULL) {
        wcrypto_del_comp_ctx(instance->wd_ctx);   // scy: TBM
        instance->wd_ctx = NULL;
    }

    kae_free(instance);
}

#define COMP_OPTYPE_NUM (2)
__thread struct kaezip_instance *g_cur_instance[COMP_OPTYPE_NUM];
kaezip_ctx_t* kaezip_get_ctx(int alg_comp_type, int comp_optype, int win_size, int is_sgl, const device_config_t *config, operation_mode mode)
{
    KAE_QUEUE_DATA_NODE_S      *q_node = NULL;
    kaezip_ctx_t               *kz_ctx = NULL;
    KAE_QUEUE_POOL_HEAD_S* qp = kaezip_get_qp(comp_optype);
    struct kaezip_instance *cur_instance = g_cur_instance[comp_optype % COMP_OPTYPE_NUM];

    if(unlikely(!qp)) {
        US_ERR("failed to get hardware queue pool");
        return NULL;
    }

    // check cur_instance
    if (cur_instance == NULL || cur_instance->q_node->comp_alg_type != alg_comp_type \
        || cur_instance->q_node->win_size != win_size || cur_instance->q_node->is_sgl != is_sgl) {
        q_node = kaezip_get_node_from_pool(qp, alg_comp_type, comp_optype, win_size, is_sgl, config, mode);
        if (q_node == NULL) {
            kaezip_queue_pool_check_and_release(qp, kaezip_free_instance);
            q_node = kaezip_get_node_from_pool(qp, alg_comp_type, comp_optype, win_size, is_sgl, config, mode);

            if (q_node == NULL) {
                kae_free(cur_instance);
                US_ERR("failed to get hardware queue");
                return NULL;
            }
        }

        if (q_node->priv_ctx == NULL) {
            cur_instance = kaezip_new_instance(q_node, alg_comp_type, comp_optype, win_size, is_sgl, mode);
            if (cur_instance == NULL) {
                US_ERR("create instance fail!");
                (void)kaezip_put_node_to_pool(qp, q_node, kaezip_free_instance);
                return NULL;
            }
            q_node->priv_ctx = cur_instance;
        } else {
            cur_instance = q_node->priv_ctx;
        }
        g_cur_instance[comp_optype % COMP_OPTYPE_NUM] = cur_instance;
    } else {
        q_node = cur_instance->q_node;
    }

    kz_ctx = cur_instance->kz_ctx[cur_instance->cur_idx];
    if (kz_ctx == NULL) {
        kz_ctx = kaezip_new_ctx(cur_instance, alg_comp_type, comp_optype, is_sgl);
        if (kz_ctx == NULL) {
            if (cur_instance->cur_idx == 0) {
                (void)kaezip_put_node_to_pool(qp, q_node, kaezip_free_instance);
            }
            g_cur_instance[comp_optype % COMP_OPTYPE_NUM] = NULL;
            return NULL;
        }
        cur_instance->kz_ctx[cur_instance->cur_idx] = kz_ctx;
    }

    kaezip_init_ctx(kz_ctx);
    kz_ctx->index = cur_instance->cur_idx;
    cur_instance->cur_idx++;
    if (cur_instance->cur_idx == cur_instance->total_num) {
        g_cur_instance[comp_optype % COMP_OPTYPE_NUM] = NULL;
    }

    return kz_ctx;
}

void kaezip_put_ctx(kaezip_ctx_t* kz_ctx)
{
    KAE_QUEUE_DATA_NODE_S* temp = NULL;
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    if (kz_ctx->q_node != NULL) {
        struct kaezip_instance *instance = (struct kaezip_instance *)kz_ctx->q_node->priv_ctx;

        temp = kz_ctx->q_node;
        instance->free_num++;
        if (instance->free_num == instance->cur_idx) {
            (void)kaezip_put_node_to_pool(kaezip_get_qp(kz_ctx->comp_type), temp, kaezip_free_instance);
            instance->cur_idx = 0;
            instance->free_num = 0;
            if (instance == g_cur_instance[kz_ctx->comp_type % COMP_OPTYPE_NUM]) {
                g_cur_instance[kz_ctx->comp_type % COMP_OPTYPE_NUM] = NULL;
            }
        }
    }

    kz_ctx = NULL;

    return;
}

void kaezip_free_ctx(kaezip_ctx_t* kz_ctx)
{
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    struct kaezip_instance *instance = (struct kaezip_instance *)kz_ctx->q_node->priv_ctx;
    KAE_QUEUE_DATA_NODE_S *q_node = kz_ctx->q_node;
    int comp_optype = kz_ctx->comp_type % COMP_OPTYPE_NUM;

    if (kz_ctx->q_node->is_sgl) {
        if (kz_ctx->src_sgl) {
            wd_destory_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->src_sgl);
            kz_ctx->src_sgl = NULL;
        }
        if (kz_ctx->dst_sgl_usr) {
            wd_destory_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->dst_sgl_usr);
            kz_ctx->dst_sgl_usr = NULL;
        }
    }
    instance->kz_ctx[kz_ctx->index] = NULL;
    kaezip_free_kz_ctx(kz_ctx);

    instance->free_num++;
    if (instance->free_num == instance->cur_idx) {
        kaezip_free_wd_queue_memory(q_node, kaezip_free_instance);
        if (instance == g_cur_instance[comp_optype]) {
            g_cur_instance[comp_optype] = NULL;
        }
    }
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
        kaezip_queue_pool_destroy(g_kaezip_deflate_qp, kaezip_free_instance);
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
        kaezip_queue_pool_destroy(g_kaezip_inflate_qp, kaezip_free_instance);
        g_kaezip_inflate_qp = kaezip_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaezip_inflate_pool_init_mutex);

        return g_kaezip_inflate_qp == NULL ? NULL : g_kaezip_inflate_qp;
    }

    return NULL;
}
