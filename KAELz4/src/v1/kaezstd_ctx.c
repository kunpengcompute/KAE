/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd ctx func
 * @Author: LiuYongYang
 * @Date: 2024-02-23
 * @LastEditTime: 2024-03-28
 */
#include "kaezstd_ctx.h"
#include "kaelz4_utils.h"
#include "kaelz4_log.h"

static KAE_QUEUE_POOL_HEAD_S* g_kaezstd_deflate_qp = NULL;
static KAE_QUEUE_POOL_HEAD_S* g_kaezstd_inflate_qp = NULL;
static pthread_mutex_t g_kaezstd_deflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_kaezstd_inflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static KAE_QUEUE_POOL_HEAD_S* kaezstd_get_qp(int algtype);
static kaezstd_ctx_t* kaezstd_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype);
static int kaezstd_create_wd_ctx(kaezstd_ctx_t *kz_ctx, int alg_comp_type, int comp_optype);
static int kaezstd_driver_do_comp_impl(kaezstd_ctx_t *kz_ctx);

void kaezstd_free_ctx(void* kz_ctx)
{
    kaezstd_ctx_t* kaezstd_ctx = (kaezstd_ctx_t *)kz_ctx;
    if (kaezstd_ctx == NULL) {
        return;
    }

    if (kaezstd_ctx->op_data.in && kaezstd_ctx->setup.br.usr) {
        kaezstd_ctx->setup.br.free(kaezstd_ctx->setup.br.usr, (void *)kaezstd_ctx->op_data.in);
        kaezstd_ctx->op_data.in = NULL;
    }

    if (kaezstd_ctx->op_data.out && kaezstd_ctx->setup.br.usr) {
        kaezstd_ctx->setup.br.free(kaezstd_ctx->setup.br.usr, (void *)kaezstd_ctx->op_data.out);
        kaezstd_ctx->op_data.out = NULL;
    }

    if (kaezstd_ctx->wd_ctx != NULL) {
        wcrypto_del_comp_ctx(kaezstd_ctx->wd_ctx);
        kaezstd_ctx->wd_ctx = NULL;
    }

    kae_free(kaezstd_ctx);

    return;
}

static int kaezstd_get_comp_lv()
{
    char *zstd_str = getenv("KAE_ZSTD_COMP_TYPE");
    if (zstd_str == NULL) {
        US_DEBUG("KAE_ZSTD_COMP_TYPE is NULL, use default lv 8\n");
        return 8;
    }
    int zstd_val = atoi(zstd_str);
    if (zstd_val != 8 && zstd_val != 9) {
        US_DEBUG("KAE_ZSTD_COMP_TYPE value out of range ：%d ,use default lv 8", zstd_val);
        return 8;
    }
    US_DEBUG("KAE_ZSTD_COMP_TYPE value is ：%d ", zstd_val);
    return zstd_val;
}

static int kaezstd_get_win_size()
{
    char *zstd_str = getenv("KAE_ZSTD_WINTYPE");
    if (zstd_str == NULL) {
        US_DEBUG("KAE_ZSTD_WINTYPE is NULL, use default winsize 32\n");
        return 16;
    }
    int winsize = atoi(zstd_str);

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
        US_DEBUG("KAE_ZSTD_WINTYPE value out of range ：%d ,use default winsize 32", winsize);
        break;
	}

    US_DEBUG("KAE_ZSTD_WINTYPE wintype is ：%d ", wintype);
    return wintype;
}

static kaezstd_ctx_t* kaezstd_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype)
{
    kaezstd_ctx_t *kz_ctx = NULL;
    kz_ctx = (kaezstd_ctx_t *)kae_malloc(sizeof(kaezstd_ctx_t));
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kaezip ctx malloc fail.");
        return NULL;
    }
    memset(kz_ctx, 0, sizeof(kaezstd_ctx_t));

    kz_ctx->setup.comp_lv = kaezstd_get_comp_lv();
    kz_ctx->setup.win_size  = kaezstd_get_win_size();
    kz_ctx->setup.win_size = WCRYPTO_COMP_WS_16K;
    kz_ctx->setup.br.alloc = kaezstd_wd_alloc_blk;
    kz_ctx->setup.br.free = kaezstd_wd_free_blk;
    kz_ctx->setup.br.iova_map = kaezstd_dma_map;
    kz_ctx->setup.br.iova_unmap = kaezstd_dma_unmap;
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

    kz_ctx->op_data.priv = &kz_ctx->zstd_data;
    kz_ctx->q_node = q_node;
    q_node->priv_ctx = kz_ctx;

    if (kaezstd_create_wd_ctx(kz_ctx, alg_comp_type, comp_optype) == KAEZIP_FAILED) {
        US_ERR("create wd ctx fail!");
        goto err;
    }

    return kz_ctx;

err:
    kaezstd_free_ctx(kz_ctx);

    return NULL;
}

static int kaezstd_create_wd_ctx(kaezstd_ctx_t *kz_ctx, int alg_comp_type, int comp_optype)
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
    kz_ctx->comp_type     = comp_optype;

    return KAEZIP_SUCCESS;
}

kaezstd_ctx_t* kaezstd_get_ctx(int alg_comp_type, int comp_optype)
{
    KAE_QUEUE_DATA_NODE_S      *q_node = NULL;
    kaezstd_ctx_t               *kz_ctx = NULL;

    KAE_QUEUE_POOL_HEAD_S* qp = kaezstd_get_qp(comp_optype);
    if(unlikely(!qp)) {
        US_ERR("failed to get hardware queue pool");
        return NULL;
    }

    kaezstd_queue_pool_check_and_release(qp, kaezstd_free_ctx);

    q_node = kaezstd_get_node_from_pool(qp, alg_comp_type, comp_optype);
    if (q_node == NULL) {
        US_ERR("failed to get hardware queue");
        return NULL;
    }

    kz_ctx = (kaezstd_ctx_t *)q_node->priv_ctx;
    if (kz_ctx == NULL) {
        kz_ctx = kaezstd_new_ctx(q_node, alg_comp_type, comp_optype);
        if (kz_ctx == NULL) {
            US_ERR("kaezip new engine ctx fail!");
            (void)kaezstd_put_node_to_pool(qp, q_node);
            return NULL;
        }
    }

    kz_ctx->q_node = q_node;
    kaezstd_init_ctx(kz_ctx);

    return kz_ctx;
}

void kaezstd_init_ctx(kaezstd_ctx_t* kz_ctx)
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

    kz_ctx->flush        = 0;
    kz_ctx->status       = KAEZIP_COMP_INIT;
    kz_ctx->zstd_data.blk_type = 2; //  zstd compressed block

    memset(&kz_ctx->end_block, 0, sizeof(struct wcrypto_end_block));
}

void kaezstd_put_ctx(kaezstd_ctx_t* kz_ctx)
{
    KAE_QUEUE_DATA_NODE_S* temp = NULL;
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    if (kz_ctx->q_node != NULL) {
        temp = kz_ctx->q_node;
        kz_ctx->q_node = NULL;
        (void)kaezstd_put_node_to_pool(kaezstd_get_qp(kz_ctx->comp_type), temp);
    }

    kz_ctx = NULL;

    return;
}

static int kaezstd_driver_do_comp_impl(kaezstd_ctx_t* kz_ctx)
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

int kaezstd_driver_do_comp(kaezstd_ctx_t *kaezstd_ctx)
{
    KAEZIP_RETURN_FAIL_IF(kaezstd_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);

    if (kaezstd_ctx->remain != 0) {
        return kaezstd_get_remain_data(kaezstd_ctx);
    }

    if (kaezstd_ctx->in_len == 0) {
        US_DEBUG("kaezip do comp impl success, for input len zero, comp type : %s",
            kaezstd_ctx->comp_type == WCRYPTO_DEFLATE ? "deflate" : "inflate");
        return KAEZIP_SUCCESS;
    }

    if (kaezstd_ctx->in_len >= KAEZIP_STREAM_CHUNK_IN) {
        kaezstd_ctx->do_comp_len = KAEZIP_STREAM_CHUNK_IN;
    } else {
        kaezstd_ctx->do_comp_len = kaezstd_ctx->in_len;
    }

    kaezstd_set_input_data(kaezstd_ctx);
    int ret = kaezstd_driver_do_comp_impl(kaezstd_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_DEBUG("kaezip do comp impl success, comp type : %s",
            kaezstd_ctx->comp_type == WCRYPTO_DEFLATE ? "deflate" : "inflate");
        return ret;
    }
    kaezstd_get_output_data(kaezstd_ctx);

    return KAEZIP_SUCCESS;
}

void kaezstd_set_input_data(kaezstd_ctx_t *kz_ctx)
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

static void kaezstd_set_comp_status(kaezstd_ctx_t *kz_ctx)
{
    US_DEBUG("kaezstd before comp status is %u, op_data.status is %u", kz_ctx->status, kz_ctx->op_data.status);
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
    US_DEBUG("kaezstd after  comp status is %u", kz_ctx->status);
}

void kaezstd_get_output_data(kaezstd_ctx_t *kz_ctx)
{
    kaezstd_set_comp_status(kz_ctx);
}

int kaezstd_get_remain_data(kaezstd_ctx_t *kz_ctx)
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
    return KAEZIP_SUCCESS;
}

static KAE_QUEUE_POOL_HEAD_S* kaezstd_get_qp(int algtype)
{
    if ((algtype != WCRYPTO_DEFLATE) && (algtype != WCRYPTO_INFLATE) ) {
        US_ERR("kaezip get q pool failed, not a support algtye %d!", algtype);
        return NULL;
    }

    if (algtype == WCRYPTO_DEFLATE) {
        if (g_kaezstd_deflate_qp) {
            return g_kaezstd_deflate_qp;
        }
        pthread_mutex_lock(&g_kaezstd_deflate_pool_init_mutex);
        if (g_kaezstd_deflate_qp != NULL) {
            pthread_mutex_unlock(&g_kaezstd_deflate_pool_init_mutex);
            return g_kaezstd_deflate_qp;
        }
        kaezstd_queue_pool_destroy(g_kaezstd_deflate_qp, kaezstd_free_ctx);
        g_kaezstd_deflate_qp = kaezstd_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaezstd_deflate_pool_init_mutex);

        return g_kaezstd_deflate_qp == NULL ? NULL : g_kaezstd_deflate_qp;
    } else {
        if (g_kaezstd_inflate_qp) {
            return g_kaezstd_inflate_qp;
        }
        pthread_mutex_lock(&g_kaezstd_inflate_pool_init_mutex);
        if (g_kaezstd_inflate_qp != NULL) {
            pthread_mutex_unlock(&g_kaezstd_inflate_pool_init_mutex);
            return g_kaezstd_inflate_qp;
        }
        kaezstd_queue_pool_destroy(g_kaezstd_inflate_qp, kaezstd_free_ctx);
        g_kaezstd_inflate_qp = kaezstd_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaezstd_inflate_pool_init_mutex);

        return g_kaezstd_inflate_qp == NULL ? NULL : g_kaezstd_inflate_qp;
    }

    return NULL;
}
