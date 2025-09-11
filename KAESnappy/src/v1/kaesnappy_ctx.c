/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy ctx func
 * @Author: LiuYongYang
 * @Date: 2024-02-23
 * @LastEditTime: 2024-03-28
 */
#include "kaesnappy_ctx.h"
#include "kaesnappy_utils.h"
#include "kaesnappy_log.h"

static KAE_QUEUE_POOL_HEAD_S* g_kaelz4_deflate_qp = NULL;
static KAE_QUEUE_POOL_HEAD_S* g_kaelz4_inflate_qp = NULL;
static pthread_mutex_t g_kaelz4_deflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_kaelz4_inflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static KAE_QUEUE_POOL_HEAD_S* kaelz4_get_qp(int algtype);
static kaelz4_ctx_t* kaelz4_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype);
static int kaelz4_create_wd_ctx(kaelz4_ctx_t *kz_ctx, int alg_comp_type, int comp_optype);
static int kaelz4_driver_do_comp_impl(kaelz4_ctx_t *kz_ctx);

static void kaelz4_free_kz_ctx(void* kz_ctx)
{
    kaelz4_ctx_t* kaelz4_ctx = (kaelz4_ctx_t *)kz_ctx;
    if (kaelz4_ctx == NULL) {
        return;
    }

    if (kaelz4_ctx->op_data.in && kaelz4_ctx->setup.br.usr) {
        kaelz4_ctx->setup.br.free(kaelz4_ctx->setup.br.usr, (void *)kaelz4_ctx->op_data.in);
        kaelz4_ctx->op_data.in = NULL;
    }

    if (kaelz4_ctx->op_data.out && kaelz4_ctx->setup.br.usr) {
        kaelz4_ctx->setup.br.free(kaelz4_ctx->setup.br.usr, (void *)kaelz4_ctx->op_data.out);
        kaelz4_ctx->op_data.out = NULL;
    }

    if (kaelz4_ctx->wd_ctx != NULL) {
        wcrypto_del_comp_ctx(kaelz4_ctx->wd_ctx);
        kaelz4_ctx->wd_ctx = NULL;
    }

    kae_free(kaelz4_ctx);

    return;
}

static int kaelz4_get_comp_lv()
{
    char *lz4_str = getenv("KAE_LZ4_COMP_TYPE");
    if (lz4_str == NULL) {
        US_DEBUG("KAE_LZ4_COMP_TYPE is NULL, use default lv 8\n");
        return 8;
    }
    int lz4_val = atoi(lz4_str);
    if (lz4_val != 8 && lz4_val != 9) {
        US_DEBUG("KAE_LZ4_COMP_TYPE value out of range ：%d ,use default lv 8", lz4_val);
        return 8;
    }
    US_DEBUG("KAE_LZ4_COMP_TYPE value is ：%d ", lz4_val);
    return lz4_val;
}

static int kaelz4_get_win_size()
{
    char *lz4_str = getenv("KAE_LZ4_WINTYPE");
    if (lz4_str == NULL) {
        US_DEBUG("KAE_LZ4_WINTYPE is NULL, use default winsize 32\n");
        return WCRYPTO_COMP_WS_16K;
    }
    int winsize = atoi(lz4_str);

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
        US_DEBUG("KAE_LZ4_WINTYPE value out of range ：%d ,use default winsize 32", winsize);
        break;
	}

    US_DEBUG("KAE_LZ4_WINTYPE wintype is ：%d ", wintype);
    return wintype;
}

static void kaelz4_ctx_callback(const void *msg, void *tag)
{
    const struct wcrypto_comp_msg *respmsg = msg;
    kaelz4_ctx_t *kz_ctx = (kaelz4_ctx_t *)tag;

    if (kz_ctx->callback)
        kz_ctx->callback(respmsg->status, kz_ctx->param);

    return;
}

static kaelz4_ctx_t* kaelz4_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype)
{
    kaelz4_ctx_t *kz_ctx = NULL;
    kz_ctx = (kaelz4_ctx_t *)kae_malloc(sizeof(kaelz4_ctx_t));
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kaezip ctx malloc fail.");
        return NULL;
    }
    memset(kz_ctx, 0, sizeof(kaelz4_ctx_t));

    kz_ctx->setup.comp_lv = kaelz4_get_comp_lv();
    kz_ctx->setup.win_size  = kaelz4_get_win_size();
    kz_ctx->setup.br.alloc = kaelz4_wd_alloc_blk;
    kz_ctx->setup.br.free = kaelz4_wd_free_blk;
    kz_ctx->setup.br.iova_map = kaelz4_dma_map;
    kz_ctx->setup.br.iova_unmap = kaelz4_dma_unmap;
    kz_ctx->setup.br.usr = q_node->kae_queue_mem_pool;
    kz_ctx->setup.cb = kaelz4_ctx_callback;

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

    kz_ctx->op_data.priv = &kz_ctx->lz4_data;
    kz_ctx->q_node = q_node;
    q_node->priv_ctx = kz_ctx;

    if (kaelz4_create_wd_ctx(kz_ctx, alg_comp_type, comp_optype) == KAEZIP_FAILED) {
        US_ERR("create wd ctx fail!");
        goto err;
    }

    return kz_ctx;

err:
    kaelz4_free_kz_ctx(kz_ctx);

    return NULL;
}

static int kaelz4_create_wd_ctx(kaelz4_ctx_t *kz_ctx, int alg_comp_type, int comp_optype)
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

kaelz4_ctx_t* kaelz4_get_ctx(int alg_comp_type, int comp_optype)
{
    KAE_QUEUE_DATA_NODE_S      *q_node = NULL;
    kaelz4_ctx_t               *kz_ctx = NULL;

    KAE_QUEUE_POOL_HEAD_S* qp = kaelz4_get_qp(comp_optype);
    if(unlikely(!qp)) {
        US_ERR("failed to get hardware queue pool");
        return NULL;
    }

    q_node = kaelz4_get_node_from_pool(qp, alg_comp_type, comp_optype);
    if (q_node == NULL) {
        kaelz4_queue_pool_check_and_release(qp, kaelz4_free_kz_ctx);
        q_node = kaelz4_get_node_from_pool(qp, alg_comp_type, comp_optype);

        if (q_node == NULL) {
            US_ERR("failed to get hardware queue");
            return NULL;
        }
    }

    kz_ctx = (kaelz4_ctx_t *)q_node->priv_ctx;
    if (kz_ctx == NULL) {
        kz_ctx = kaelz4_new_ctx(q_node, alg_comp_type, comp_optype);
        if (kz_ctx == NULL) {
            US_ERR("kaezip new engine ctx fail!");
            (void)kaelz4_put_node_to_pool(qp, q_node, kaelz4_free_kz_ctx);
            return NULL;
        }
    }

    kz_ctx->q_node = q_node;
    kaelz4_init_ctx(kz_ctx);

    return kz_ctx;
}

void kaelz4_init_ctx(kaelz4_ctx_t* kz_ctx)
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
    kz_ctx->lz4_data.blk_type = 2; //  lz4 compressed block
    kz_ctx->callback = NULL;
    kz_ctx->param = NULL;

    memset(&kz_ctx->end_block, 0, sizeof(struct wcrypto_end_block));
}

void kaelz4_put_ctx(kaelz4_ctx_t* kz_ctx)
{
    KAE_QUEUE_DATA_NODE_S* temp = NULL;
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    if (kz_ctx->q_node != NULL) {
        temp = kz_ctx->q_node;
        kz_ctx->q_node = NULL;
        (void)kaelz4_put_node_to_pool(kaelz4_get_qp(kz_ctx->comp_type), temp, kaelz4_free_kz_ctx);
    }

    kz_ctx = NULL;

    return;
}

void kaelz4_free_ctx(kaelz4_ctx_t* kz_ctx)
{
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    kaelz4_free_wd_queue_memory(kz_ctx->q_node, kaelz4_free_kz_ctx);
}

static int kaelz4_driver_do_comp_impl(kaelz4_ctx_t* kz_ctx)
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

int kaelz4_driver_do_comp(kaelz4_ctx_t *kaelz4_ctx)
{
    KAEZIP_RETURN_FAIL_IF(kaelz4_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);

    if (kaelz4_ctx->remain != 0) {
        return kaelz4_get_remain_data(kaelz4_ctx);
    }

    if (kaelz4_ctx->in_len == 0) {
        US_DEBUG("kaezip do comp impl success, for input len zero, comp type : %s",
            kaelz4_ctx->comp_type == WCRYPTO_DEFLATE ? "deflate" : "inflate");
        return KAEZIP_SUCCESS;
    }

    if (kaelz4_ctx->in_len >= KAEZIP_STREAM_CHUNK_IN) {
        kaelz4_ctx->do_comp_len = KAEZIP_STREAM_CHUNK_IN;
    } else {
        kaelz4_ctx->do_comp_len = kaelz4_ctx->in_len;
    }

    kaelz4_set_input_data(kaelz4_ctx);
    int ret = kaelz4_driver_do_comp_impl(kaelz4_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_DEBUG("kaezip do comp impl success, comp type : %s",
            kaelz4_ctx->comp_type == WCRYPTO_DEFLATE ? "deflate" : "inflate");
        return ret;
    }
    kaelz4_get_output_data(kaelz4_ctx);

    return KAEZIP_SUCCESS;
}

void kaelz4_set_input_data(kaelz4_ctx_t *kz_ctx)
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

static void kaelz4_set_comp_status(kaelz4_ctx_t *kz_ctx)
{
    US_DEBUG("kaelz4 before comp status is %u, op_data.status is %u", kz_ctx->status, kz_ctx->op_data.status);
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
    US_DEBUG("kaelz4 after  comp status is %u", kz_ctx->status);
}

void kaelz4_get_output_data(kaelz4_ctx_t *kz_ctx)
{
    kaelz4_set_comp_status(kz_ctx);
}

int kaelz4_get_remain_data(kaelz4_ctx_t *kz_ctx)
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

static KAE_QUEUE_POOL_HEAD_S* kaelz4_get_qp(int algtype)
{
    if ((algtype != WCRYPTO_DEFLATE) && (algtype != WCRYPTO_INFLATE) ) {
        US_ERR("kaezip get q pool failed, not a support algtye %d!", algtype);
        return NULL;
    }

    if (algtype == WCRYPTO_DEFLATE) {
        if (g_kaelz4_deflate_qp) {
            return g_kaelz4_deflate_qp;
        }
        pthread_mutex_lock(&g_kaelz4_deflate_pool_init_mutex);
        if (g_kaelz4_deflate_qp != NULL) {
            pthread_mutex_unlock(&g_kaelz4_deflate_pool_init_mutex);
            return g_kaelz4_deflate_qp;
        }
        kaelz4_queue_pool_destroy(g_kaelz4_deflate_qp, kaelz4_free_kz_ctx);
        g_kaelz4_deflate_qp = kaelz4_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaelz4_deflate_pool_init_mutex);

        return g_kaelz4_deflate_qp == NULL ? NULL : g_kaelz4_deflate_qp;
    } else {
        if (g_kaelz4_inflate_qp) {
            return g_kaelz4_inflate_qp;
        }
        pthread_mutex_lock(&g_kaelz4_inflate_pool_init_mutex);
        if (g_kaelz4_inflate_qp != NULL) {
            pthread_mutex_unlock(&g_kaelz4_inflate_pool_init_mutex);
            return g_kaelz4_inflate_qp;
        }
        kaelz4_queue_pool_destroy(g_kaelz4_inflate_qp, kaelz4_free_kz_ctx);
        g_kaelz4_inflate_qp = kaelz4_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaelz4_inflate_pool_init_mutex);

        return g_kaelz4_inflate_qp == NULL ? NULL : g_kaelz4_inflate_qp;
    }

    return NULL;
}

void kaelz4_free_all_qps(void)
{
    pthread_mutex_lock(&g_kaelz4_deflate_pool_init_mutex);
    kaelz4_queue_pool_destroy(g_kaelz4_deflate_qp, kaelz4_free_kz_ctx);
    g_kaelz4_deflate_qp = NULL;
    pthread_mutex_unlock(&g_kaelz4_deflate_pool_init_mutex);
    pthread_mutex_lock(&g_kaelz4_inflate_pool_init_mutex);
    kaelz4_queue_pool_destroy(g_kaelz4_inflate_qp, kaelz4_free_kz_ctx);
    g_kaelz4_inflate_qp = NULL;
    pthread_mutex_unlock(&g_kaelz4_inflate_pool_init_mutex);
}
