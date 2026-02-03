/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
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

#include "kaesnappy_ctx.h"
#include "kaesnappy_utils.h"
#include "kaesnappy_log.h"

static KAE_QUEUE_POOL_HEAD_S* g_kaesnappy_deflate_qp = NULL;
static pthread_mutex_t g_kaesnappy_deflate_pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static KAE_QUEUE_POOL_HEAD_S* kaesnappy_get_qp(int algtype);
static kaesnappy_ctx_t* kaesnappy_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype);
static int kaesnappy_create_wd_ctx(kaesnappy_ctx_t *kz_ctx, int alg_comp_type, int comp_optype);

static void kaesnappy_free_kz_ctx(void* kz_ctx)
{
    kaesnappy_ctx_t* kaesnappy_ctx = (kaesnappy_ctx_t *)kz_ctx;
    kae_free(kaesnappy_ctx);
    return;
}

static int kaesnappy_get_comp_lv()
{
    char *snappy_str = getenv("KAE_SNAPPY_COMP_TYPE");
    if (snappy_str == NULL) {
        US_DEBUG("KAE_SNAPPY_COMP_TYPE is NULL, use default lv 8\n");
        return 8;
    }
    int snappy_val = atoi(snappy_str);
    if (snappy_val != 8 && snappy_val != 9) {
        US_DEBUG("KAE_SNAPPY_COMP_TYPE value out of range ：%d ,use default lv 8", snappy_val);
        return 8;
    }
    US_DEBUG("KAE_SNAPPY_COMP_TYPE value is ：%d ", snappy_val);
    return snappy_val;
}

static int kaesnappy_get_win_size()
{
    char *snappy_str = getenv("KAE_SNAPPY_WINTYPE");
    if (snappy_str == NULL) {
        US_DEBUG("KAE_SNAPPY_WINTYPE is NULL, use default winsize 32\n");
        return WCRYPTO_COMP_WS_16K;
    }
    int winsize = atoi(snappy_str);

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
        US_DEBUG("KAE_SNAPPY_WINTYPE value out of range ：%d ,use default winsize 32", winsize);
        break;
	}

    US_DEBUG("KAE_SNAPPY_WINTYPE wintype is ：%d ", wintype);
    return wintype;
}

static void kaesnappy_ctx_callback(const void *msg, void *tag)
{
    return;
}

static kaesnappy_ctx_t* kaesnappy_new_ctx(KAE_QUEUE_DATA_NODE_S* q_node, int alg_comp_type, int comp_optype)
{
    kaesnappy_ctx_t *kz_ctx = NULL;
    kz_ctx = (kaesnappy_ctx_t *)kae_malloc(sizeof(kaesnappy_ctx_t));
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kaezip ctx malloc fail.");
        return NULL;
    }
    memset(kz_ctx, 0, sizeof(kaesnappy_ctx_t));

    kz_ctx->setup.comp_lv = kaesnappy_get_comp_lv();
    kz_ctx->setup.win_size  = kaesnappy_get_win_size();
    kz_ctx->setup.br.alloc = kaesnappy_wd_alloc_blk;
    kz_ctx->setup.br.free = kaesnappy_wd_free_blk;
    kz_ctx->setup.br.iova_map = kaesnappy_dma_map;
    kz_ctx->setup.br.iova_unmap = kaesnappy_dma_unmap;
    kz_ctx->setup.br.usr = q_node->kae_queue_mem_pool;
    kz_ctx->setup.cb = kaesnappy_ctx_callback;

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

    kz_ctx->op_data.priv = &kz_ctx->snappy_data;
    kz_ctx->q_node = q_node;
    q_node->priv_ctx = kz_ctx;

    if (kaesnappy_create_wd_ctx(kz_ctx, alg_comp_type, comp_optype) == KAEZIP_FAILED) {
        US_ERR("create wd ctx fail!");
        goto err;
    }

    return kz_ctx;

err:
    kaesnappy_free_kz_ctx(kz_ctx);

    return NULL;
}

static int kaesnappy_create_wd_ctx(kaesnappy_ctx_t *kz_ctx, int alg_comp_type, int comp_optype)
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

kaesnappy_ctx_t* kaesnappy_get_ctx(int alg_comp_type, int comp_optype)
{
    KAE_QUEUE_DATA_NODE_S      *q_node = NULL;
    kaesnappy_ctx_t               *kz_ctx = NULL;

    KAE_QUEUE_POOL_HEAD_S* qp = kaesnappy_get_qp(comp_optype);
    if(unlikely(!qp)) {
        US_ERR("failed to get hardware queue pool");
        return NULL;
    }

    q_node = kaesnappy_get_node_from_pool(qp, alg_comp_type, comp_optype);
    if (q_node == NULL) {
        kaesnappy_queue_pool_check_and_release(qp, kaesnappy_free_kz_ctx);
        q_node = kaesnappy_get_node_from_pool(qp, alg_comp_type, comp_optype);

        if (q_node == NULL) {
            US_ERR("failed to get hardware queue");
            return NULL;
        }
    }

    kz_ctx = (kaesnappy_ctx_t *)q_node->priv_ctx;
    if (kz_ctx == NULL) {
        kz_ctx = kaesnappy_new_ctx(q_node, alg_comp_type, comp_optype);
        if (kz_ctx == NULL) {
            US_ERR("kaezip new engine ctx fail!");
            (void)kaesnappy_put_node_to_pool(qp, q_node, kaesnappy_free_kz_ctx);
            return NULL;
        }
    }

    kz_ctx->q_node = q_node;
    kaesnappy_init_ctx(kz_ctx);

    return kz_ctx;
}

void kaesnappy_init_ctx(kaesnappy_ctx_t* kz_ctx)
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
    kz_ctx->snappy_data.blk_type = 2; //  snappy compressed block
    kz_ctx->callback = NULL;
    kz_ctx->param = NULL;

    memset(&kz_ctx->end_block, 0, sizeof(struct wcrypto_end_block));
}

void kaesnappy_put_ctx(kaesnappy_ctx_t* kz_ctx)
{
    KAE_QUEUE_DATA_NODE_S* temp = NULL;
    if (unlikely(kz_ctx == NULL)) {
        US_ERR("kae zip ctx NULL!");
        return;
    }

    if (kz_ctx->q_node != NULL) {
        temp = kz_ctx->q_node;
        kz_ctx->q_node = NULL;
        (void)kaesnappy_put_node_to_pool(kaesnappy_get_qp(kz_ctx->comp_type), temp, kaesnappy_free_kz_ctx);
    }

    kz_ctx = NULL;

    return;
}

void kaesnappy_set_input_data(kaesnappy_ctx_t *kz_ctx)
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

static void kaesnappy_set_comp_status(kaesnappy_ctx_t *kz_ctx)
{
    US_DEBUG("kaesnappy before comp status is %u, op_data.status is %u", kz_ctx->status, kz_ctx->op_data.status);
    switch (kz_ctx->op_data.status) {
        case WCRYPTO_STATUS_NULL:
            if (kz_ctx->in_len > kz_ctx->consumed) {
                kz_ctx->status = KAEZIP_COMP_DOING;
                break;
            }
        default:
            kz_ctx->status = KAEZIP_COMP_DOING;
            break;
    }
    US_DEBUG("kaesnappy after  comp status is %u", kz_ctx->status);
}

void kaesnappy_get_output_data(kaesnappy_ctx_t *kz_ctx)
{
    kaesnappy_set_comp_status(kz_ctx);
}

static KAE_QUEUE_POOL_HEAD_S* kaesnappy_get_qp(int algtype)
{
    if ((algtype != WCRYPTO_DEFLATE) && (algtype != WCRYPTO_INFLATE) ) {
        US_ERR("kaezip get q pool failed, not a support algtye %d!", algtype);
        return NULL;
    }

    if (algtype == WCRYPTO_DEFLATE) {
        if (g_kaesnappy_deflate_qp) {
            return g_kaesnappy_deflate_qp;
        }
        pthread_mutex_lock(&g_kaesnappy_deflate_pool_init_mutex);
        if (g_kaesnappy_deflate_qp != NULL) {
            pthread_mutex_unlock(&g_kaesnappy_deflate_pool_init_mutex);
            return g_kaesnappy_deflate_qp;
        }

        g_kaesnappy_deflate_qp = kaesnappy_init_queue_pool(algtype);
        pthread_mutex_unlock(&g_kaesnappy_deflate_pool_init_mutex);

        return g_kaesnappy_deflate_qp == NULL ? NULL : g_kaesnappy_deflate_qp;
    }
    return NULL;
}

