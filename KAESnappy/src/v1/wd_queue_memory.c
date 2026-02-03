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

#include <stdio.h>
#include "wd_queue_memory.h"
#include "kaesnappy_log.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_comp.h"
#include "kaesnappy_ctx.h"

struct wd_queue* kaesnappy_wd_new_queue(int comp_alg_type, int comp_optype);

struct wd_queue* kaesnappy_wd_new_queue(int comp_alg_type, int comp_optype)
{
    struct wd_queue* queue = (struct wd_queue *)kae_malloc(sizeof(struct wd_queue));
    if (queue == NULL) {
        US_ERR("malloc failed");
        return NULL;
    }

    memset(queue, 0, sizeof(struct wd_queue));
    switch (comp_alg_type) {
        case WCRYPTO_LZ77_ONLY:
        case WCRYPTO_LZ77_ZSTD:
            queue->capa.alg = "lz77_zstd";
            break;
        default:
            kae_free(queue);
            return NULL;
    }
    queue->capa.latency = 0;
    queue->capa.throughput = 0;

    struct wcrypto_paras *priv = (struct wcrypto_paras *)&(queue->capa.priv);
    priv->direction = comp_optype;
    int ret = wd_request_queue(queue);
    if (ret) {
        US_ERR("request wd queue fail! errno:%d", ret);
        kae_free(queue);
        queue = NULL;
        return NULL;
    }

    return queue;
}

void kaesnappy_wd_free_queue(struct wd_queue* queue)
{
    if (queue != NULL) {
        wd_release_queue(queue);
        kae_free(queue);
        queue = NULL;
    }
}

void* kaesnappy_create_alg_wd_queue_mempool(struct wd_queue *q)
{
    unsigned int block_size = COMP_BLOCK_SIZE;
    unsigned int block_num = COMP_BLOCK_NUM;
    struct wd_blkpool_setup setup;

    memset(&setup, 0, sizeof(setup));
    setup.block_size = block_size;
    setup.block_num = block_num;
    setup.align_size = 64;   // align with 64

    void *mempool = wd_blkpool_create(q, &setup);

    return mempool;
}

void kaesnappy_wd_queue_mempool_destroy(void *pool)
{
    return wd_blkpool_destroy(pool);
}

void *kaesnappy_dma_map(void *usr, void *va, size_t sz)
{
    return wd_blk_iova_map(usr, va);
}

void kaesnappy_dma_unmap(void *usr, void *va, void *dma, size_t sz)
{
    return wd_blk_iova_unmap(usr, dma, va);
}

void *kaesnappy_wd_alloc_blk(void *pool, size_t size)
{
    if (pool == NULL) {
        US_ERR("mem pool empty!");
        return NULL;
    }

    return wd_alloc_blk(pool);
}

void kaesnappy_wd_free_blk(void *pool, void *blk)
{
    return wd_free_blk(pool, blk);
}

KAE_QUEUE_POOL_HEAD_S* kaesnappy_init_queue_pool(int algtype)
{
    KAE_QUEUE_POOL_HEAD_S *kae_pool = NULL;

    kae_pool = (KAE_QUEUE_POOL_HEAD_S *)kae_malloc(sizeof(KAE_QUEUE_POOL_HEAD_S));
    if (kae_pool == NULL) {
        US_ERR("malloc pool head fail!");
        return NULL;
    }

    /* fill data of head */
    kae_pool->algtype = algtype;
    kae_pool->next = NULL;
    kae_pool->pool_use_num = 0;

    /* malloc a pool */
    kae_pool->kae_queue_pool = (KAE_QUEUE_POOL_NODE_S *)
        kae_malloc(KAE_QUEUE_POOL_MAX_SIZE * sizeof(KAE_QUEUE_POOL_NODE_S));
    if (kae_pool->kae_queue_pool == NULL) {
        US_ERR("malloc failed");
        kae_free(kae_pool);
        return NULL;
    }
    memset(kae_pool->kae_queue_pool, 0, KAE_QUEUE_POOL_MAX_SIZE * sizeof(KAE_QUEUE_POOL_NODE_S));

    pthread_mutex_init(&kae_pool->kae_queue_mutex, NULL);
    pthread_mutex_init(&kae_pool->destroy_mutex, NULL);

    return kae_pool;
}

static KAE_QUEUE_DATA_NODE_S* kaesnappy_get_queue_data_from_list(KAE_QUEUE_POOL_HEAD_S* pool_head, int type)
{
    int i = 0;
    KAE_QUEUE_DATA_NODE_S *queue_data_node = NULL;
    KAE_QUEUE_POOL_HEAD_S *temp_pool = pool_head;

    if ((pool_head->pool_use_num == 0) && (pool_head->next == NULL)) {
        return queue_data_node;
    }

    while (temp_pool != NULL) {
        for (i = 0; i < temp_pool->pool_use_num; i++) {
            if (temp_pool->kae_queue_pool[i].node_data == NULL) {
                continue;
            }

            if (KAE_SPIN_TRYLOCK(temp_pool->kae_queue_pool[i].spinlock)) {
                if (temp_pool->kae_queue_pool[i].node_data == NULL) {
                    KAE_SPIN_UNLOCK(temp_pool->kae_queue_pool[i].spinlock);
                    continue;
                }

                if (temp_pool->kae_queue_pool[i].node_data->comp_alg_type != type) {
                    KAE_SPIN_UNLOCK(temp_pool->kae_queue_pool[i].spinlock);
                    continue;
                }

                queue_data_node = temp_pool->kae_queue_pool[i].node_data;
                temp_pool->kae_queue_pool[i].node_data = NULL;
                KAE_SPIN_UNLOCK(temp_pool->kae_queue_pool[i].spinlock);

                US_DEBUG("kaezip get queue from pool success. queue_node id =%d", i);
                return queue_data_node;
            }
        }
        /* next pool */
        temp_pool = temp_pool->next;
    }

    return queue_data_node;
}

void kaesnappy_free_wd_queue_memory(KAE_QUEUE_DATA_NODE_S *queue_node, kae_release_priv_ctx_cb release_fn)
{
    if (queue_node != NULL) {
        if (release_fn != NULL && queue_node->priv_ctx != NULL) {
            release_fn(queue_node->priv_ctx);
            queue_node->priv_ctx = NULL;
        }
        if (queue_node->kae_queue_mem_pool != NULL) {
            kaesnappy_wd_queue_mempool_destroy(queue_node->kae_queue_mem_pool);
            queue_node->kae_queue_mem_pool = NULL;
        }
        if (queue_node->kae_wd_queue != NULL) {
            kaesnappy_wd_free_queue(queue_node->kae_wd_queue);
            queue_node->kae_wd_queue = NULL;
        }
        kae_free(queue_node);
        queue_node = NULL;
    }

    US_DEBUG("free wd queue success");
}

static KAE_QUEUE_DATA_NODE_S* kaesnappy_new_wd_queue_memory(int comp_alg_type, int comp_type)
{
    KAE_QUEUE_DATA_NODE_S *queue_node = NULL;

    queue_node = (KAE_QUEUE_DATA_NODE_S *)kae_malloc(sizeof(KAE_QUEUE_DATA_NODE_S));
    if (queue_node == NULL) {
        US_ERR("malloc failed");
        return NULL;
    }
    memset(queue_node, 0, sizeof(KAE_QUEUE_DATA_NODE_S));

    queue_node->kae_wd_queue = kaesnappy_wd_new_queue(comp_alg_type, comp_type);
    if (queue_node->kae_wd_queue == NULL) {
        US_ERR("new wd queue fail");
        goto err;
    }

    queue_node->kae_queue_mem_pool = kaesnappy_create_alg_wd_queue_mempool(queue_node->kae_wd_queue);
    if (queue_node->kae_queue_mem_pool == NULL) {
        US_ERR("request mempool fail!");
        goto err;
    }

    queue_node->comp_alg_type = comp_alg_type;
    return queue_node;

err:
    kaesnappy_free_wd_queue_memory(queue_node, NULL);
    return NULL;
}

KAE_QUEUE_DATA_NODE_S* kaesnappy_get_node_from_pool(KAE_QUEUE_POOL_HEAD_S* pool_head, int comp_alg_type, int comp_type)
{
    KAE_QUEUE_DATA_NODE_S *queue_data_node = NULL;

    if (pool_head == NULL) {
        US_ERR("input params pool_head is null");
        return NULL;
    }

    queue_data_node = kaesnappy_get_queue_data_from_list(pool_head, comp_alg_type);
    if (queue_data_node == NULL) {
        queue_data_node = kaesnappy_new_wd_queue_memory(comp_alg_type, comp_type);
    }

    return queue_data_node;
}

static void kaesnappy_set_pool_use_num(KAE_QUEUE_POOL_HEAD_S *pool, int set_num)
{
    pthread_mutex_lock(&pool->kae_queue_mutex);
    if (set_num > pool->pool_use_num) {
        pool->pool_use_num = set_num;
    }
    (void)pthread_mutex_unlock(&pool->kae_queue_mutex);
}

int kaesnappy_put_node_to_pool(KAE_QUEUE_POOL_HEAD_S* pool_head,  KAE_QUEUE_DATA_NODE_S* node_data, kae_release_priv_ctx_cb release_fn)
{
    int i = 0;
    KAE_QUEUE_POOL_HEAD_S *temp_pool = pool_head;

    if (node_data == NULL || pool_head == NULL) {
        return 0;
    }

    while (temp_pool != NULL) {
        for (i = 0; i < KAE_QUEUE_POOL_MAX_SIZE; i++) {
            if (temp_pool->kae_queue_pool[i].node_data) {
                continue;
            }

            if (KAE_SPIN_TRYLOCK(temp_pool->kae_queue_pool[i].spinlock)) {
                if (temp_pool->kae_queue_pool[i].node_data) {
                    KAE_SPIN_UNLOCK(temp_pool->kae_queue_pool[i].spinlock);
                    continue;
                } else {
                    temp_pool->kae_queue_pool[i].node_data = node_data;
                    temp_pool->kae_queue_pool[i].add_time = time((time_t *)NULL);
                    KAE_SPIN_UNLOCK(temp_pool->kae_queue_pool[i].spinlock);
                    if (i >= temp_pool->pool_use_num) {
                        kaesnappy_set_pool_use_num(temp_pool, i + 1);
                    }

                    US_DEBUG("kaezip put queue node to pool, queue node id is %d.", i);
                    return 1;
                }
            }
        }
    }
    /* if not added,free it */
    return 0;
}

void kaesnappy_queue_pool_reset(KAE_QUEUE_POOL_HEAD_S* pool_head)
{
    (void)pool_head;
    return;
}

void kaesnappy_queue_pool_check_and_release(KAE_QUEUE_POOL_HEAD_S* pool_head, kae_release_priv_ctx_cb release_fn)
{
    int i = 0;
    int error;
    time_t current_time;
    KAE_QUEUE_POOL_HEAD_S *cur_pool = pool_head;

    current_time = time((time_t *)NULL);

    while (cur_pool != NULL) {
        error = pthread_mutex_lock(&cur_pool->destroy_mutex);
        if (error != 0) {
            cur_pool = cur_pool->next;
            continue;
        }
        if (cur_pool->kae_queue_pool == NULL) {
            (void)pthread_mutex_unlock(&cur_pool->destroy_mutex);
            cur_pool = cur_pool->next;
            continue;
        }

        for (i = cur_pool->pool_use_num - 1; i >= 0; i--) {
            if (cur_pool->kae_queue_pool[i].node_data == NULL) {
                continue;
            }

            if (difftime(current_time, cur_pool->kae_queue_pool[i].add_time) < CHECK_QUEUE_TIME_SECONDS) {
                continue;
            }
        }

        (void)pthread_mutex_unlock(&cur_pool->destroy_mutex);
        cur_pool = cur_pool->next;
    }

    return;
}

