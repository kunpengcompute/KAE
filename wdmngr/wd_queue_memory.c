/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for KAE engine of wd queue memory management
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
#include "engine_utils.h"
#include "engine_log.h"
#include "wd_bmm.h"

#define MAXBLOCKSIZE   0x90000
#define MAXRSVMEM      0x400000

#define MAXBLOCKSIZE   0x90000
#define MAXRSVMEM      0x400000

const char *g_alg_type[] = {
    "rsa",
    "dh",
    "cipher",
    "digest",
};

struct wd_queue_mempool *wd_queue_mempool_create(struct wd_queue *q,
    unsigned int block_size, unsigned int block_num)
{
    void *addr = NULL;
    unsigned long rsv_mm_sz;
    struct wd_queue_mempool *pool = NULL;
    unsigned int bitmap_sz;
    const unsigned int BLOCKS_PER_BITMAP = 32;

    if (block_size > MAXBLOCKSIZE) {
        US_ERR("error! current blk size is beyond 576k");
        return NULL;
    }

    rsv_mm_sz = (unsigned long)block_size * (unsigned long)block_num;
    if (rsv_mm_sz > (unsigned long)MAXRSVMEM) {
        US_ERR("error! current mem size is beyond 4M");
        return NULL;
    }

    addr = wd_reserve_memory(q, rsv_mm_sz);
    if (addr == NULL) {
        US_ERR("reserve_memory fail!");
        return NULL;
    }
    kae_memset(addr, 0, rsv_mm_sz);

    bitmap_sz = (block_num / BLOCKS_PER_BITMAP + 1) * sizeof(unsigned int);
    pool =
        (struct wd_queue_mempool *)kae_malloc(sizeof(struct wd_queue_mempool) + bitmap_sz);
    if (pool == NULL) {
        US_ERR("Alloc pool handle fail!");
        return NULL;
    }
    kae_memset(pool, 0, sizeof(struct wd_queue_mempool) + bitmap_sz);

    pool->base = addr;
    sem_init(&pool->mempool_sem, 0, 1);
    pool->block_size = block_size;
    pool->block_num = block_num;
    pool->free_num = block_num;
    pool->bitmap = (unsigned int *) (pool + 1);
    pool->mem_size = rsv_mm_sz;
    pool->q = q;

    return pool;
}

struct wd_queue_mempool *create_alg_wd_queue_mempool(int algtype, struct wd_queue *q)
{
    struct wd_queue_mempool *mempool = NULL;
    unsigned int block_size;
    unsigned int block_num;

    switch (algtype) {
        case WCRYPTO_RSA:
            block_size = RSA_BLOCK_SIZE;
            block_num = RSA_BLOCK_NUM;
            break;
        case WCRYPTO_DH:
            block_size = DH_BLOCK_SIZE;
            block_num = DH_BLOCK_NUM;
            break;
        case WCRYPTO_CIPHER:
            block_size = CIPHER_BLOCK_SIZE;
            block_num = CIPHER_BLOCK_NUM;
            break;
        case WCRYPTO_DIGEST:
            block_size = DIGEST_BLOCK_SIZE;
            block_num = DIGEST_BLOCK_NUM;
            break;
        case WCRYPTO_COMP:
        case WCRYPTO_EC:
        case WCRYPTO_RNG:
        default:
            US_WARN("create_alg_wd_queue_mempool not support algtype:%d", algtype);
            return NULL;
    }

#ifdef NO_WD_BLK_POOL    
    mempool = wd_queue_mempool_create(q, block_size, block_num);
#else
    struct wd_blkpool_setup setup;

    kae_memset(&setup, 0, sizeof(setup));
    setup.block_size = block_size;
    setup.block_num = block_num;
    setup.align_size = 64;   // align with 64

    mempool = (struct wd_queue_mempool *)wd_blkpool_create(q, &setup);
#endif

    return mempool;
}

void wd_queue_mempool_destroy(struct wd_queue_mempool *pool)
{
#ifdef  NO_WD_BLK_POOL
    kae_free(pool);
#else
    wd_blkpool_destroy(pool);
#endif

    return;
}

void *kae_dma_map(void *usr, void *va, size_t sz)
{
#ifdef  NO_WD_BLK_POOL
    struct wd_queue_mempool *pool = (struct wd_queue_mempool *)usr;

    return wd_dma_map(pool->q, va, sz);
#else
    return wd_blk_iova_map(usr, va);
#endif
}

void kae_dma_unmap(void *usr, void *va, void *dma, size_t sz)
{
#ifdef  NO_WD_BLK_POOL
    struct wd_queue_mempool *pool = (struct wd_queue_mempool *)usr;

    return wd_dma_unmap(pool->q, va, dma, sz);
#else
    return wd_blk_iova_unmap(usr, dma, va);
#endif
}

#ifdef  NO_WD_BLK_POOL
static void *wd_queue_pool_alloc_buf(struct wd_queue_mempool *pool)
{
    __u64 i = 0;
    __u64 j = 0;

    (void) sem_wait(&pool->mempool_sem);
    __u32 *pbm = pool->bitmap;
    __u64 tmp = pool->index;
    for (; pool->index < pool->block_num; pool->index++) {
        i = (pool->index >> 5);
        j = (pool->index & (32 - 1));
        if ((pbm[i] & ((__u32) 0x1 << j)) == 0) {
            pbm[i] |= ((__u32) 0x1 << j);
            tmp = pool->index;
            pool->index++;
            (void) sem_post(&pool->mempool_sem);
            return (void*)((char *) pool->base + (tmp * pool->block_size));
        }
    }
    for (pool->index = 0; pool->index < tmp; pool->index++) {
        i = (pool->index >> 5);
        j = (pool->index & (32 - 1));
        if ((pbm[i] & ((__u32) 0x1 << j)) == 0) {
            pbm[i] |= ((__u32) 0x1 << j);
            tmp = pool->index;
            pool->index++;
            (void) sem_post(&pool->mempool_sem);
            return  (void*)((char *) pool->base + (tmp * pool->block_size));
        }
    }
    (void) sem_post(&pool->mempool_sem);
    US_ERR("no reserve mem available!");

    return NULL;
}

static void wd_queue_pool_free_buf(struct wd_queue_mempool *pool, void *pbuf)
{
    __u32 *pbm = pool->bitmap;

    kae_memset(pbuf, 0, pool->block_size);

    __u64 offset = (__u64)((unsigned long) pbuf - (unsigned long) pool->base);
    offset = offset / pool->block_size;
    if (pool->block_num <= offset) {
        US_ERR("offset = %lld, virtual address err!", offset);
        return;
    }
    __u32 bit_mask = ~(0x1u << (offset & 31));
    (void) sem_wait(&pool->mempool_sem);
    pbm[(offset >> 5)] &= bit_mask;
    (void) sem_post(&pool->mempool_sem);
}
#endif

void *kae_wd_alloc_blk(void *pool, size_t size)
{
    if (pool == NULL) {
        US_ERR("mem pool empty!");
        return NULL;
    }

#ifdef  NO_WD_BLK_POOL
    struct wd_queue_mempool *mempool = (struct wd_queue_mempool *)pool;
    if (size > (size_t)mempool->block_size) {
        US_ERR("alloc size error, over one block size.");
        return NULL;
    }
    return wd_queue_pool_alloc_buf((struct wd_queue_mempool *)pool);
#else
    return wd_alloc_blk(pool);
#endif  
}

void kae_wd_free_blk(void *pool, void *blk)
{
#ifdef  NO_WD_BLK_POOL
    wd_queue_pool_free_buf((struct wd_queue_mempool *)pool, blk); 
#else
    wd_free_blk(pool, blk);
#endif
}

KAE_QUEUE_POOL_HEAD_S* kae_init_queue_pool(int algtype)
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
    kae_memset(kae_pool->kae_queue_pool, 0, KAE_QUEUE_POOL_MAX_SIZE * sizeof(KAE_QUEUE_POOL_NODE_S));

    pthread_mutex_init(&kae_pool->kae_queue_mutex, NULL);
    pthread_mutex_init(&kae_pool->destroy_mutex, NULL);

    US_DEBUG("kae init %s queue success", g_alg_type[algtype]);

    return kae_pool;
}

static KAE_QUEUE_DATA_NODE_S* kae_get_queue_data_from_list(KAE_QUEUE_POOL_HEAD_S* pool_head)
{
    int i = 0;
    KAE_QUEUE_DATA_NODE_S *queue_data_node = NULL;
    KAE_QUEUE_POOL_HEAD_S *temp_pool = pool_head;
    
    US_DEBUG("kae get queue node from pool start.");

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
                } else {
                    queue_data_node = temp_pool->kae_queue_pool[i].node_data;
                    temp_pool->kae_queue_pool[i].node_data = (KAE_QUEUE_DATA_NODE_S *)NULL;
                    KAE_SPIN_UNLOCK(temp_pool->kae_queue_pool[i].spinlock);

                    US_DEBUG("kae queue pool first success. queue_data_node=%p queue_node id =%d", queue_data_node, i);
                    return queue_data_node;
                }
            }
        }
        /* next pool */
        temp_pool = temp_pool->next;
    }
    
    return queue_data_node;
}

static void kae_free_wd_queue_memory(KAE_QUEUE_DATA_NODE_S *queue_node, release_engine_ctx_cb release_fn)
{
    if (queue_node != NULL) {
        if (release_fn != NULL && queue_node->engine_ctx != NULL) {
            release_fn(queue_node->engine_ctx);
            queue_node->engine_ctx = NULL;
        }

        if (queue_node->kae_queue_mem_pool != NULL) {
            wd_queue_mempool_destroy(queue_node->kae_queue_mem_pool);
            queue_node->kae_queue_mem_pool = NULL;
        }
        if (queue_node->kae_wd_queue != NULL) {
            wd_free_queue(queue_node->kae_wd_queue);
            queue_node->kae_wd_queue = NULL;
        }
        
        kae_free(queue_node);
        queue_node = NULL;
    }

    US_DEBUG("free wd queue success");
}

static KAE_QUEUE_DATA_NODE_S* kae_new_wd_queue_memory(int algtype)
{
    KAE_QUEUE_DATA_NODE_S *queue_node = NULL;
    
    queue_node = (KAE_QUEUE_DATA_NODE_S *)kae_malloc(sizeof(KAE_QUEUE_DATA_NODE_S));
    if (queue_node == NULL) {
        US_ERR("malloc failed");
        return NULL;
    }
    kae_memset(queue_node, 0, sizeof(KAE_QUEUE_DATA_NODE_S));
    
    queue_node->kae_wd_queue = wd_new_queue(algtype);
    if (queue_node->kae_wd_queue == NULL) {
        US_ERR("new wd queue fail");
        goto err;
    }
    
    queue_node->kae_queue_mem_pool = create_alg_wd_queue_mempool(algtype, queue_node->kae_wd_queue);
    if (queue_node->kae_queue_mem_pool == NULL) {
        US_ERR("request mempool fail!");
        goto err;
    }
    
    return queue_node;
    
err:
    kae_free_wd_queue_memory(queue_node, NULL);
    return NULL;
}

KAE_QUEUE_DATA_NODE_S* kae_get_node_from_pool(KAE_QUEUE_POOL_HEAD_S* pool_head)
{
    KAE_QUEUE_DATA_NODE_S *queue_data_node = NULL;

    if (pool_head == NULL) {
        US_ERR("input params pool_head is null");
        return NULL;
    }

    queue_data_node = kae_get_queue_data_from_list(pool_head);
    if (queue_data_node == NULL) {
        queue_data_node = kae_new_wd_queue_memory(pool_head->algtype);
    }

    return queue_data_node;
}

static void kae_set_pool_use_num(KAE_QUEUE_POOL_HEAD_S *pool, int set_num)
{
    pthread_mutex_lock(&pool->kae_queue_mutex);
    if (set_num > pool->pool_use_num) {
        pool->pool_use_num = set_num;
    }
    (void)pthread_mutex_unlock(&pool->kae_queue_mutex);
}

int kae_put_node_to_pool(KAE_QUEUE_POOL_HEAD_S* pool_head,  KAE_QUEUE_DATA_NODE_S* node_data)
{
    int i = 0;
    KAE_QUEUE_POOL_HEAD_S *temp_pool = pool_head;
    KAE_QUEUE_POOL_HEAD_S *last_pool = NULL;
    
    if (node_data == NULL || pool_head == NULL) {
        return 0;
    }

    US_DEBUG("Add nodedata to pool");

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
                        kae_set_pool_use_num(temp_pool, i + 1);
                    }
    
                    US_DEBUG("kae put queue node to pool, queue_node id is %d.", i);
                    return 1;
                }
            }
        }
        last_pool = temp_pool;
        temp_pool = temp_pool->next;
        /* if no empty pool to add,new a pool */
        if (temp_pool == NULL) {
            pthread_mutex_lock(&last_pool->destroy_mutex);
            if (last_pool->next == NULL) {
                temp_pool = kae_init_queue_pool(last_pool->algtype);
                if (temp_pool == NULL) {
                    (void)pthread_mutex_unlock(&last_pool->destroy_mutex);
                    break;
                }
                last_pool->next = temp_pool;
            }
            (void)pthread_mutex_unlock(&last_pool->destroy_mutex);
        }
    }
    /* if not added,free it */    
    kae_free_wd_queue_memory(node_data, NULL);
    return 0;
}

void kae_queue_pool_reset(KAE_QUEUE_POOL_HEAD_S* pool_head)
{
    (void)pool_head;
    return;
}

void kae_queue_pool_destroy(KAE_QUEUE_POOL_HEAD_S* pool_head, release_engine_ctx_cb release_fn)
{
    int error = 0;
    int i = 0;
    KAE_QUEUE_DATA_NODE_S *queue_data_node = (KAE_QUEUE_DATA_NODE_S *)NULL;
    KAE_QUEUE_POOL_HEAD_S *temp_pool = NULL;
    KAE_QUEUE_POOL_HEAD_S *cur_pool = pool_head;

    while (cur_pool != NULL) {
        error = pthread_mutex_lock(&cur_pool->destroy_mutex);
        if (error != 0) {
            return;
        }

        error = pthread_mutex_lock(&cur_pool->kae_queue_mutex);
        if (error != 0) {
            (void)pthread_mutex_unlock(&cur_pool->destroy_mutex);
            return;
        }
        for (i = 0; i < cur_pool->pool_use_num; i++) {
            queue_data_node = cur_pool->kae_queue_pool[i].node_data;
            if (queue_data_node != NULL) {
                kae_free_wd_queue_memory(queue_data_node, release_fn);
                US_DEBUG("kae queue node destroy success. queue_node id =%d", i);
                cur_pool->kae_queue_pool[i].node_data = NULL;
            }
        }
        US_DEBUG("pool use num :%d.", cur_pool->pool_use_num);

        kae_free(cur_pool->kae_queue_pool);

        (void)pthread_mutex_unlock(&cur_pool->kae_queue_mutex);
        (void)pthread_mutex_unlock(&cur_pool->destroy_mutex);

        pthread_mutex_destroy(&cur_pool->kae_queue_mutex);
        pthread_mutex_destroy(&cur_pool->destroy_mutex);

        temp_pool = cur_pool;

        kae_free(cur_pool);

        cur_pool = temp_pool->next;
    }

    US_DEBUG("kae queue pool destory success.");
    return;
}

void kae_queue_pool_check_and_release(KAE_QUEUE_POOL_HEAD_S* pool_head, release_engine_ctx_cb release_fn)
{
    int i = 0;
    int error;
    time_t current_time;
    KAE_QUEUE_DATA_NODE_S *queue_data_node = NULL;
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

            if (KAE_SPIN_TRYLOCK(cur_pool->kae_queue_pool[i].spinlock)) {
                if ((cur_pool->kae_queue_pool[i].node_data == NULL) ||
                    (difftime(current_time, cur_pool->kae_queue_pool[i].add_time) < CHECK_QUEUE_TIME_SECONDS)) {
                    KAE_SPIN_UNLOCK(cur_pool->kae_queue_pool[i].spinlock);
                    continue;
                } else {
                    queue_data_node = cur_pool->kae_queue_pool[i].node_data;
                    cur_pool->kae_queue_pool[i].node_data = (KAE_QUEUE_DATA_NODE_S *)NULL;
                    KAE_SPIN_UNLOCK(cur_pool->kae_queue_pool[i].spinlock);

                    kae_free_wd_queue_memory(queue_data_node, release_fn);

                    US_DEBUG("hpre queue list release success. queue node id =%d", i);
                }
            }
        }
        
        (void)pthread_mutex_unlock(&cur_pool->destroy_mutex);
        cur_pool = cur_pool->next;
    }
    
    return;
}

