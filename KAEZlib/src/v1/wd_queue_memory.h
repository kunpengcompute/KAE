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

#ifndef __KAEZIP_QUEUE_MEMORY_H
#define __KAEZIP_QUEUE_MEMORY_H

#include <semaphore.h>
#include "uadk/v1/wd.h"
#include "kaezip_utils.h"
#include "kaezip_dev.h"

#define KAE_QUEUE_POOL_MAX_SIZE     (512)
#define CHECK_QUEUE_TIME_SECONDS    (60)  // seconds

typedef enum {
    SYNC_MODE = 0,
    ASYNC_MODE,
} operation_mode;

typedef void (*kae_release_priv_ctx_cb)(void* priv_ctx);

typedef struct KAE_QUEUE_DATA_NODE {
    struct wd_queue            *kae_wd_queue;
    void                       *kae_queue_mem_pool;
    int                         comp_alg_type;
    void                       *priv_ctx;
    int                         win_size;
    int                         is_sgl;
} KAE_QUEUE_DATA_NODE_S;

typedef struct KAE_QUEUE_POOL_NODE {
    // int using_flag; /* used:true,nouse:false */
    struct kae_spinlock spinlock;
    time_t add_time;
    // int index;   /* index of node,init:-1 */
    KAE_QUEUE_DATA_NODE_S *node_data;
    // KAE_QUEUE_POOL_NODE_S *next;
} KAE_QUEUE_POOL_NODE_S;

typedef struct KAE_QUEUE_POOL_HEAD {
    // int init_flag;
    int pool_use_num;
    int algtype;  /* alg type,just init at init pool */
    pthread_mutex_t destroy_mutex;
    pthread_mutex_t kae_queue_mutex;
    struct KAE_QUEUE_POOL_HEAD *next;  /* next pool */
    KAE_QUEUE_POOL_NODE_S *kae_queue_pool; /* point to a attray */
} KAE_QUEUE_POOL_HEAD_S;

void kaezip_wd_free_blk(void *pool, void *blk);
void *kaezip_wd_alloc_blk(void *pool, size_t size);
void *kaezip_dma_map(void *usr, void *va, size_t sz);
void kaezip_dma_unmap(void *usr, void *va, void *dma, size_t sz);

KAE_QUEUE_POOL_HEAD_S* kaezip_init_queue_pool (int algtype);
KAE_QUEUE_DATA_NODE_S* kaezip_get_node_from_pool(KAE_QUEUE_POOL_HEAD_S* pool_head, int alg_comp_type, int comp_optype, 
                                                    int win_size, int is_sgl, const device_config_t *config, operation_mode mode);
int kaezip_put_node_to_pool (KAE_QUEUE_POOL_HEAD_S* pool_head, KAE_QUEUE_DATA_NODE_S* node_data, kae_release_priv_ctx_cb release_fn);
void kaezip_queue_pool_destroy(KAE_QUEUE_POOL_HEAD_S* pool_head, kae_release_priv_ctx_cb release_fn);
void kaezip_queue_pool_check_and_release(KAE_QUEUE_POOL_HEAD_S* pool_head, kae_release_priv_ctx_cb release_ectx_fn);

void kaezip_wd_free_blk(void *pool, void *blk);
void *kaezip_wd_alloc_blk(void *pool, size_t size);
void *kaezip_wd_alloc_sgl(void *pool, size_t size);
void kaezip_wd_free_sgl(void *pool, void *sgl);
void *kaezip_dma_map(void *usr, void *va, size_t sz);
void kaezip_dma_unmap(void *usr, void *va, void *dma, size_t sz);
void *kaezip_dma_map_sgl(void *usr, void *va, size_t sz);
void kaezip_dma_unmap_sgl(void *usr, void *va, void *dma, size_t sz);

KAE_QUEUE_POOL_HEAD_S* kaezip_init_queue_pool (int algtype);
void kaezip_free_wd_queue_memory(KAE_QUEUE_DATA_NODE_S *queue_node, kae_release_priv_ctx_cb release_fn);

#endif

