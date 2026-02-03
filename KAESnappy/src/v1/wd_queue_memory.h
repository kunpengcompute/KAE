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

/*****************************************************************************
 * @file wd_queue_memory.h
 *
 * This file provides the queue and mempool for zlib;
 *
 *****************************************************************************/

#ifndef __KAESNAPPY_QUEUE_MEMORY_H
#define __KAESNAPPY_QUEUE_MEMORY_H

#include <semaphore.h>
#include "uadk/v1/wd.h"
#include "kaesnappy_utils.h"

#define KAE_QUEUE_POOL_MAX_SIZE     (512)
#define CHECK_QUEUE_TIME_SECONDS    (60)  // seconds

#define COMP_BLOCK_NUM              (4)
#define COMP_BLOCK_SIZE             (2 * 1024 * 1024)

typedef void (*kae_release_priv_ctx_cb)(void* priv_ctx);

typedef struct KAE_QUEUE_DATA_NODE {
    struct wd_queue            *kae_wd_queue;
    void                       *kae_queue_mem_pool;
    int                         comp_alg_type;
    void                       *priv_ctx;
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

void kaesnappy_wd_free_blk(void *pool, void *blk);
void *kaesnappy_wd_alloc_blk(void *pool, size_t size);
void *kaesnappy_dma_map(void *usr, void *va, size_t sz);
void kaesnappy_dma_unmap(void *usr, void *va, void *dma, size_t sz);

KAE_QUEUE_POOL_HEAD_S* kaesnappy_init_queue_pool (int algtype);
KAE_QUEUE_DATA_NODE_S* kaesnappy_get_node_from_pool(KAE_QUEUE_POOL_HEAD_S* pool_head, int alg_comp_type, int comp_optype);
int kaesnappy_put_node_to_pool(KAE_QUEUE_POOL_HEAD_S* pool_head, KAE_QUEUE_DATA_NODE_S* node_data, kae_release_priv_ctx_cb release_fn);
void kaesnappy_queue_pool_reset(KAE_QUEUE_POOL_HEAD_S* pool_head);
void kaesnappy_queue_pool_check_and_release(KAE_QUEUE_POOL_HEAD_S* pool_head, kae_release_priv_ctx_cb release_ectx_fn);

#endif

