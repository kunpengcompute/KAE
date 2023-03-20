/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the interface for wd_queue_memory.c
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

#ifndef __WD_QUEUE_MEMORY_H
#define __WD_QUEUE_MEMORY_H

#include <semaphore.h>
#include "wd.h"
#include "wd_alg_queue.h"
#include "engine_utils.h"

#define KAE_QUEUE_POOL_MAX_SIZE    512
#define CHECK_QUEUE_TIME_SECONDS 5 // seconds

/*
 * once use 3 block for ctx&pubkey*prikey.
 * the max Concurrent num = HPRE_BLOCK_NUM/3
 * when use 4096bit rsa. block use max is 3576.
 * 3576 = sizeof(ctx)(248)+ pubkey_size(1024) + prikey_size(2304)
 * that means  max block used is 2304. set 4096 for reserve
 */
#define RSA_BLOCK_NUM       16
#define RSA_BLOCK_SIZE      4096

#define DH_BLOCK_NUM       16
#define DH_BLOCK_SIZE      4096

#define CIPHER_BLOCK_NUM   4
#define CIPHER_BLOCK_SIZE  (272*1024) 

#define DIGEST_BLOCK_NUM   4
#define DIGEST_BLOCK_SIZE  (512 * 1024)

typedef void (*release_engine_ctx_cb)(void* engine_ctx);

typedef struct KAE_QUEUE_DATA_NODE {
    struct wd_queue            *kae_wd_queue;
    struct wd_queue_mempool    *kae_queue_mem_pool;
    void                       *engine_ctx;
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

struct wd_queue_mempool {
    struct wd_queue *q;
    void *base;
    unsigned int *bitmap;
    unsigned int block_size;
    unsigned int block_num;
    unsigned int mem_size;
    unsigned int block_align_size;
    unsigned int free_num;
    unsigned int fail_times;
    unsigned long long index;
    sem_t mempool_sem;
    int dev;
};

struct wd_queue_mempool *wd_queue_mempool_create(struct wd_queue *q, unsigned int block_size, unsigned int block_num);

void wd_queue_mempool_destroy(struct wd_queue_mempool *pool);

void kae_wd_free_blk(void *pool, void *blk);
void *kae_wd_alloc_blk(void *pool, size_t size);

void *kae_dma_map(void *usr, void *va, size_t sz);

void kae_dma_unmap(void *usr, void *va, void *dma, size_t sz);

KAE_QUEUE_POOL_HEAD_S* kae_init_queue_pool (int algtype);
KAE_QUEUE_DATA_NODE_S* kae_get_node_from_pool(KAE_QUEUE_POOL_HEAD_S* pool_head);
int kae_put_node_to_pool (KAE_QUEUE_POOL_HEAD_S* pool_head, KAE_QUEUE_DATA_NODE_S* node_data);
void kae_queue_pool_reset(KAE_QUEUE_POOL_HEAD_S* pool_head);
void kae_queue_pool_destroy(KAE_QUEUE_POOL_HEAD_S* pool_head, release_engine_ctx_cb release_fn);
void kae_queue_pool_check_and_release(KAE_QUEUE_POOL_HEAD_S* pool_head, release_engine_ctx_cb release_ectx_fn);

#endif

