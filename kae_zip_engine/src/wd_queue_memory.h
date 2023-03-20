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
 * @file wd_queue_memory.h
 *
 * This file provides the queue and mempool for zlib;
 *
 *****************************************************************************/

#ifndef __KAEZIP_QUEUE_MEMORY_H
#define __KAEZIP_QUEUE_MEMORY_H

#include <semaphore.h>
#include "wd.h"
#include "kaezip_utils.h"

#define KAE_QUEUE_POOL_MAX_SIZE     (512)
#define CHECK_QUEUE_TIME_SECONDS    (60)  // seconds

#define COMP_BLOCK_NUM              (4)
#define COMP_BLOCK_SIZE             (1024 * 1024)

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

void kaezip_wd_free_blk(void *pool, void *blk);
void *kaezip_wd_alloc_blk(void *pool, size_t size);
void *kaezip_dma_map(void *usr, void *va, size_t sz);
void kaezip_dma_unmap(void *usr, void *va, void *dma, size_t sz);

KAE_QUEUE_POOL_HEAD_S* kaezip_init_queue_pool (int algtype);
KAE_QUEUE_DATA_NODE_S* kaezip_get_node_from_pool(KAE_QUEUE_POOL_HEAD_S* pool_head, int alg_comp_type, int comp_optype);
int kaezip_put_node_to_pool (KAE_QUEUE_POOL_HEAD_S* pool_head, KAE_QUEUE_DATA_NODE_S* node_data);
void kaezip_queue_pool_reset(KAE_QUEUE_POOL_HEAD_S* pool_head);
void kaezip_queue_pool_destroy(KAE_QUEUE_POOL_HEAD_S* pool_head, kae_release_priv_ctx_cb release_fn);
void kaezip_queue_pool_check_and_release(KAE_QUEUE_POOL_HEAD_S* pool_head, kae_release_priv_ctx_cb release_ectx_fn);

#endif

