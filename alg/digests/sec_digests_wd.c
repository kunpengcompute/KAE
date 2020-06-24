/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for KAE engine utils dealing with wrapdrive
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

#include "sec_digests_wd.h"
#include "wd_queue_memory.h"
#include "engine_utils.h"
#include "engine_types.h"
#include "engine_log.h"

static KAE_QUEUE_POOL_HEAD_S* g_sec_digests_qnode_pool = NULL;
static digest_engine_ctx_t* wd_digests_new_engine_ctx(KAE_QUEUE_DATA_NODE_S* q_node, sec_digest_priv_t* md_ctx);
static int wd_digests_init_engine_ctx(digest_engine_ctx_t *e_digest_ctx);

void wd_digests_free_engine_ctx(void* digest_ctx)
{
    digest_engine_ctx_t* e_digest_ctx = (digest_engine_ctx_t *)digest_ctx;
    if (e_digest_ctx == NULL) {
        return;
    }

    if (e_digest_ctx->op_data.in && e_digest_ctx->setup.br.usr) {
        e_digest_ctx->setup.br.free(e_digest_ctx->setup.br.usr, (void *)e_digest_ctx->op_data.in); 
        e_digest_ctx->op_data.in = NULL;
    }
    
    if (e_digest_ctx->op_data.out && e_digest_ctx->setup.br.usr) {
        e_digest_ctx->setup.br.free(e_digest_ctx->setup.br.usr, (void *)e_digest_ctx->op_data.out); 
        e_digest_ctx->op_data.out = NULL;
    }

    OPENSSL_free(e_digest_ctx);
    e_digest_ctx = NULL;

    return;
}

static digest_engine_ctx_t* wd_digests_new_engine_ctx(KAE_QUEUE_DATA_NODE_S* q_node, sec_digest_priv_t* md_ctx)
{
    digest_engine_ctx_t *e_digest_ctx = NULL;
    e_digest_ctx = (digest_engine_ctx_t *)OPENSSL_malloc(sizeof(digest_engine_ctx_t));
    if (e_digest_ctx == NULL) {
        US_ERR("digest engine_ctx malloc fail.");
        return NULL;
    }
    kae_memset(e_digest_ctx, 0, sizeof(digest_engine_ctx_t));

    e_digest_ctx->setup.br.alloc = kae_wd_alloc_blk;
    e_digest_ctx->setup.br.free = kae_wd_free_blk;
    e_digest_ctx->setup.br.iova_map = kae_dma_map;
    e_digest_ctx->setup.br.iova_unmap = kae_dma_unmap;
    e_digest_ctx->setup.br.usr = q_node->kae_queue_mem_pool;

    e_digest_ctx->op_data.in = e_digest_ctx->setup.br.alloc(e_digest_ctx->setup.br.usr, DIGEST_BLOCK_SIZE); 
    if (e_digest_ctx->op_data.in == NULL) {
        US_ERR("alloc opdata in buf failed");
        goto err;
    }

    e_digest_ctx->op_data.out = e_digest_ctx->setup.br.alloc(e_digest_ctx->setup.br.usr, DIGEST_BLOCK_SIZE); 
    if (e_digest_ctx->op_data.out == NULL) {
        US_ERR("alloc opdata out buf failed");
        goto err;
    }
    
    e_digest_ctx->md_ctx = md_ctx;      // point to each other
    e_digest_ctx->q_node = q_node;      // point to each other
    q_node->engine_ctx = e_digest_ctx;  // point to each other

    return e_digest_ctx;
    
err:
    wd_digests_free_engine_ctx(e_digest_ctx);  

    return NULL;
}

static int wd_digests_init_engine_ctx(digest_engine_ctx_t *e_digest_ctx)
{
    struct wd_queue *q = e_digest_ctx->q_node->kae_wd_queue;
    sec_digest_priv_t* md_ctx = e_digest_ctx->md_ctx;

    if (e_digest_ctx->wd_ctx != NULL) {
        US_WARN("wd ctx is in used by other digests");
        return KAE_FAIL;
    }
    
    e_digest_ctx->setup.alg  = (enum wcrypto_digest_alg)md_ctx->d_alg;    // for example: WD_SM3;
    e_digest_ctx->setup.mode = WCRYPTO_DIGEST_NORMAL;
    e_digest_ctx->setup.cb = (wcrypto_cb)sec_digests_cb;
    e_digest_ctx->wd_ctx = wcrypto_create_digest_ctx(q, &e_digest_ctx->setup);
    if (e_digest_ctx->wd_ctx == NULL) {
        US_ERR("wd create sec digest ctx fail!");
        return KAE_FAIL;
    }

    return KAE_SUCCESS;
}

digest_engine_ctx_t* wd_digests_get_engine_ctx(sec_digest_priv_t* md_ctx)
{
    KAE_QUEUE_DATA_NODE_S      *q_node = NULL;
    digest_engine_ctx_t        *e_digest_ctx = NULL;

    if (unlikely(md_ctx == NULL)) {
        US_WARN("sec digest priv ctx NULL!");
        return NULL;
    }

    q_node = kae_get_node_from_pool(g_sec_digests_qnode_pool);
    if (q_node == NULL) {
        US_ERR_LIMIT("failed to get hardware queue");
        return NULL;
    }

    e_digest_ctx = (digest_engine_ctx_t *)q_node->engine_ctx;
    if (e_digest_ctx == NULL) {
        e_digest_ctx = wd_digests_new_engine_ctx(q_node, md_ctx);
        if (e_digest_ctx == NULL) {
            US_WARN("sec new engine ctx fail!");
            (void)kae_put_node_to_pool(g_sec_digests_qnode_pool, q_node);
            return NULL;
        }
    }
    
    e_digest_ctx->md_ctx = md_ctx;
    md_ctx->e_digest_ctx = e_digest_ctx;
    
    if (wd_digests_init_engine_ctx(e_digest_ctx) == KAE_FAIL) {
        US_WARN("init engine ctx fail!");
        wd_digests_put_engine_ctx(e_digest_ctx);
        return NULL;
    }
    
    return e_digest_ctx;
}

void wd_digests_put_engine_ctx(digest_engine_ctx_t* e_digest_ctx)
{
    if (unlikely(e_digest_ctx == NULL)) {
        US_WARN("sec digest engine ctx NULL!");
        return;
    }

    if (e_digest_ctx->md_ctx->last_update_buff != NULL) {
        kae_free(e_digest_ctx->md_ctx->last_update_buff);
    }

    if (e_digest_ctx->wd_ctx != NULL) {
        wcrypto_del_digest_ctx(e_digest_ctx->wd_ctx);
        e_digest_ctx->wd_ctx = NULL;
    }

    if (e_digest_ctx->q_node != NULL) {
        (void)kae_put_node_to_pool(g_sec_digests_qnode_pool, e_digest_ctx->q_node);
    }

    e_digest_ctx = NULL;

    return;
}

int wd_digests_doimpl(digest_engine_ctx_t *e_digest_ctx) 
{
    int ret;
    int trycount = 0;
        
    if (unlikely(e_digest_ctx == NULL)) {
        US_ERR("do digest ctx NULL!");
        return KAE_FAIL;
    }

again:    
    ret = wcrypto_do_digest(e_digest_ctx->wd_ctx, &e_digest_ctx->op_data, NULL);  
    if (ret != WD_SUCCESS) {
        if (ret == -WD_EBUSY && trycount <= 5) { // try 5 times
            US_WARN("do digest busy, retry again!");
            trycount++;
            goto again;
        } else {
            US_ERR("do digest failed!");
            return KAE_FAIL;
        }
    }
    
    return KAE_SUCCESS;
}

void wd_digests_set_input_data(digest_engine_ctx_t *e_digest_ctx)
{
    // fill engine ctx opdata
    sec_digest_priv_t* md_ctx = e_digest_ctx->md_ctx;

    kae_memcpy((uint8_t *)e_digest_ctx->op_data.in, md_ctx->in, md_ctx->do_digest_len);
    e_digest_ctx->op_data.in_bytes = md_ctx->do_digest_len;
    e_digest_ctx->op_data.out_bytes = md_ctx->out_len;

    e_digest_ctx->op_data.has_next = (md_ctx->state == SEC_DIGEST_FINAL) ? false : true;
}

inline void wd_digests_get_output_data(digest_engine_ctx_t *e_digest_ctx)
{
    sec_digest_priv_t* md_ctx = e_digest_ctx->md_ctx;
    
    // the real out data start at opdata.out + offset
    if (e_digest_ctx->op_data.has_next == false) {
        kae_memcpy(md_ctx->out, (uint8_t*)e_digest_ctx->op_data.out, md_ctx->out_len);
    }
}

inline uint32_t wd_digests_get_do_digest_len(digest_engine_ctx_t *e_digest_ctx, int leftlen)
{
    uint32_t do_digest_len = 0;
    int max_input_datalen = DIGEST_BLOCK_SIZE;
    /*
     * Note: Small encrypted block can be encrypted once.
     * or the last encrypted slice of a large encrypted block
     */
    if (leftlen <= max_input_datalen) {
        do_digest_len = leftlen;
    } else {
        do_digest_len = max_input_datalen;
    }
    
    return do_digest_len;
}

KAE_QUEUE_POOL_HEAD_S* wd_digests_get_qnode_pool(void)
{
    return g_sec_digests_qnode_pool;
}

int wd_digests_init_qnode_pool(void)
{
    kae_queue_pool_destroy(g_sec_digests_qnode_pool, wd_digests_free_engine_ctx);

    g_sec_digests_qnode_pool = kae_init_queue_pool(WCRYPTO_DIGEST);
    if (g_sec_digests_qnode_pool == NULL) {
        US_ERR("do digest ctx NULL!");
        return KAE_FAIL;
    }

    return KAE_SUCCESS;
}

void wd_digests_uninit_qnode_pool(void)
{
    kae_queue_pool_destroy(g_sec_digests_qnode_pool, wd_digests_free_engine_ctx);
    g_sec_digests_qnode_pool = NULL;
}