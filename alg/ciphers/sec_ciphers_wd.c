/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for KAE ciphers using wd interface
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
 * @file sec_cipher_wd.c
 *
 * This file provides the implemenation for SEC ciphers using wd interface
 *
 *****************************************************************************/
#include "sec_ciphers_wd.h"
#include "sec_ciphers_utils.h"
#include "wd_queue_memory.h"
#include "engine_utils.h"
#include "engine_types.h"

#define OUTPUT_CACHE_SIZE  (256*1024)
#define INPUT_CACHE_SIZE   (256*1024)
#define MAX_KEY_SIZE       64
#define MAX_IV_SIZE        16

     
KAE_QUEUE_POOL_HEAD_S* g_sec_ciphers_qnode_pool = NULL;
static cipher_engine_ctx_t* wd_ciphers_new_engine_ctx(KAE_QUEUE_DATA_NODE_S* q_node, cipher_priv_ctx_t* priv_ctx);

void wd_ciphers_free_engine_ctx(void* engine_ctx)
{
    cipher_engine_ctx_t* e_cipher_ctx = (cipher_engine_ctx_t *)engine_ctx;
    if (e_cipher_ctx == NULL) {
        return;
    }

    if (e_cipher_ctx->op_data.in && e_cipher_ctx->setup.br.usr) {
        e_cipher_ctx->setup.br.free(e_cipher_ctx->setup.br.usr, (void *)e_cipher_ctx->op_data.in); 
        e_cipher_ctx->op_data.in = NULL;
    }
    
    if (e_cipher_ctx->op_data.out && e_cipher_ctx->setup.br.usr) {
        e_cipher_ctx->setup.br.free(e_cipher_ctx->setup.br.usr, (void *)e_cipher_ctx->op_data.out); 
        e_cipher_ctx->op_data.out = NULL;
    }

    if (e_cipher_ctx->op_data.iv && e_cipher_ctx->setup.br.usr) {
        e_cipher_ctx->setup.br.free(e_cipher_ctx->setup.br.usr, (void *)e_cipher_ctx->op_data.iv); 
        e_cipher_ctx->op_data.iv = NULL;
    }

    OPENSSL_free(e_cipher_ctx);
    e_cipher_ctx = NULL;
}

static cipher_engine_ctx_t* wd_ciphers_new_engine_ctx(KAE_QUEUE_DATA_NODE_S* q_node, cipher_priv_ctx_t* priv_ctx)
{
    cipher_engine_ctx_t   *e_cipher_ctx = NULL;

    e_cipher_ctx = (cipher_engine_ctx_t *)OPENSSL_malloc(sizeof(cipher_engine_ctx_t));
    if (e_cipher_ctx == NULL) {
        US_ERR("OPENSSL_malloc ctx failed");
        return NULL;
    }
    kae_memset(e_cipher_ctx, 0, sizeof(cipher_engine_ctx_t));
    
    e_cipher_ctx->setup.br.alloc = kae_wd_alloc_blk;
    e_cipher_ctx->setup.br.free = kae_wd_free_blk;
    e_cipher_ctx->setup.br.iova_map = kae_dma_map;
    e_cipher_ctx->setup.br.iova_unmap = kae_dma_unmap;
    e_cipher_ctx->setup.br.usr = q_node->kae_queue_mem_pool;

    e_cipher_ctx->op_data.in = e_cipher_ctx->setup.br.alloc(e_cipher_ctx->setup.br.usr, INPUT_CACHE_SIZE); 
    if (e_cipher_ctx->op_data.in == NULL) {
        US_ERR("alloc opdata in buf failed");
        goto err;
    }

    e_cipher_ctx->op_data.out = e_cipher_ctx->setup.br.alloc(e_cipher_ctx->setup.br.usr, OUTPUT_CACHE_SIZE); 
    if (e_cipher_ctx->op_data.out == NULL) {
        US_ERR("alloc opdata out buf failed");
        goto err;
    }

    e_cipher_ctx->op_data.iv = e_cipher_ctx->setup.br.alloc(e_cipher_ctx->setup.br.usr, priv_ctx->iv_len); 
    if (e_cipher_ctx->op_data.iv == NULL) {
        US_ERR("alloc opdata iv buf failed");
        goto err;
    }
        
    e_cipher_ctx->priv_ctx = priv_ctx;  // point to each other
    e_cipher_ctx->q_node = q_node;      // point to each other
    q_node->engine_ctx = e_cipher_ctx;  // point to each other

    return e_cipher_ctx;
    
err:
    (void)wd_ciphers_free_engine_ctx(e_cipher_ctx);  

    return NULL;
}

static int wd_ciphers_init_engine_ctx(cipher_engine_ctx_t *e_cipher_ctx)
{
    struct wd_queue *q = e_cipher_ctx->q_node->kae_wd_queue;
    cipher_priv_ctx_t* priv_ctx = e_cipher_ctx->priv_ctx;
        
    if (e_cipher_ctx->wd_ctx != NULL) {
        US_WARN("wd ctx is in used by other ciphers");

        return KAE_FAIL;
    }
    
    e_cipher_ctx->setup.alg  = (enum wcrypto_cipher_alg)priv_ctx->c_alg;    // for example: WD_CIPHER_SM4;
    e_cipher_ctx->setup.mode = (enum wcrypto_cipher_mode)priv_ctx->c_mode;  // for example: WD_CIPHER_CBC;
    e_cipher_ctx->setup.cb = (wcrypto_cb)sec_ciphers_cb;
    e_cipher_ctx->wd_ctx = wcrypto_create_cipher_ctx(q, &e_cipher_ctx->setup);
    
    if (e_cipher_ctx->wd_ctx == NULL) {
        US_ERR("wd create sec cipher ctx fail!");
        return KAE_FAIL;
    }

    wcrypto_set_cipher_key(e_cipher_ctx->wd_ctx, priv_ctx->key, priv_ctx->key_len);

    return KAE_SUCCESS;
}

cipher_engine_ctx_t* wd_ciphers_get_engine_ctx(cipher_priv_ctx_t* priv_ctx)
{
    KAE_QUEUE_DATA_NODE_S   *q_node = NULL;
    cipher_engine_ctx_t        *e_cipher_ctx = NULL;
    
    if (unlikely(priv_ctx == NULL)) {
        US_ERR("sec cipher priv ctx NULL!");
        return NULL;
    }

    q_node = kae_get_node_from_pool(g_sec_ciphers_qnode_pool);
    if (q_node == NULL) {
        US_ERR_LIMIT("failed to get hardware queue");
        return NULL;
    }

    e_cipher_ctx = (cipher_engine_ctx_t *)q_node->engine_ctx;
    if (e_cipher_ctx == NULL) {
        e_cipher_ctx = wd_ciphers_new_engine_ctx(q_node, priv_ctx);
        if (e_cipher_ctx == NULL) {
            US_WARN("sec new engine ctx fail!");
            (void)kae_put_node_to_pool(g_sec_ciphers_qnode_pool, q_node);
            return NULL;
        }
    }
    
    e_cipher_ctx->priv_ctx = priv_ctx;
    
    if (wd_ciphers_init_engine_ctx(e_cipher_ctx) == KAE_FAIL) {
        US_WARN("init engine ctx fail!");
        wd_ciphers_put_engine_ctx(e_cipher_ctx);
        return NULL;
    }
    
    return e_cipher_ctx;
}

void wd_ciphers_put_engine_ctx(cipher_engine_ctx_t* e_cipher_ctx)
{
    if (unlikely(e_cipher_ctx == NULL)) {
        US_WARN("sec cipher engine ctx NULL!");
        return;
    }

    if (e_cipher_ctx->wd_ctx != NULL) {
        wcrypto_del_cipher_ctx(e_cipher_ctx->wd_ctx);
        e_cipher_ctx->wd_ctx = NULL;
    }
    
    if (e_cipher_ctx->priv_ctx && e_cipher_ctx->priv_ctx->ecb_encryto) {
        if (e_cipher_ctx->priv_ctx->ecb_encryto->ecb_ctx != NULL) {
            EVP_CIPHER_CTX_free(e_cipher_ctx->priv_ctx->ecb_encryto->ecb_ctx);
            e_cipher_ctx->priv_ctx->ecb_encryto->ecb_ctx = NULL;
        }

        kae_free(e_cipher_ctx->priv_ctx->ecb_encryto->key2);
        kae_free(e_cipher_ctx->priv_ctx->ecb_encryto->encryto_iv);
        kae_free(e_cipher_ctx->priv_ctx->ecb_encryto->iv_out);
        kae_free(e_cipher_ctx->priv_ctx->ecb_encryto);
    }

    if (e_cipher_ctx->q_node != NULL) {
        (void)kae_put_node_to_pool(g_sec_ciphers_qnode_pool, e_cipher_ctx->q_node);
    }

    e_cipher_ctx = NULL;

    return;
}

int wd_ciphers_do_crypto_impl(cipher_engine_ctx_t *e_cipher_ctx) 
{
    int ret = -WD_EINVAL;
    int trycount = 0;
    
    if (unlikely(e_cipher_ctx == NULL)) {
        US_ERR("do cipher ctx NULL!");
        return KAE_FAIL;
    }

again:    
    ret = wcrypto_do_cipher(e_cipher_ctx->wd_ctx, &e_cipher_ctx->op_data, NULL);
    if (ret != WD_SUCCESS) {
        if (ret == -WD_EBUSY && trycount <= 5) { // try 5 times
            US_WARN("do cipher busy, retry again!");
            trycount++;
            goto again;
        } else {
            US_ERR("do cipher failed!");
            return KAE_FAIL;
        }
    }
    
    return KAE_SUCCESS;
}

inline void wd_ciphers_set_input_data(cipher_engine_ctx_t *e_cipher_ctx)
{
    // fill engine ctx opdata
    cipher_priv_ctx_t* priv_ctx = e_cipher_ctx->priv_ctx;
    
    kae_memcpy(((uint8_t *)e_cipher_ctx->op_data.in + priv_ctx->offset), priv_ctx->in, priv_ctx->do_cipher_len);

    if (priv_ctx->encrypt == OPENSSL_ENCRYPTION) {
        e_cipher_ctx->op_data.op_type = WCRYPTO_CIPHER_ENCRYPTION;
    } else {
        e_cipher_ctx->op_data.op_type = WCRYPTO_CIPHER_DECRYPTION;
    }
    
    e_cipher_ctx->op_data.in_bytes = priv_ctx->do_cipher_len + priv_ctx->offset;
    
    // the real out data start at opdata.out + offset
    e_cipher_ctx->op_data.out_bytes = priv_ctx->offset + priv_ctx->do_cipher_len;
    kae_memcpy(e_cipher_ctx->op_data.iv, priv_ctx->iv, priv_ctx->iv_len);
    e_cipher_ctx->op_data.iv_bytes = priv_ctx->iv_len;
}

inline void wd_ciphers_get_output_data(cipher_engine_ctx_t *e_cipher_ctx)
{
    cipher_priv_ctx_t* priv_ctx = e_cipher_ctx->priv_ctx;
    
    // the real out data start at opdata.out + offset
    kae_memcpy(priv_ctx->out, (uint8_t*)e_cipher_ctx->op_data.out + priv_ctx->offset,
               priv_ctx->do_cipher_len);
}

inline uint32_t wd_ciphers_get_do_cipher_len(uint32_t offset, int leftlen)
{
    uint32_t do_cipher_len = 0;
    int max_input_datalen = INPUT_CACHE_SIZE - offset;
    /* 
     * Note: Small encrypted block can be encrypted once.
     * or the last encrypted slice of a large encrypted block
     */
    if (leftlen <= max_input_datalen) {
        do_cipher_len = leftlen;
    } else {
        do_cipher_len = max_input_datalen;
    }

    return do_cipher_len;
}

KAE_QUEUE_POOL_HEAD_S* wd_ciphers_get_qnode_pool(void)
{
    return g_sec_ciphers_qnode_pool;
}

int wd_ciphers_init_qnode_pool(void)
{
    kae_queue_pool_destroy(g_sec_ciphers_qnode_pool, wd_ciphers_free_engine_ctx);

    g_sec_ciphers_qnode_pool = kae_init_queue_pool(WCRYPTO_CIPHER);
    if (g_sec_ciphers_qnode_pool == NULL) {
        US_ERR("do cipher ctx NULL!");
        return KAE_FAIL;
    }
    
    return KAE_SUCCESS;
}

void wd_ciphers_uninit_qnode_pool(void)
{
    kae_queue_pool_destroy(g_sec_ciphers_qnode_pool, wd_ciphers_free_engine_ctx);
    g_sec_ciphers_qnode_pool = NULL;
}
