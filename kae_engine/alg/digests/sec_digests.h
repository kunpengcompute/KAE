/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the digest interface for KAE engine
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

#ifndef SEC_DIGESTS_H
#define SEC_DIGESTS_H

#include <openssl/engine.h>
#include <openssl/evp.h>
#include "wd_digest.h"
#include "wd_queue_memory.h"
#include "engine_types.h"
#include "engine_utils.h"

#define MAX_SEND_TRY_CNTS 50

#define MIN_DIGEST_LEN 512
#define INPUT_CACHE_SIZE (512 * 1024)
#define SM3_LEN 32
#define MAX_OUTLEN 64
#define MD5_HASH_LEN  16

enum sec_digest_state {
    SEC_DIGEST_INIT = 0,
    SEC_DIGEST_FIRST_UPDATING,
    SEC_DIGEST_DOING,
    SEC_DIGEST_FINAL
};

typedef struct digest_engine_ctx digest_engine_ctx_t;
typedef struct sec_digest_priv sec_digest_priv_t;

struct sec_digest_priv {
    uint8_t*                last_update_buff;
    uint8_t*                in;
    uint8_t*                out;
    uint32_t                d_mode; // haven't used
    uint32_t                d_alg;
    uint32_t                state;
    uint32_t                last_update_bufflen;
    uint32_t                do_digest_len; // do one cycle digest length
    uint32_t                out_len; // digest out length
    uint32_t                e_nid; // digest nid
    digest_engine_ctx_t*    e_digest_ctx;
    EVP_MD_CTX*             soft_ctx;   
    uint32_t                switch_flag;
};

struct digest_engine_ctx {
    KAE_QUEUE_DATA_NODE_S*          q_node;
    struct wcrypto_digest_op_data   op_data;
    struct wcrypto_digest_ctx_setup setup;
    void*                           wd_ctx; // one ctx or a list of ctx
    sec_digest_priv_t*              md_ctx;
};

struct digest_threshold_table {
    int nid;
    int threshold;
};
void sec_digests_set_enabled(int nid, int enabled);
int sec_engine_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
void sec_digests_free_methods(void);
int sec_cipher_engine_ctx_poll(void* engnine_ctx);

int digest_module_init(void);
void sec_digests_cb(const void* msg, void* tag);
#endif

