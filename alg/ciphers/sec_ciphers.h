/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the the interface for KAE engine dealing with wrapdrive
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
 * @file sec_cipher.h
 *
 * This file provides the interface for SEC engine dealing with wrapdrive
 *
 *****************************************************************************/

#ifndef SEC_CIPHERS_H
#define SEC_CIPHERS_H
#include <openssl/engine.h>
#include "wd_cipher.h"
#include "wd_queue_memory.h"

#define MAX_SEND_TRY_CNTS 50

enum openssl_cipher_enc_t {
    OPENSSL_DECRYPTION = 0,
    OPENSSL_ENCRYPTION = 1
};

enum sec_cipher_priv_ctx_syncto {
    SEC_CIHPER_SYNC_S2W = 1,    // software priv ctx sync to hareware priv ctx
    SEC_CIHPER_SYNC_H2S,        // hareware priv ctx sync to software priv ctx
};
typedef enum sec_cipher_priv_ctx_syncto sec_cipher_priv_ctx_syncto_t;

typedef struct xts_ecb_data_strcut {
    EVP_CIPHER_CTX *ecb_ctx;
    const EVP_CIPHER* cipher_type;
    uint8_t* key2;
    uint8_t  key2_len;
    uint8_t* iv_out;
    uint8_t* encryto_iv;
    uint32_t countNum;
} xts_ecb_data;

typedef struct cipher_engine_ctx cipher_engine_ctx_t;
/*
 * |    16bytes * n length | offset |                |
 * | <---------first buf -----------><---next buf -->|
 * the next buf send to warpdriv should start at hardaddr + first offset
 */
struct cipher_priv_ctx {
    int32_t         encrypt;     // encrypt or decryto   DECRYPTION = 0, ENCRYPTION = 1
    uint32_t        inl;         // input length
    uint32_t        left_len;    // left length for warpdrive to do
    uint32_t        offset;      // prev buf offset, that indicate the next buf should start at hardware_addr+offset   
    uint8_t*        key;         // key 
    uint32_t        key_len;     // key length
    uint8_t*        iv;          // iv
    uint32_t        iv_len;      // iv length
    uint8_t*        next_iv;     // store IV for next cbc operation in decryption
    const uint8_t*  in;
    uint8_t*        out;
    uint32_t        c_mode;
    uint32_t        c_alg;
    uint32_t        do_cipher_len;    // do one cycle cipher length
    
    size_t          switch_threshold; // crypt small packet offload threshold
    void*           sw_ctx_data;      // Pointer for context data that will be used by Small packet offload feature.
    xts_ecb_data*   ecb_encryto;
    cipher_engine_ctx_t* e_cipher_ctx;      
};

typedef struct cipher_priv_ctx cipher_priv_ctx_t;

struct cipher_engine_ctx {
    KAE_QUEUE_DATA_NODE_S*          q_node;
    struct wcrypto_cipher_op_data   op_data;
    struct wcrypto_cipher_ctx_setup setup;
    void*                           wd_ctx;    // one ctx or a list of ctx

    cipher_priv_ctx_t*              priv_ctx;
};

int sec_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
void sec_ciphers_free_ciphers(void);
int sec_cipher_engine_ctx_poll(void* engnine_ctx);

int cipher_module_init(void);
void sec_ciphers_cb(const void* msg, void* tag);

#endif

