/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the rsa interface for KAE rsa using wd interface
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

#ifndef HPRE_WD_H
#define HPRE_WD_H

#include <semaphore.h>

#include "hpre_rsa.h"
#include "wd_rsa.h"
#include "../wdmngr/wd_queue_memory.h"
#include "wd_rsa.h"


#define UNSET            0
#define ISSET            1
#define BIT_BYTES_SHIFT  3

#define BN_ULONG        unsigned long
#define MAX_SEND_TRY_CNTS  50
#define MAX_RECV_TRY_CNTS  3000

#define RSA_BALANCE_TIMES 1280

#define WD_STATUS_BUSY      (-EBUSY)

struct hpre_priv_ctx {
    RSA *ssl_alg;
    int is_pubkey_ready;
    int is_privkey_ready;
    int key_size;
};

typedef struct hpre_priv_ctx hpre_priv_ctx_t;

struct hpre_engine_ctx {
    void *ctx;
    struct wcrypto_rsa_op_data opdata;
    struct wcrypto_rsa_ctx_setup rsa_setup;
    struct KAE_QUEUE_DATA_NODE *qlist;
    hpre_priv_ctx_t priv_ctx;
};

typedef struct hpre_engine_ctx hpre_engine_ctx_t;

extern KAE_QUEUE_POOL_HEAD_S *g_hpre_rsa_qnode_pool;

int wd_hpre_init_qnode_pool(void);
void wd_hpre_uninit_qnode_pool(void);

KAE_QUEUE_POOL_HEAD_S *wd_hpre_get_qnode_pool();

hpre_engine_ctx_t *hpre_get_eng_ctx(RSA *rsa, int bits);

void hpre_free_eng_ctx(hpre_engine_ctx_t *eng_ctx);

void hpre_free_rsa_ctx(void *ctx);

void hpre_rsa_fill_pubkey(const BIGNUM *e, const BIGNUM *n, hpre_engine_ctx_t *rsa_ctx);

void hpre_rsa_fill_prikey(RSA *rsa, hpre_engine_ctx_t *eng_ctx, int version,
                          const BIGNUM *p, const BIGNUM *q, const BIGNUM *dmp1,
                          const BIGNUM *dmq1, const BIGNUM *iqmp);

int hpre_fill_keygen_opdata(void *ctx,
                            struct wcrypto_rsa_op_data *opdata);

int hpre_rsa_get_keygen_param(struct wcrypto_rsa_op_data *opdata, void *ctx,
    RSA *rsa, BIGNUM *e_value, BIGNUM *p, BIGNUM *q);

int hpre_rsa_sync(void *ctx, struct wcrypto_rsa_op_data *opdata);

int hpre_rsa_crypto(hpre_engine_ctx_t *eng_ctx, struct wcrypto_rsa_op_data *opdata);

#endif

