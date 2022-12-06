/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides wd api for DH.
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

#ifndef HPRE_DH_WD_H
#define HPRE_DH_WD_H

#include <openssl/dh.h>
#include <uadk/v1/wd_dh.h>
#include "../../wdmngr/wd_queue_memory.h"

struct hpre_dh_priv_ctx {
	DH *ssl_alg;
	int key_size;
	unsigned char *block_addr;
};

typedef struct hpre_dh_priv_ctx hpre_dh_priv_ctx_t;

struct hpre_dh_engine_ctx {
	void *ctx;
	struct wcrypto_dh_op_data opdata;
	struct wcrypto_dh_ctx_setup dh_setup;
	struct KAE_QUEUE_DATA_NODE *qlist;
	hpre_dh_priv_ctx_t priv_ctx;
};

typedef struct hpre_dh_engine_ctx hpre_dh_engine_ctx_t;

extern KAE_QUEUE_POOL_HEAD_S *g_hpre_dh_qnode_pool;

int wd_hpre_dh_init_qnode_pool(void);
void wd_hpre_dh_uninit_qnode_pool(void);

KAE_QUEUE_POOL_HEAD_S *wd_hpre_dh_get_qnode_pool(void);

void hpre_dh_free_eng_ctx(hpre_dh_engine_ctx_t *eng_ctx);

hpre_dh_engine_ctx_t *hpre_dh_get_eng_ctx(DH *dh, int bits, bool is_g2);

/*
 * fill opdata for generate_key.
 */
int hpre_dh_fill_genkey_opdata(const BIGNUM *g, const BIGNUM *p,
		const BIGNUM *priv_key, hpre_dh_engine_ctx_t *engine_ctx);

/*
 * fill opdata for compute_key.
 */
int hpre_dh_fill_compkey_opdata(const BIGNUM *g, const BIGNUM *p,
		const BIGNUM *priv_key, const BIGNUM *pub_key, hpre_dh_engine_ctx_t *engine_ctx);

/*
 * call wd API for generating public key.
 */
int hpre_dh_genkey(hpre_dh_engine_ctx_t *engine_ctx);

/*
 * call wd API for generating secret key.
 */
int hpre_dh_compkey(hpre_dh_engine_ctx_t *engine_ctx);

/*
 * get public key from engine ctx.
 */
int hpre_dh_get_pubkey(hpre_dh_engine_ctx_t *engine_ctx, BIGNUM **pubkey);

/*
 * get secret key from engine ctx.
 */
int hpre_dh_get_output_chars(hpre_dh_engine_ctx_t *engine_ctx, unsigned char *out);

#endif
