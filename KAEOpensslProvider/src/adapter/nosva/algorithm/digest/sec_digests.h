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

#include <openssl/evp.h>
#include <uadk/v1/wd_digest.h>
#include "../../wdwarp/wd_queue_memory.h"
#include "../../../common/kae_utils.h"
#include "../../../common/kae_types.h"

#define MAX_SEND_TRY_CNTS 50

#define MIN_DIGEST_LEN 512
#define DIGEST_INPUT_CACHE_SIZE (512 * 1024)
#define SM3_LEN 32
#define MAX_OUTLEN 64
#define MD5_HASH_LEN  16

struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;
typedef struct evp_md_st EVP_MD;

typedef struct evp_md_ctx_st EVP_MD_CTX;

enum sec_digest_state {
	SEC_DIGEST_INIT = 0,
	SEC_DIGEST_FIRST_UPDATING,
	SEC_DIGEST_DOING,
	SEC_DIGEST_FINAL
};

typedef struct digest_engine_ctx digest_engine_ctx_t;

typedef struct {
	uint8_t			*last_update_buff;
	uint8_t			*in;
	uint8_t			*out;
	uint32_t                d_mode; // haven't used
	uint32_t                d_alg;
	uint32_t                state;
	uint32_t                last_update_bufflen;
	uint32_t                do_digest_len; // do one cycle digest length
	uint32_t                out_len; // digest out length
	uint32_t                e_nid; // digest nid
	digest_engine_ctx_t	*e_digest_ctx;
	EVP_MD_CTX		*soft_ctx;
	EVP_MD *soft_md;
	unsigned char *small_buf;
	size_t small_len;
	size_t small_capacity;
	uint32_t                switch_flag;
	uint32_t                app_datasize;
 	bool			is_stream_copy;
    bool            is_copy;
	uint64_t		total_data_len;
	__u64			long_data_len;
    size_t md_size;
    size_t blk_size;
} sec_digest_priv;

struct digest_engine_ctx {
	KAE_QUEUE_DATA_NODE_S		*q_node;
	struct wcrypto_digest_op_data   op_data;
	struct wcrypto_digest_ctx_setup setup;
	void				*wd_ctx; // one ctx or a list of ctx
	sec_digest_priv		*md_ctx;
};

struct digest_threshold_table {
	int nid;
	int threshold;
};

struct evp_md_ctx_st {
    const EVP_MD *reqdigest;    /* The original requested digest */
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);

    /*
     * Opaque ctx returned from a providers digest algorithm implementation
     * OSSL_FUNC_digest_newctx()
     */
    void *algctx;
    EVP_MD *fetched_digest;
} /* EVP_MD_CTX */ ;

int sec_digest_module_init(void);
uint32_t sec_digests_sw_get_threshold(int nid);

int sec_digests_init(sec_digest_priv *md_ctx);
int sec_digests_update(sec_digest_priv *md_ctx, const void *data, size_t data_len);
int sec_digests_final(sec_digest_priv *md_ctx, unsigned char *digest);
int sec_digests_cleanup(sec_digest_priv *md_ctx);
int sec_digests_copy(sec_digest_priv *to_ctx, const sec_digest_priv *from_ctx);

#endif

