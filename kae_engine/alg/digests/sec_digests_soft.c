/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for switch to soft digests
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

#include <asm/byteorder.h>
#include "sec_digests_soft.h"
#include "engine_opensslerr.h"
#include "engine_log.h"

static const EVP_MD *sec_digests_soft_md(uint32_t e_nid)
{
    const EVP_MD *g_digest_md = NULL;
    switch (e_nid) {
        case NID_sm3:
            g_digest_md = EVP_sm3();
            break;
        case NID_md5:
            g_digest_md = EVP_md5();
            break;            
        default:
            break;
    }
    return g_digest_md;
}

int sec_digests_soft_init(sec_digest_priv_t *ctx, uint32_t e_nid)
{
	if (ctx->soft_ctx == NULL) {
		ctx->soft_ctx = EVP_MD_CTX_new();
        memset(ctx->soft_ctx, 0, sizeof(EVP_MD_CTX));
    }
    const EVP_MD *digest_md = NULL;
    digest_md = sec_digests_soft_md(e_nid);
    if (digest_md == NULL) {
        US_WARN("switch to soft:don't support by sec engine.");
        return OPENSSL_FAIL;
    }
    int ctx_len = EVP_MD_meth_get_app_datasize(digest_md);
    if (ctx->soft_ctx->md_data == NULL) {
        ctx->soft_ctx->md_data = OPENSSL_malloc(ctx_len);
        memset(ctx->soft_ctx->md_data, 0, ctx_len);
    }
    if (!ctx->soft_ctx->md_data) {
        KAEerr(KAE_F_DIGEST_SOFT_INIT, KAE_R_MALLOC_FAILURE);
        US_ERR("malloc md_data failed");
        return OPENSSL_FAIL;
    }
    
    return EVP_MD_meth_get_init (digest_md)(ctx->soft_ctx);
}

int sec_digests_soft_update(EVP_MD_CTX *ctx, const void *data, size_t data_len, uint32_t e_nid)
{
    const EVP_MD *digest_md = NULL;
    digest_md = sec_digests_soft_md(e_nid);
    if (digest_md == NULL) {
        US_WARN("switch to soft:don't support by sec engine.");
        return OPENSSL_FAIL;
    }
    return EVP_MD_meth_get_update (digest_md)(ctx, data, data_len);
}

int sec_digests_soft_final(EVP_MD_CTX *ctx, unsigned char *digest, uint32_t e_nid)
{
    US_WARN_LIMIT("call sec_digest_soft_final");
    
    const EVP_MD *digest_md = NULL;
    digest_md = sec_digests_soft_md(e_nid);
    if (digest_md == NULL) {
        US_WARN("switch to soft:don't support by sec engine.");
        return OPENSSL_FAIL;
    }
    return EVP_MD_meth_get_final(digest_md)(ctx, digest);
}

int sec_digests_soft_work(sec_digest_priv_t *md_ctx, int len, unsigned char *digest)
{
    int ret;
    ret = sec_digests_soft_init(md_ctx, md_ctx->e_nid);
    if (len != 0) {
        ret |= sec_digests_soft_update(md_ctx->soft_ctx, md_ctx->last_update_buff, len, md_ctx->e_nid);
    }
    ret |= sec_digests_soft_final(md_ctx->soft_ctx, digest, md_ctx->e_nid);
    sec_digests_soft_cleanup(md_ctx);
    
    return ret;
}

void sec_digests_soft_cleanup(sec_digest_priv_t *md_ctx)
{
    EVP_MD_CTX *ctx = md_ctx->soft_ctx;
    if (md_ctx->copy)
		return;
    if (ctx != NULL) {
		if (ctx->md_data) {
			OPENSSL_free(ctx->md_data);
			ctx->md_data  = NULL;
		}
		EVP_MD_CTX_free(ctx);
		md_ctx->soft_ctx = NULL;
	}
    return;
}

