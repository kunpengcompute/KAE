/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the implementation for switch to soft digests
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
#include <openssl/evp.h>
#include <openssl/md5.h>

#include <asm/byteorder.h>
#include "sec_digests_soft.h"
#include "../../utils/engine_opensslerr.h"
#include "../../../utils/engine_log.h"

static int sec_digests_soft_md(sec_digest_priv_t *priv)
{
	int app_datasize = 0;

	if (priv->soft_md)
		return 1;

	switch (priv->e_nid) {
	case NID_sm3:
		priv->soft_md = EVP_sm3();
		break;
	case NID_md5:
		priv->soft_md = EVP_md5();
		break;
	default:
		break;
	}

	if (unlikely(priv->soft_md == NULL))
		return 0;

	app_datasize = EVP_MD_meth_get_app_datasize(priv->soft_md);
	if (app_datasize == 0) {
		/* OpenSSL 3.0 has no app_datasize, need set manually
		 * check crypto/evp/legacy_md5.c: md5_md as example
		 */
		switch (priv->e_nid) {
		case NID_sm3:
			app_datasize = sizeof(EVP_MD *) + sizeof(SM3_CTX);
			break;
		case NID_md5:
			app_datasize = sizeof(EVP_MD *) + sizeof(MD5_CTX);
			break;
		default:
			break;
		}
	}

	if (priv->soft_ctx == NULL) {
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();

		if (ctx == NULL)
			return 0;

		ctx->md_data = OPENSSL_malloc(app_datasize);
		if (ctx->md_data == NULL)
			return 0;

		priv->soft_ctx = ctx;
		priv->app_datasize = app_datasize;
	}
	return 1;
}

int sec_digests_soft_init(sec_digest_priv_t *priv)
{
	if (sec_digests_soft_md(priv) == 0)
		return 0;

	return EVP_MD_meth_get_init(priv->soft_md)(priv->soft_ctx);
}

int sec_digests_soft_update(sec_digest_priv_t *priv, const void *data, size_t len)
{
	return EVP_MD_meth_get_update(priv->soft_md)(priv->soft_ctx, data, len);
}

int sec_digests_soft_final(sec_digest_priv_t *priv, unsigned char *digest)
{
	return EVP_MD_meth_get_final(priv->soft_md)(priv->soft_ctx, digest);
}

int sec_digests_soft_work(sec_digest_priv_t *md_ctx, int len, unsigned char *digest)
{
	int ret;
    ret = sec_digests_soft_init(md_ctx);
	if (len != 0)
		ret |= sec_digests_soft_update(md_ctx, md_ctx->last_update_buff, len);
    ret |= sec_digests_soft_final(md_ctx, digest);
    sec_digests_soft_cleanup(md_ctx);
	return ret;
}

void sec_digests_soft_cleanup(sec_digest_priv_t *md_ctx)
{
	EVP_MD_CTX *ctx = md_ctx->soft_ctx;
    // if (md_ctx->copy)
	// 	return;
    if (ctx != NULL) {
		if (ctx->md_data) {
			OPENSSL_free(ctx->md_data);
			ctx->md_data  = NULL;
		}
		EVP_MD_CTX_free(ctx);
		md_ctx->soft_ctx = NULL;
		md_ctx->app_datasize = 0;
	}
}

int sec_digests_soft_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    sec_digest_priv_t *to_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(to);
    sec_digest_priv_t *from_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(from);
    int ret;

    if (!to_ctx)
		return 1;

	if (!from_ctx) {
		US_ERR("priv get from digest ctx is NULL.");
		return 0;
	}
    // 需要重新给目的上下文分配ctx
    if (to_ctx->soft_ctx) {
		to_ctx->soft_ctx = NULL;
		ret = sec_digests_soft_init(to_ctx);
		if (ret != OPENSSL_SUCCESS) {
            return OPENSSL_FAIL;
        }

		memcpy(to_ctx->soft_ctx->md_data, from_ctx->soft_ctx->md_data, to_ctx->app_datasize);
	}

	return OPENSSL_SUCCESS;
}