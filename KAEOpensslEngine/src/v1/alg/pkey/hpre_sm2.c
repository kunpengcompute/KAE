/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
 *
 */
#include <openssl/bn.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#include "../../utils/engine_check.h"
#include "../../utils/engine_types.h"
#include "../../../utils/engine_log.h"
#include "../../../utils/engine_utils.h"
#include "../../wdmngr/wd_queue_memory.h"
#include "hpre_sm2.h"
#include "../../async/async_callback.h"
#include "../../async/async_task_queue.h"
#include "../../async/async_event.h"

KAE_QUEUE_POOL_HEAD_S *g_hpre_sm2_qnode_pool;

DECLARE_ASN1_FUNCTIONS(HPRE_SM2_Ciphertext)

ASN1_SEQUENCE(HPRE_SM2_Ciphertext) = {
	ASN1_SIMPLE(HPRE_SM2_Ciphertext, C1x, BIGNUM),
	ASN1_SIMPLE(HPRE_SM2_Ciphertext, C1y, BIGNUM),
	ASN1_SIMPLE(HPRE_SM2_Ciphertext, C3, ASN1_OCTET_STRING),
	ASN1_SIMPLE(HPRE_SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(HPRE_SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(HPRE_SM2_Ciphertext)

static int g_known_pkey_nids[] = {
	EVP_PKEY_SM2,
};

// static struct hpre_pkey_meth g_pkey_meth;
static EVP_PKEY_METHOD *g_hpre_sm2_method;

// 回调函数，返回值不按OPENSSL规范
static int hpre_sm2_get_rand(char *out, size_t out_len, void *usr)
{
	int count = SM2_GET_RAND_MAX_CNT;
	BIGNUM *k;
	int ret;

	if (!out) {
		fprintf(stderr, "out is NULL\n");
		return -1;
	}

	k = BN_new();
	if (!k)
		return -ENOMEM;

	do {
		ret = BN_priv_rand_range(k, usr);
		if (!ret) {
			fprintf(stderr, "failed to BN_priv_rand_range\n");
			ret = -ENOMEM;
			goto err;
		}

		ret = BN_bn2binpad(k, (void *)out, (int)out_len);
		if (ret < 0) {
			ret = -ENOMEM;
			fprintf(stderr, "failed to BN_bn2binpad\n");
			goto err;
		}
	} while (--count >= 0 && BN_is_zero(k));

	ret = 0;
	if (count < 0)
		ret = -1;
err:
	BN_free(k);

	return ret;
}

// 回调函数
static int hpre_sm2_compute_hash(const char *in, size_t in_len,
			char *out, size_t out_len, void *usr)
{
	const EVP_MD *digest = (const EVP_MD *)usr;
	EVP_MD_CTX *hash = EVP_MD_CTX_new();
	int ret = 0;

	if (EVP_DigestInit(hash, digest) == 0 ||
		EVP_DigestUpdate(hash, in, in_len) == 0 ||
		EVP_DigestFinal(hash, (void *)out, NULL) == 0) {
		fprintf(stderr, "compute hash failed\n");
		ret = -1;
	}

	EVP_MD_CTX_free(hash);

	return ret;
}

static hpre_sm2_engine_ctx_t *wd_sm2_new_engine_ctx(KAE_QUEUE_DATA_NODE_S *q_node, hpre_sm2_priv_ctx_t *priv_ctx)
{
	hpre_sm2_engine_ctx_t *e_sm2_ctx = NULL;

	e_sm2_ctx = (hpre_sm2_engine_ctx_t *)OPENSSL_malloc(sizeof(hpre_sm2_engine_ctx_t));
	if (e_sm2_ctx == NULL) {
		US_ERR("OPENSSL_malloc ctx failed");
		return NULL;
	}
	kae_memset(e_sm2_ctx, 0, sizeof(hpre_sm2_engine_ctx_t));

	// 配置setup参数
	e_sm2_ctx->setup.br.alloc = kae_wd_alloc_blk;
	e_sm2_ctx->setup.br.free = kae_wd_free_blk;
	e_sm2_ctx->setup.br.iova_map = kae_dma_map;
	e_sm2_ctx->setup.br.iova_unmap = kae_dma_unmap;
    // e_sm2_ctx->setup.br.get_bufsize = wd_blksize;
	e_sm2_ctx->setup.br.usr = q_node->kae_queue_mem_pool;

	e_sm2_ctx->priv_ctx = priv_ctx;
	e_sm2_ctx->qlist = q_node;
	q_node->engine_ctx = e_sm2_ctx;

	return e_sm2_ctx;
}

static int wd_sm2_init_engine_ctx(hpre_sm2_engine_ctx_t *e_sm2_ctx)
{

	// 后续考虑放到update中？
    e_sm2_ctx->setup.key_bits = 256;
	// sm2算法在UADK的setup_curve_cfg函数中会填充cv信息
    // e_sm2_ctx->setup.cv.type = WCRYPTO_CV_CFG_ID;
    // e_sm2_ctx->setup.cv.cfg.id = WCRYPTO_BRAINPOOLP320R1;
	e_sm2_ctx->setup.rand.cb = hpre_sm2_get_rand;
	e_sm2_ctx->setup.hash.cb = hpre_sm2_compute_hash;
	e_sm2_ctx->setup.hash.type = WCRYPTO_HASH_SHA256;
	return KAE_SUCCESS;
}

void wd_sm2_put_engine_ctx(hpre_sm2_engine_ctx_t *e_hpre_sm2_ctx)
{
	if (unlikely(e_hpre_sm2_ctx == NULL)) {
		US_WARN("sec cipher engine ctx NULL!");
		return;
	}

	if (e_hpre_sm2_ctx->wd_ctx != NULL) {
		wcrypto_del_ecc_ctx(e_hpre_sm2_ctx->wd_ctx);
		e_hpre_sm2_ctx->wd_ctx = NULL;
	}

	if (e_hpre_sm2_ctx->qlist != NULL)
		(void)kae_put_node_to_pool(g_hpre_sm2_qnode_pool, e_hpre_sm2_ctx->qlist);

	e_hpre_sm2_ctx = NULL;
}

hpre_sm2_engine_ctx_t *wd_sm2_get_engine_ctx(hpre_sm2_priv_ctx_t *priv_ctx)
{
	KAE_QUEUE_DATA_NODE_S *q_node = NULL;
	hpre_sm2_engine_ctx_t *e_hpre_sm2_ctx = NULL;

	if (unlikely(priv_ctx == NULL)) {
		US_ERR("sm2 cipher priv ctx NULL!");
		return NULL;
	}
    US_DEBUG("kae hpre_sm2 get queue node from pool start.");

	q_node = kae_get_node_from_pool(g_hpre_sm2_qnode_pool);
	if (q_node == NULL) {
		US_ERR_LIMIT("failed to get hardware queue");
		return NULL;
	}

	e_hpre_sm2_ctx = (hpre_sm2_engine_ctx_t *)q_node->engine_ctx;
	if (e_hpre_sm2_ctx == NULL) {
		e_hpre_sm2_ctx = wd_sm2_new_engine_ctx(q_node, priv_ctx);
		if (e_hpre_sm2_ctx == NULL) {
			US_WARN("sec new engine ctx fail!");
			(void)kae_put_node_to_pool(g_hpre_sm2_qnode_pool, q_node);
			return NULL;
		}
	}

	e_hpre_sm2_ctx->priv_ctx = priv_ctx;

	// 初始化一次engine参数
	if (wd_sm2_init_engine_ctx(e_hpre_sm2_ctx) == KAE_FAIL) { //todo
		US_WARN("init engine ctx fail!");
		OPENSSL_free(e_hpre_sm2_ctx);
		wd_sm2_put_engine_ctx(e_hpre_sm2_ctx);
		return NULL;
	}

	return e_hpre_sm2_ctx;
}

static int  hpre_sm2_init(EVP_PKEY_CTX *ctx)
{
	hpre_sm2_priv_ctx_t *sm2ctx = NULL;

	sm2ctx = calloc(1, sizeof(*sm2ctx)); // 不同于cipher的自动申请和回收pkey需要自己申请的
	if (!sm2ctx) {
		fprintf(stderr, "failed to alloc sm2 ctx\n");
		return OPENSSL_FAIL;
	}

	sm2ctx->init_status = HPRE_SM2_INIT_SUCC;

	EVP_PKEY_CTX_set_data(ctx, sm2ctx);
	EVP_PKEY_CTX_set0_keygen_info(ctx, NULL, 0);
	return OPENSSL_SUCCESS;
}

// 这个函数应该可以优化吧，直接去找sm2的METHOD
const EVP_PKEY_METHOD *hpre_get_openssl_pkey_meth(int nid)
{
	size_t count = EVP_PKEY_meth_get_count();
	const EVP_PKEY_METHOD *pmeth;
	int pkey_id = -1;
	size_t i;

	for (i = 0; i < count; i++) {
		pmeth = EVP_PKEY_meth_get0(i);
		EVP_PKEY_meth_get0_info(&pkey_id, NULL, pmeth);
		if (nid == pkey_id)
			return pmeth;
	}

	fprintf(stderr, "not find openssl method %d\n", nid);
	return NULL;
}

static int hpre_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	hpre_sm2_priv_ctx_t *dctx, *sctx;

	if (!hpre_sm2_init(dst))
		return OPENSSL_FAIL;
	sctx = EVP_PKEY_CTX_get_data(src);
	dctx = EVP_PKEY_CTX_get_data(dst);
	if (sctx->ctx.gen_group != NULL) {
		dctx->ctx.gen_group = EC_GROUP_dup(sctx->ctx.gen_group);
		if (dctx->ctx.gen_group == NULL) {
			fprintf(stderr, "failed to EC GROUP dup\n");
			// sm2_cleanup(dst);
			return OPENSSL_FAIL;
		}
	}

	if (sctx->ctx.id != NULL) {
		dctx->ctx.id = OPENSSL_malloc(sctx->ctx.id_len);
		if (dctx->ctx.id == NULL) {
			fprintf(stderr, "failed to malloc\n");
			// sm2_cleanup(dst);
			return OPENSSL_FAIL;
		}
		memcpy(dctx->ctx.id, sctx->ctx.id, sctx->ctx.id_len);
	}
	dctx->ctx.id_len = sctx->ctx.id_len;
	dctx->ctx.id_set = sctx->ctx.id_set;
	dctx->ctx.md = sctx->ctx.md;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_set_ctx_id(struct hpre_sm2_priv_ctx *smctx, int p1, const void *p2)
{
	uint8_t *tmp_id;

	if (p1 > 0) {
		tmp_id = OPENSSL_malloc(p1);
		if (tmp_id == NULL) {
			fprintf(stderr, "failed to malloc\n");
			return OPENSSL_FAIL;
		}
		memcpy(tmp_id, p2, p1);
		OPENSSL_free(smctx->ctx.id);
		smctx->ctx.id = tmp_id;
	} else {
		/* Set null-ID */
		OPENSSL_free(smctx->ctx.id);
		smctx->ctx.id = NULL;
	}
	smctx->ctx.id_len = (size_t)p1;
	smctx->ctx.id_set = 1;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_get_hash_type(int nid_hash)
{
	switch (nid_hash) {
	case NID_sha1:
		return WCRYPTO_HASH_SHA1;
	case NID_sha224:
		return WCRYPTO_HASH_SHA224;
	case NID_sha256:
		return WCRYPTO_HASH_SHA256;
	case NID_sha384:
		return WCRYPTO_HASH_SHA384;
	case NID_sha512:
		return WCRYPTO_HASH_SHA512;
	case NID_md4:
		return WCRYPTO_HASH_MD4;
	case NID_md5:
		return WCRYPTO_HASH_MD5;
	case NID_sm3:
		return WCRYPTO_HASH_SM3;
	default:
		return -1;
	}
}

static void hpre_sm2_cb(const void *message, void *tag)
{
	if (!message || !tag) {
		US_ERR("hpre sm2 params err!\n");
		return;
	}
	struct wcrypto_ecc_msg *msg = (struct wcrypto_ecc_msg *)message;
	hpre_sm2_engine_ctx_t *eng_ctx = (hpre_sm2_engine_ctx_t *)tag;

	eng_ctx->opdata.out = msg->out;
	eng_ctx->opdata.out_bytes = msg->out_bytes;
	eng_ctx->opdata.status = msg->result;
}

static int hpre_sm2_update_sess(struct hpre_sm2_priv_ctx *smctx)
{
	const unsigned char sm2_order[] = {
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
		0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23
	};

	if (smctx->e_hpre_sm2_ctx == NULL) {
		smctx->e_hpre_sm2_ctx = wd_sm2_get_engine_ctx(smctx);
		if (smctx->e_hpre_sm2_ctx == NULL) {
			US_WARN("hpre sm2 failed to get engine ctx, switch to soft cipher");
            return OPENSSL_FAIL;
		}
	}

	// struct wcrypto_ecc_ctx_setup setup;
	hpre_sm2_engine_ctx_t * e_sm2_ctx = smctx->e_hpre_sm2_ctx;
	void * sess;
	BIGNUM *order;
	int type;

	struct wd_queue *queue = smctx->e_hpre_sm2_ctx->qlist->kae_wd_queue;

	if (smctx->ctx.md) {
		/* Set hash method */
		e_sm2_ctx->setup.hash.cb = hpre_sm2_compute_hash;
		e_sm2_ctx->setup.hash.usr = (void *)smctx->ctx.md;
		type = hpre_sm2_get_hash_type(smctx->md_nid);
		if (type < 0) {
			wd_sm2_put_engine_ctx(smctx->e_hpre_sm2_ctx);
			fprintf(stderr, "uadk not support hash nid %d\n", smctx->md_nid);
			return OPENSSL_FAIL;
		}
		e_sm2_ctx->setup.hash.type = type;
	}

	order = BN_bin2bn((void *)sm2_order, sizeof(sm2_order), NULL);
	e_sm2_ctx->setup.rand.cb = hpre_sm2_get_rand;
	e_sm2_ctx->setup.rand.usr = (void *)order;
	e_sm2_ctx->setup.cb = (wcrypto_cb)hpre_sm2_cb;
	sess = wcrypto_create_ecc_ctx(queue, &e_sm2_ctx->setup);
	if (!sess) {
		fprintf(stderr, "failed to alloc sess\n");
		wd_sm2_put_engine_ctx(smctx->e_hpre_sm2_ctx);
		BN_free(order);
		smctx->init_status = HPRE_SM2_INIT_FAIL;
		return OPENSSL_FAIL;
	}

	/* Free old session before setting new session */
	if (smctx->e_hpre_sm2_ctx->wd_ctx) {
		wcrypto_del_ecc_ctx(smctx->e_hpre_sm2_ctx->wd_ctx);
		smctx->e_hpre_sm2_ctx->wd_ctx = NULL;
	}
		
	smctx->e_hpre_sm2_ctx->wd_ctx = sess;

	smctx->prikey = NULL;
	smctx->pubkey = NULL;
	smctx->order = order;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	hpre_sm2_priv_ctx_t *smctx = EVP_PKEY_CTX_get_data(ctx);
	EC_GROUP *group;
	int md_nid;

	if (!smctx) {
		fprintf(stderr, "smctx not set.\n");
		return OPENSSL_FAIL;
	}

	switch (type) {
	case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
		group = EC_GROUP_new_by_curve_name(p1);
		if (group == NULL) {
			fprintf(stderr, "invalid curve %d\n", p1);
			return OPENSSL_FAIL;
		}
		EC_GROUP_free(smctx->ctx.gen_group);
		smctx->ctx.gen_group = group;
		goto set_data;
	case EVP_PKEY_CTRL_EC_PARAM_ENC:
		if (smctx->ctx.gen_group == NULL) {
			fprintf(stderr, "no parameters set\n");
			return OPENSSL_FAIL;
		}
		EC_GROUP_set_asn1_flag(smctx->ctx.gen_group, p1);
		goto set_data;
	case EVP_PKEY_CTRL_MD:
		if (!p2)
			smctx->ctx.md = EVP_sm3();
		else
			smctx->ctx.md = p2;

		md_nid = EVP_MD_type(smctx->ctx.md);
		if (md_nid == smctx->md_nid) {
			smctx->md_update_status = MD_UNCHANGED;
		} else {
			smctx->md_update_status = MD_CHANGED;
			smctx->md_nid = md_nid;
		}
		goto set_data;
	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD **)p2 = smctx->ctx.md;
		return OPENSSL_SUCCESS;
	case EVP_PKEY_CTRL_SET1_ID:
		if (hpre_sm2_set_ctx_id(smctx, p1, p2))
			goto set_data;
		return OPENSSL_FAIL;
	case EVP_PKEY_CTRL_GET1_ID:
		memcpy(p2, smctx->ctx.id, smctx->ctx.id_len);
		return OPENSSL_SUCCESS;
	case EVP_PKEY_CTRL_GET1_ID_LEN:
		*(size_t *)p2 = smctx->ctx.id_len;
		return OPENSSL_SUCCESS;
	case EVP_PKEY_CTRL_DIGESTINIT:
		/* Nothing to be inited, for suppress the error */
		return OPENSSL_SUCCESS;
	default:
		fprintf(stderr, "sm2 ctrl type = %d error\n", type);
		return OPENSSL_FAIL;
	}
set_data:
	if (smctx->init_status == HPRE_SM2_INIT_SUCC && smctx->md_update_status)
		if (!hpre_sm2_update_sess(smctx))
			return OPENSSL_FAIL;

	EVP_PKEY_CTX_set_data(ctx, smctx);
	return OPENSSL_SUCCESS;

}

static int hpre_sm2_ctrl_str(EVP_PKEY_CTX *ctx,
			const char *type, const char *value)
{
	if (strcmp(type, "ec_paramgen_curve") == 0) {
		int nid;

		if ((EC_curve_nist2nid(value) == NID_undef)
			&& (OBJ_sn2nid(value) == NID_undef)
			&& (OBJ_ln2nid(value) == NID_undef)) {
			fprintf(stderr, "invalid curve\n");
			return OPENSSL_FAIL;
		}

		nid = EC_curve_nist2nid(value);
		if (nid == NID_undef) {
			nid = OBJ_sn2nid(value);
			if (nid == NID_undef)
				nid = OBJ_ln2nid(value);
		}
		return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
	} else if (strcmp(type, "ec_param_enc") == 0) {
		int param_enc;

		if (strcmp(value, "explicit") == 0)
			param_enc = 0;
		else if (strcmp(value, "named_curve") == 0)
			param_enc = OPENSSL_EC_NAMED_CURVE;
		else
			return OPENSSL_FAIL;
		return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
	}

	return OPENSSL_FAIL;
}

static int get_hpre_sm2_param(struct hpre_sm2_param *sm2_param, BN_CTX *ctx)
{
	sm2_param->p = BN_CTX_get(ctx);
	if (!sm2_param->p)
		goto end;

	sm2_param->a = BN_CTX_get(ctx);
	if (!sm2_param->a)
		goto end;

	sm2_param->b = BN_CTX_get(ctx);
	if (!sm2_param->b)
		goto end;

	sm2_param->xG = BN_CTX_get(ctx);
	if (!sm2_param->xG)
		goto end;

	sm2_param->yG = BN_CTX_get(ctx);
	if (!sm2_param->yG)
		goto end;

	sm2_param->xA = BN_CTX_get(ctx);
	if (!sm2_param->xA)
		goto end;

	sm2_param->yA = BN_CTX_get(ctx);
	if (!sm2_param->yA)
		goto end;

	return OPENSSL_SUCCESS;

end:
	fprintf(stderr, "failed to malloc params\n");
	return OPENSSL_FAIL;
}

static int hpre_sm2_check_digest_evp_lib(const EVP_MD *digest, EVP_MD_CTX *hash,
				const size_t id_len, const uint8_t *id)
{
	uint8_t e_byte;
	uint16_t entl;
	if (!EVP_DigestInit(hash, digest)) {
		fprintf(stderr, "error evp lib\n");
		return OPENSSL_FAIL;
	}

	/* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
	if (id_len >= (UINT16_MAX >> TRANS_BITS_BYTES_SHIFT)) {
		fprintf(stderr, "id too large\n");
		return OPENSSL_FAIL;
	}

	entl = (uint16_t)(id_len << TRANS_BITS_BYTES_SHIFT);

	/* Update the most significant (first) byte of 'entl' */
	e_byte = GET_MS_BYTE(entl);
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		fprintf(stderr, "error evp lib\n");
		return OPENSSL_FAIL;
	}

	/* Update the least significant (second) byte of 'entl' */
	e_byte = GET_LS_BYTE(entl);
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		fprintf(stderr, "error evp lib\n");
		return OPENSSL_FAIL;
	}

	if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
		fprintf(stderr, "error evp lib\n");
		return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

static int check_equation_param(struct hpre_sm2_param *param, EVP_MD_CTX *hash,
				uint8_t *buf, int p_bytes)
{
	if (BN_bn2binpad(param->a, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->b, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes)) {
		fprintf(stderr, "failed to check equation param\n");
		return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

static int check_base_point_group_param(struct hpre_sm2_param *param, BN_CTX *ctx,
					const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);

	if (!EC_POINT_get_affine_coordinates(group,
					     EC_GROUP_get0_generator(group),
					     param->xG, param->yG, ctx)) {
		fprintf(stderr, "failed to check base point group param\n");
		return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

static int check_base_point_param(struct hpre_sm2_param *param, EVP_MD_CTX *hash,
				  uint8_t *buf, int p_bytes)
{
	if (BN_bn2binpad(param->xG, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->yG, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes)) {
		fprintf(stderr, "failed to check base point param\n");
		return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

static int check_pkey_point_group_param(struct hpre_sm2_param *param, BN_CTX *ctx,
					const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);

	if (!EC_POINT_get_affine_coordinates(group,
					     EC_KEY_get0_public_key(key),
					     param->xA, param->yA, ctx)) {
		fprintf(stderr, "failed to check pkey point group param\n");
		return OPENSSL_FAIL;
	}
	return OPENSSL_SUCCESS;
}

static int check_pkey_point_param(struct hpre_sm2_param *param, EVP_MD_CTX *hash,
				  uint8_t *buf, int p_bytes, uint8_t *out)
{
	if (BN_bn2binpad(param->xA, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->yA, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    !EVP_DigestFinal(hash, out, NULL)) {
		fprintf(stderr, "failed to check pkey point param\n");
		return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_compute_z_digest(uint8_t *out, const EVP_MD *digest,
				const uint8_t *id, const size_t id_len,
				const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);
	struct hpre_sm2_param *param = NULL;
	EVP_MD_CTX *hash = NULL;
	uint8_t *buf = NULL;
	BN_CTX *ctx = NULL;
	int p_bytes;
	int ret = OPENSSL_FAIL;

	hash = EVP_MD_CTX_new();
	if (!hash)
		return ret;

	ctx = BN_CTX_new();
	if (!ctx)
		goto free_hash;

	param = OPENSSL_zalloc(sizeof(struct hpre_sm2_param));
	if (!param) {
		fprintf(stderr, "failed to malloc sm2 param\n");
		goto free_ctx;
	}

	if (!get_hpre_sm2_param(param, ctx))
		goto free_param;

	if (!hpre_sm2_check_digest_evp_lib(digest, hash, id_len, id))
		goto free_param;

	if (!EC_GROUP_get_curve(group, param->p, param->a, param->b, ctx)) {
		fprintf(stderr, "failed to get curve\n");
		goto free_param;
	}

	p_bytes = BN_num_bytes(param->p);
	buf = OPENSSL_zalloc(p_bytes);
	if (!buf) {
		fprintf(stderr, "failed to malloc buf\n");
		goto free_param;
	}

	if (!check_equation_param(param, hash, buf, p_bytes) ||
	    !check_base_point_group_param(param, ctx, key) ||
	    !check_base_point_param(param, hash, buf, p_bytes) ||
	    !check_pkey_point_group_param(param, ctx, key) ||
	    !check_pkey_point_param(param, hash, buf, p_bytes, out))
		goto free_buf;

	ret = OPENSSL_SUCCESS;

free_buf:
	OPENSSL_free(buf);
free_param:
	OPENSSL_free(param);
free_ctx:
	BN_CTX_free(ctx);
free_hash:
	EVP_MD_CTX_free(hash);
	return ret;
}

static int hpre_sm2_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	const EVP_MD *md = EVP_MD_CTX_md(mctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	uint8_t z[EVP_MAX_MD_SIZE];
	int mdlen = EVP_MD_size(md);

	if (!smctx) {
		fprintf(stderr, "smctx not set in digest custom\n");
		return OPENSSL_FAIL;
	}

	if (!smctx->ctx.id_set) {
		/*
		 * An ID value must be set. The specifications are not clear whether a
		 * NULL is allowed. We only allow it if set explicitly for maximum
		 * flexibility.
		 */
		fprintf(stderr, "id not set\n");
		return OPENSSL_FAIL;
	}

	if (mdlen < 0) {
		fprintf(stderr, "invalid digest size %d\n", mdlen);
		return OPENSSL_FAIL;
	}

	/* Get hashed prefix 'z' of tbs message */
	if (!hpre_sm2_compute_z_digest(z, md, smctx->ctx.id, smctx->ctx.id_len, ec))
		return OPENSSL_FAIL;
	return EVP_DigestUpdate(mctx, z, (size_t)mdlen);
}

static void hpre_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);

	if (!smctx)
		return;

	EC_GROUP_free(smctx->ctx.gen_group);
	OPENSSL_free(smctx->ctx.id);

	if (smctx->e_hpre_sm2_ctx && smctx->e_hpre_sm2_ctx->wd_ctx) {
		wcrypto_del_ecc_ctx(smctx->e_hpre_sm2_ctx->wd_ctx);
		smctx->e_hpre_sm2_ctx->wd_ctx = NULL;
	}

	BN_free(smctx->order);
	free(smctx);
	EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int hpre_sm2_encrypt_init(EVP_PKEY_CTX *ctx)
{
	return OPENSSL_SUCCESS;
}

static int openssl_soft_encrypt(EVP_PKEY_CTX *ctx,
			   unsigned char *out, size_t *outlen,
			   const unsigned char *in, size_t inlen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_DEC enc_pfunc = NULL;

	openssl_meth = hpre_get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_encrypt(openssl_meth, NULL, &enc_pfunc);
	if (!enc_pfunc) {
		fprintf(stderr, "enc_pfunc is NULL\n");
		return OPENSSL_FAIL;
	}

	return (*enc_pfunc)(ctx, out, outlen, in, inlen);
}

static int openssl_soft_decrypt(EVP_PKEY_CTX *ctx,
			   unsigned char *out, size_t *outlen,
			   const unsigned char *in, size_t inlen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_ENC dec_pfunc = NULL;

	openssl_meth = hpre_get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_decrypt(openssl_meth, NULL, &dec_pfunc);
	if (!dec_pfunc) {
		fprintf(stderr, "dec_pfunc is NULL\n");
		return OPENSSL_FAIL;
	}

	return (*dec_pfunc)(ctx, out, outlen, in, inlen);
}

static size_t sm2_field_size(const EC_GROUP *group)
{
	BIGNUM *p = BN_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	size_t field_size = 0;
	size_t p_bits;

	if (p == NULL || a == NULL || b == NULL)
		goto done;

	if (!EC_GROUP_get_curve(group, p, a, b, NULL))
		goto done;

	p_bits = BN_num_bits(p);
	field_size = BITS_TO_BYTES(p_bits);

done:
	BN_free(p);
	BN_free(a);
	BN_free(b);

	return field_size;
}

static int hpre_sm2_ciphertext_size(const EC_KEY *key,
			       const EVP_MD *digest, size_t msg_len,
			       size_t *ct_size)
{
	const size_t field_size = sm2_field_size(EC_KEY_get0_group(key));
	const int md_size = EVP_MD_size(digest);
	size_t sz;

	if (field_size == 0 || md_size < 0)
		return OPENSSL_FAIL;

	/*
	 * Integer and string are simple type; set constructed = 0, means
	 * primitive and definite length encoding.
	 */
	sz = ECC_POINT_SIZE(ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER))
		+ ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
		+ ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
	*ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_encrypt_check(EVP_PKEY_CTX *ctx,
			     unsigned char *out, size_t *outlen,
			     const unsigned char *in, size_t inlen)
{
	US_DEBUG("sm2_encrypt_check started.\n");
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	const EVP_MD *md;
	int c3_size;

	if (!smctx || !smctx->e_hpre_sm2_ctx || !smctx->e_hpre_sm2_ctx->wd_ctx) {
		fprintf(stderr, "smctx or sess NULL\n");
		return OPENSSL_FAIL;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
	c3_size = EVP_MD_size(md);
	if (c3_size <= 0) {
		fprintf(stderr, "c3 size error\n");
		return OPENSSL_FAIL;
	}

	if (!out) {
		if (!hpre_sm2_ciphertext_size(ec, md, inlen, outlen))
			return OPENSSL_FAIL;
		else
			return OPENSSL_SUCCESS;
	}

	if (inlen > UINT_MAX)
		return OPENSSL_FAIL;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_encrypt_init_iot(void* sess, struct wcrypto_ecc_op_data *opdata,
				unsigned char *in, size_t inlen)
{
	struct wcrypto_ecc_out *ecc_out;
	struct wcrypto_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wcrypto_new_sm2_enc_out(sess, inlen);
	if (!ecc_out) {
		fprintf(stderr, "failed to new enc out\n");
		return OPENSSL_FAIL;
	}

	e.data = (void *)in;
	e.dsize = inlen;
	ecc_in = wcrypto_new_sm2_enc_in(sess, NULL, &e);
	if (!ecc_in) {
		fprintf(stderr, "failed to new enc in\n");
		wcrypto_del_ecc_out(sess, ecc_out);
		return OPENSSL_FAIL;
	}

	opdata->op_type = WCRYPTO_SM2_ENCRYPT;
	opdata->in = ecc_in;
	opdata->out = ecc_out;
	return OPENSSL_SUCCESS;
}

int hpre_sm2_set_public_key(void *sess, const EC_KEY *eckey)
{
	unsigned char *point_bin = NULL;
	struct wcrypto_ecc_point pubkey;
	struct wcrypto_ecc_key *ecc_key;
	const EC_POINT *point;
	const EC_GROUP *group;
	int ret, len;

	point = EC_KEY_get0_public_key(eckey);
	if (!point) {
		fprintf(stderr, "pubkey not set!\n");
		return OPENSSL_FAIL;
	}

	group = EC_KEY_get0_group(eckey);
	len = EC_POINT_point2buf(group, point, SM2_OCTET_STRING,
				 &point_bin, NULL);
	if (!len) {
		fprintf(stderr, "EC_POINT_point2buf error.\n");
		return OPENSSL_FAIL;
	}

	len /= SM2_ECC_PUBKEY_PARAM_NUM;
	pubkey.x.data = (char *)point_bin + 1;
	pubkey.x.dsize = len;
	pubkey.y.data = pubkey.x.data + len;
	pubkey.y.dsize = len;
	ecc_key = wcrypto_get_ecc_key(sess);
	ret = wcrypto_set_ecc_pubkey(ecc_key, &pubkey);
	if (ret) {
		fprintf(stderr, "failed to set ecc pubkey\n");
		ret = OPENSSL_FAIL;
	}

	free(point_bin);

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_update_public_key(EVP_PKEY_CTX *ctx)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *eckey = EVP_PKEY_get0(p_key);
	const EC_GROUP *group;
	const EC_POINT *point;
	int ret;

	point = EC_KEY_get0_public_key(eckey);
	if (!point) {
		fprintf(stderr, "pubkey not set!\n");
		return OPENSSL_FAIL;
	}

	if (smctx->pubkey) {
		group = EC_KEY_get0_group(eckey);
		ret = EC_POINT_cmp(group, (void *)smctx->pubkey, point, NULL);
		if (!ret)
			return OPENSSL_SUCCESS;
	}

	ret = hpre_sm2_set_public_key(smctx->e_hpre_sm2_ctx->wd_ctx, eckey);
	if (!ret)
		return OPENSSL_FAIL;

	smctx->pubkey = point;
	return OPENSSL_SUCCESS;
}

static int hpre_sync_do_sm2(struct hpre_sm2_engine_ctx *engine, struct wcrypto_ecc_op_data *opdata)
{
	int ret = wcrypto_do_sm2(engine->wd_ctx, opdata, NULL);
	if(ret != KAE_SUCCESS) {
		return OPENSSL_FAIL;
	}
	return OPENSSL_SUCCESS;

}

static int hpre_async_do_sm2(struct hpre_sm2_engine_ctx *eng_ctx,
		struct wcrypto_ecc_op_data *opdata, op_done_t *op_done)
{
	int ret = 0;
	int cnt = 0;
	enum task_type type = ASYNC_TASK_ECC;
	void *tag = eng_ctx;

	do {
		if (cnt > MAX_SEND_TRY_CNTS)
			break;
		ret = wcrypto_do_sm2(eng_ctx->wd_ctx, opdata, tag);
		if (ret == -WD_EBUSY) {
			if ((async_wake_job_v1(op_done->job, ASYNC_STATUS_EAGAIN) == 0 ||
						(async_pause_job_v1(op_done->job, ASYNC_STATUS_EAGAIN) == 0))) {
				US_ERR("hpre wake job or hpre pause job fail!");
				ret = 0;
				break;
			}
			cnt++;
		}
	} while (ret == -WD_EBUSY);

	if (ret != WD_SUCCESS)
		return OPENSSL_FAIL;

	if (async_add_poll_task_v1(eng_ctx, op_done, type) == 0)
		return OPENSSL_FAIL;

	return OPENSSL_SUCCESS;
}


int hpre_sm2_crypto(struct wcrypto_ecc_op_data *opdata, struct hpre_sm2_priv_ctx *smctx)
{
	op_done_t op;
	int ret;

	async_init_op_done_v1(&op);

	if (op.job != NULL && kae_is_async_enabled()) {
		if (async_setup_async_event_notification_v1(0) == 0) {
			US_ERR("hpre async event notifying failed");
			async_cleanup_op_done_v1(&op);
			return OPENSSL_FAIL;
		}
	} else {
		US_DEBUG("hpre rsa no async Job or async disable, back to sync!");
		async_cleanup_op_done_v1(&op);
		return hpre_sync_do_sm2(smctx->e_hpre_sm2_ctx, opdata);
	}

	if (!hpre_async_do_sm2(smctx->e_hpre_sm2_ctx, opdata, &op))
		goto err;

	do {
		ret = async_pause_job_v1(op.job, ASYNC_STATUS_OK);
		if (ret == 0) {
			US_DEBUG("- pthread_yidle -");
			kae_pthread_yield();
		}
	} while (!op.flag || ASYNC_CHK_JOB_RESUMED_UNEXPECTEDLY(ret));

	if (op.verifyRst <= 0) {
		US_ERR("hpre sm2 verify result failed with %d", op.verifyRst);
		async_cleanup_op_done_v1(&op);
		return OPENSSL_FAIL;
	}

	async_cleanup_op_done_v1(&op);

	US_DEBUG("hpre sm2 do async job success!");
	return OPENSSL_SUCCESS;

err:
	US_ERR("hpre sm2 do async job err");
	(void)async_clear_async_event_notification_v1();
	async_cleanup_op_done_v1(&op);
	return OPENSSL_FAIL;
}

static int sm2_cipher_bin_to_ber(const EVP_MD *md, struct wcrypto_ecc_point *c1,
			     struct wd_dtb *c2, struct wd_dtb *c3,
			     unsigned char *ber, size_t *ber_len)
{
	struct hpre_sm2_ciphertext ctext_struct;
	int ciphertext_leni, ret;
	BIGNUM *x1, *y1;

	x1 = BN_bin2bn((void *)c1->x.data, c1->x.dsize, NULL);
	if (!x1) {
		fprintf(stderr, "failed to BN_bin2bn x1\n");
		return OPENSSL_FAIL;
	}

	y1 = BN_bin2bn((void *)c1->y.data, c1->y.dsize, NULL);
	if (!y1) {
		fprintf(stderr, "failed to BN_bin2bn y1\n");
		ret = OPENSSL_FAIL;
		goto free_x1;
	}

	ctext_struct.C1x = x1;
	ctext_struct.C1y = y1;
	ctext_struct.C3 = ASN1_OCTET_STRING_new();
	if (!ctext_struct.C3) {
		ret = OPENSSL_FAIL;
		goto free_y1;
	}

	ctext_struct.C2 = ASN1_OCTET_STRING_new();
	if (!ctext_struct.C2) {
		ret = OPENSSL_FAIL;
		goto free_y1;
	}

	if (!ASN1_OCTET_STRING_set(ctext_struct.C3, (void *)c3->data, c3->dsize)
		|| !ASN1_OCTET_STRING_set(ctext_struct.C2,
					  (void *)c2->data, c2->dsize)) {
		fprintf(stderr, "failed to ASN1_OCTET_STRING_set\n");
		ret = OPENSSL_FAIL;
		goto free_y1;
	}

	ciphertext_leni = i2d_HPRE_SM2_Ciphertext(&ctext_struct,
					     (unsigned char **)&ber);
	/* Ensure cast to size_t is safe */
	if (ciphertext_leni < 0) {
		ret = OPENSSL_FAIL;
		goto free_y1;
	}
	*ber_len = (size_t)ciphertext_leni;
	ret = OPENSSL_SUCCESS;
free_y1:
	BN_free(y1);
free_x1:
	BN_free(x1);

	return ret;
}

// 之后需要考虑下异常不走软算的场景
static int hpre_sm2_encrypt(EVP_PKEY_CTX *ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	struct wcrypto_ecc_point *c1 = NULL;
	struct wd_dtb *c2 = NULL;
	struct wd_dtb *c3 = NULL;
	struct wcrypto_ecc_op_data opdata;
	const EVP_MD *md;
	int ret;

	ret = hpre_sm2_encrypt_check(ctx, out, outlen, in, inlen);
	if (!ret){
		US_ERR("hpre_sm2_encrypt_check failed ,then switch to soft!\n");
		goto do_soft;
	}

	if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
		ret = OPENSSL_FAIL;
		goto do_soft;
	}

	memset(&opdata, 0, sizeof(opdata));

	ret = hpre_sm2_encrypt_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, (void *)in, inlen);
	if (!ret){
		US_ERR("sm2_encrypt_init_iot failed , then switch to soft!\n");
		goto do_soft;
	}

	ret = hpre_sm2_update_public_key(ctx);
	if (!ret) {
		ret = OPENSSL_FAIL;
		US_ERR("update_public_key failed , then switch to soft!\n");
		goto uninit_iot;
	}

	ret = hpre_sm2_crypto(&opdata, smctx); //wcrypto_do_sm2函数返回0是表示成功
	if (!ret) {
		ret = OPENSSL_FAIL;
		fprintf(stderr, "failed to sm2_crypto in encrypt, ret = %d\n", ret);
		US_ERR("uadk_ecc_crypto failed.\n");
		goto uninit_iot;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
	wcrypto_get_sm2_enc_out_params(opdata.out, &c1, &c2, &c3);
	if (!c1 || !c2 || !c3) {
		ret = OPENSSL_FAIL;
		goto uninit_iot;
	}

	ret = sm2_cipher_bin_to_ber(md, c1, c2, c3, out, outlen);
	if (!ret)
		goto uninit_iot;

	ret = OPENSSL_SUCCESS;
uninit_iot:
	wcrypto_del_ecc_in(smctx->e_hpre_sm2_ctx->wd_ctx, opdata.in);
	wcrypto_del_ecc_out(smctx->e_hpre_sm2_ctx->wd_ctx, opdata.out);
	if (ret == OPENSSL_SUCCESS)
		return ret;
do_soft:

	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_soft_encrypt(ctx, out, outlen, in, inlen);
}

static int hpre_sm2_decrypt_init(EVP_PKEY_CTX *ctx)
{
	return OPENSSL_SUCCESS;
}

static int sm2_cipher_ber_to_bin(unsigned char *ber, size_t ber_len,
			     struct wcrypto_ecc_point *c1,
			     struct wd_dtb *c2,
			     struct wd_dtb *c3)
{
	struct hpre_sm2_ciphertext *ctext_struct;
	int ret, len, len1;

	ctext_struct = d2i_HPRE_SM2_Ciphertext(NULL, (const unsigned char **)&ber,
					  ber_len);
	if (!ctext_struct) {
		fprintf(stderr, "failed to d2i_SM2_Ciphertext\n");
		return OPENSSL_FAIL;
	}

	len = BN_num_bytes(ctext_struct->C1x);
	len1 = BN_num_bytes(ctext_struct->C1y);
	c1->x.data = malloc(len + len1 + ctext_struct->C2->length +
			    ctext_struct->C3->length);
	if (!c1->x.data) {
		goto free_ctext;
	}
	c1->y.data = c1->x.data + len;
	c3->data = c1->y.data + len1;
	c2->data = c3->data + ctext_struct->C3->length;
	memcpy(c2->data, ctext_struct->C2->data, ctext_struct->C2->length);
	memcpy(c3->data, ctext_struct->C3->data, ctext_struct->C3->length);
	c2->dsize = ctext_struct->C2->length;
	c3->dsize = ctext_struct->C3->length;
	c1->x.dsize = BN_bn2bin(ctext_struct->C1x, (void *)c1->x.data);
	c1->y.dsize = BN_bn2bin(ctext_struct->C1y, (void *)c1->y.data);

	return OPENSSL_SUCCESS;
free_ctext:
	HPRE_SM2_Ciphertext_free(ctext_struct);
	return OPENSSL_FAIL;
}

static int hpre_sm2_decrypt_init_iot(void* sess,
				struct wcrypto_ecc_op_data *opdata,
				struct wcrypto_ecc_point *c1,
				struct wd_dtb *c2,
				struct wd_dtb *c3)
{
	struct wcrypto_ecc_out *ecc_out;
	struct wcrypto_ecc_in *ecc_in;

	ecc_out = wcrypto_new_sm2_dec_out(sess, c2->dsize);
	if (!ecc_out) {
		fprintf(stderr, "failed to new dec out\n");
		return OPENSSL_FAIL;
	}

	ecc_in = wcrypto_new_sm2_dec_in(sess, c1, c2, c3);
	if (!ecc_in) {
		fprintf(stderr, "failed to new dec in\n");
		wcrypto_del_ecc_out(sess, ecc_out);
		return OPENSSL_FAIL;
	}

	opdata->op_type = WCRYPTO_SM2_DECRYPT;
	opdata->in = ecc_in;
	opdata->out = ecc_out;

	return OPENSSL_SUCCESS;
}

int hpre_sm2_set_private_key(void * sess, const EC_KEY *eckey)
{
	unsigned char bin[SM2_MAX_KEY_BYTES];
	struct wcrypto_ecc_key *ecc_key;
	const EC_GROUP *group;
	struct wd_dtb prikey;
	const BIGNUM *d;
	size_t degree;
	int buflen;
	int ret;

	d = EC_KEY_get0_private_key(eckey);
	if (!d) {
		fprintf(stderr, "private key not set\n");
		return OPENSSL_FAIL;
	}

	group = EC_KEY_get0_group(eckey);
	if (!group) {
		fprintf(stderr, "failed to get ecc group\n");
		return OPENSSL_FAIL;
	}

	degree = EC_GROUP_get_degree(group);
	buflen = BITS_TO_BYTES(degree);
	ecc_key = wcrypto_get_ecc_key(sess);
	prikey.data = (void *)bin;
	prikey.dsize = BN_bn2binpad(d, bin, buflen);

	ret = wcrypto_set_ecc_prikey(ecc_key, &prikey);
	if (ret != KAE_SUCCESS) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		ret = OPENSSL_FAIL;
	} // 是否考虑下其他返回码

	return OPENSSL_SUCCESS;
}


static int hpre_sm2_update_private_key(EVP_PKEY_CTX *ctx)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *eckey = EVP_PKEY_get0(p_key);
	const BIGNUM *d;
	int ret;

	d = EC_KEY_get0_private_key(eckey);
	if (!d) {
		fprintf(stderr, "private key not set\n");
		return OPENSSL_FAIL;
	}

	if (smctx->prikey && !BN_cmp(d, smctx->prikey))
		return OPENSSL_SUCCESS;

	ret = hpre_sm2_set_private_key(smctx->e_hpre_sm2_ctx->wd_ctx, eckey);
	if (!ret)
		return OPENSSL_FAIL;

	smctx->prikey = d;
	return OPENSSL_SUCCESS;
}

static int hpre_sm2_get_plaintext(struct wcrypto_ecc_op_data *opdata,
			     unsigned char *out, size_t *outlen)
{
	struct wd_dtb *ptext = NULL;

	wcrypto_get_sm2_dec_out_params(opdata->out, &ptext);
	if (!ptext) {
		fprintf(stderr, "failed to get ptext\n");
		return OPENSSL_FAIL;
	}

	if (*outlen < ptext->dsize) {
		fprintf(stderr, "outlen(%lu) < (%u)\n", *outlen, ptext->dsize);
		return OPENSSL_FAIL;
	}

	memcpy(out, ptext->data, ptext->dsize);
	*outlen = ptext->dsize;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_plaintext_size(const unsigned char *ct, size_t ct_size, size_t *pt_size)
{
	struct hpre_sm2_ciphertext *sm2_ctext;

	sm2_ctext = d2i_HPRE_SM2_Ciphertext(NULL, &ct, ct_size);
	if (!sm2_ctext) {
		fprintf(stderr, "invalid sm2 encoding\n");
		return OPENSSL_FAIL;
	}

	*pt_size = sm2_ctext->C2->length;
	HPRE_SM2_Ciphertext_free(sm2_ctext);

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_decrypt_check(EVP_PKEY_CTX *ctx,
			     unsigned char *out, size_t *outlen,
			     const unsigned char *in, size_t inlen)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	const EVP_MD *md;
	int hash_size;

	if (!smctx || !smctx->e_hpre_sm2_ctx || !smctx->e_hpre_sm2_ctx->wd_ctx) {
		fprintf(stderr, "smctx or sess NULL\n");
		return OPENSSL_FAIL;
	}

	if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
		fprintf(stderr, "sm2 ctx init failed\n");
		return OPENSSL_FAIL;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
	hash_size = EVP_MD_size(md);
	if (hash_size <= 0) {
		fprintf(stderr, "hash size = %d error\n", hash_size);
		return OPENSSL_FAIL;
	}

	if (!out) {
		if (!hpre_sm2_plaintext_size(in, inlen, outlen))
			return OPENSSL_FAIL;
		else
			return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_decrypt(EVP_PKEY_CTX *ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	struct wcrypto_ecc_point c1;
	struct wcrypto_ecc_op_data opdata;
	struct wd_dtb c2, c3;
	const EVP_MD *md;
	int ret;

	ret = hpre_sm2_decrypt_check(ctx, out, outlen, in, inlen);
	if (!ret)
		goto do_soft;

	if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
		goto do_soft;
	}

	md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;

	ret = sm2_cipher_ber_to_bin((void *)in, inlen, &c1, &c2, &c3);
	if (!ret)
		goto do_soft;

	if (c3.dsize != EVP_MD_size(md)) {
		fprintf(stderr, "c3 dsize != hash_size\n");
		goto free_c1;
	}

	memset(&opdata, 0, sizeof(opdata));
	ret = hpre_sm2_decrypt_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, &c1, &c2, &c3);
	if (!ret)
		goto free_c1;

	ret = hpre_sm2_update_private_key(ctx);
	if (!ret) {
		goto uninit_iot;
	}

	ret = hpre_sm2_crypto(&opdata, smctx);
	if (!ret) {
		fprintf(stderr, "failed to sm2_crypto in decrypt, ret = %d\n", ret);
		goto uninit_iot;
	}

	ret = hpre_sm2_get_plaintext(&opdata, out, outlen);
	if (!ret)
		goto uninit_iot;

	ret = OPENSSL_SUCCESS;
uninit_iot:
	wcrypto_del_ecc_in(smctx->e_hpre_sm2_ctx->wd_ctx, opdata.in);
	wcrypto_del_ecc_out(smctx->e_hpre_sm2_ctx->wd_ctx, opdata.out);
free_c1:
	free(c1.x.data);
	if (ret == OPENSSL_SUCCESS) //得考虑异常情况不走soft，抛异常
		return ret;
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_soft_decrypt(ctx, out, outlen, in, inlen);
}

static int hpre_sm2_sign_init(EVP_PKEY_CTX *ctx)
{
	return OPENSSL_SUCCESS;
}

static int hpre_sm2_sign_init_iot(void * sess, struct wcrypto_ecc_op_data *opdata,
			     unsigned char *digest, size_t digest_len)
{
	struct wcrypto_ecc_out *ecc_out;
	struct wcrypto_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wcrypto_new_sm2_sign_out(sess);
	if (!ecc_out) {
		fprintf(stderr, "failed to new sign out\n");
		return OPENSSL_FAIL;
	}

	e.data = (void *)digest;
	e.dsize = digest_len;
	ecc_in = wcrypto_new_sm2_sign_in(sess, &e, NULL, NULL, 1);
	if (!ecc_in) {
		fprintf(stderr, "failed to new sign in\n");
		wcrypto_del_ecc_out(sess, ecc_out);
		return OPENSSL_FAIL;
	}

	opdata->op_type = WCRYPTO_SM2_SIGN;
	opdata->in = ecc_in;
	opdata->out = ecc_out;

	return OPENSSL_SUCCESS;
}

bool data_all_zero(const unsigned char *data, size_t dlen)
{
	int i;

	for (i = 0; i < dlen; i++) {
		if (data[i])
			return false;
	}

	return true;
}

static int hpre_sm2_sign_check(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		  const unsigned char *tbs, size_t tbslen)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	const int sig_sz = ECDSA_size(ec);

	/*
	 * If 'sig' is NULL, users can use sm2_decrypt API to obtain the valid 'siglen' first,
	 * then users use the value of 'signlen' to alloc the memory of 'sig' and call the
	 * sm2_decrypt API a second time to do the decryption task.
	 */
	if (sig == NULL) {
		*siglen = (size_t)sig_sz;
		return OPENSSL_SUCCESS;
	}

	if (!smctx || !smctx->e_hpre_sm2_ctx || !smctx->e_hpre_sm2_ctx->wd_ctx) {
		fprintf(stderr, "smctx or sess NULL\n");
		return OPENSSL_FAIL;
	}

	if (sig_sz <= 0) {
		fprintf(stderr, "sig_sz error\n");
		return OPENSSL_FAIL;
	}

	if (*siglen < (size_t)sig_sz) {
		fprintf(stderr, "siglen(%lu) < sig_sz(%lu)\n", *siglen, (size_t)sig_sz);
		return OPENSSL_FAIL;
	}

	if (tbslen > SM2_KEY_BYTES)
		return OPENSSL_FAIL;

	if (data_all_zero(tbs, tbslen))
		return OPENSSL_FAIL;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_sign_bin_to_ber(EC_KEY *ec, struct wd_dtb *r, struct wd_dtb *s,
			   unsigned char *sig, size_t *siglen)
{
	int ret = OPENSSL_FAIL;
	ECDSA_SIG *e_sig;
	BIGNUM *br, *bs;
	int sltmp;

	e_sig = ECDSA_SIG_new();
	if (!e_sig) {
		fprintf(stderr, "failed to ECDSA_SIG_new\n");
		return OPENSSL_FAIL;
	}

	br = BN_bin2bn((void *)r->data, r->dsize, NULL);
	if (!br) {
		fprintf(stderr, "failed to BN_bin2bn r\n");
		goto free_sig;
	}

	bs = BN_bin2bn((void *)s->data, s->dsize, NULL);
	if (!bs) {
		fprintf(stderr, "failed to BN_bin2bn s\n");
		goto free_r;
	}

	ret = ECDSA_SIG_set0(e_sig, br, bs);
	if (!ret) {
		fprintf(stderr, "failed to ECDSA_SIG_set0\n");
		goto free_s;
	}

	sltmp = i2d_ECDSA_SIG(e_sig, &sig);
	if (sltmp < 0) {
		fprintf(stderr, "failed to i2d_ECDSA_SIG\n");
		goto free_s;
	}
	*siglen = (size_t)sltmp;
	return OPENSSL_SUCCESS;

free_s:
	BN_free(bs);
free_r:
	BN_free(br);
free_sig:
	ECDSA_SIG_free(e_sig);

	return OPENSSL_FAIL;
}

static int openssl_soft_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_SIGN sign_pfunc = NULL;

	openssl_meth = hpre_get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_sign(openssl_meth, NULL, &sign_pfunc);
	if (!sign_pfunc) {
		fprintf(stderr, "sign_pfunc is NULL\n");
		return OPENSSL_FAIL;
	}

	return (*sign_pfunc)(ctx, sig, siglen, tbs, tbslen);
}

static int hpre_sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		    const unsigned char *tbs, size_t tbslen)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	struct wcrypto_ecc_op_data opdata;
	int ret;

	ret = hpre_sm2_sign_check(ctx, sig, siglen, tbs, tbslen);
	if (!ret)
		goto do_soft;

	if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
		goto do_soft;
	}

	memset(&opdata, 0, sizeof(opdata));
	ret = hpre_sm2_sign_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, (void *)tbs, tbslen);
	if (!ret)
		goto do_soft;

	ret = hpre_sm2_update_private_key(ctx);
	if (!ret) {
		goto uninit_iot;
	}

	ret = hpre_sm2_crypto(&opdata, smctx);
	if (!ret) {
		fprintf(stderr, "failed to sm2_crypto in sign, ret = %d\n", ret);
		goto uninit_iot;
	}

	wcrypto_get_sm2_sign_out_params(opdata.out, &r, &s);
	if (!r || !s) {
		goto uninit_iot;
	}

	ret = hpre_sm2_sign_bin_to_ber(NULL, r, s, sig, siglen);
	if (!ret)
		goto uninit_iot;

	ret = OPENSSL_SUCCESS;

uninit_iot:
	wcrypto_del_ecc_in(smctx->e_hpre_sm2_ctx->wd_ctx, opdata.in);
	wcrypto_del_ecc_out(smctx->e_hpre_sm2_ctx->wd_ctx, opdata.out);
	if (ret == OPENSSL_SUCCESS){
		US_DEBUG("sm2_sign successed!\n");
		return OPENSSL_SUCCESS;
	}
do_soft:
	fprintf(stderr, "sm2_sign failed, switch to execute openssl software calculation.\n");
	US_ERR("sm2_sign failed, switch to execute openssl software calculation.\n");
	return openssl_soft_sign(ctx, sig, siglen, tbs, tbslen);
}

static int hpre_sm2_verify_init(EVP_PKEY_CTX *ctx)
{
	return OPENSSL_SUCCESS;
}

static int hpre_sm2_verify_check(EVP_PKEY_CTX *ctx,
			    const unsigned char *sig,
			    size_t siglen,
			    const unsigned char *tbs,
			    size_t tbslen)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);

	if (!smctx || !smctx->e_hpre_sm2_ctx || !smctx->e_hpre_sm2_ctx->wd_ctx) {
		fprintf(stderr, "smctx or sess NULL\n");
		return OPENSSL_FAIL;
	}

	if (tbslen > SM2_KEY_BYTES)
		return OPENSSL_FAIL;

	if (data_all_zero(tbs, tbslen))
		return OPENSSL_FAIL;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_verify_init_iot(void * sess, struct wcrypto_ecc_op_data *opdata,
			       struct wd_dtb *e, struct wd_dtb *r,
			       struct wd_dtb *s)
{
	struct wcrypto_ecc_in *ecc_in;

	ecc_in = wcrypto_new_sm2_verf_in(sess, e, r, s, NULL, 1);
	if (!ecc_in) {
		fprintf(stderr, "failed to new verf in\n");
		return OPENSSL_FAIL;
	}

	opdata->op_type = WCRYPTO_SM2_VERIFY;
	opdata->in = ecc_in;

	return OPENSSL_SUCCESS;
}

static int hpre_sm2_sig_ber_to_bin(EC_KEY *ec, unsigned char *sig, size_t sig_len,
			  struct wd_dtb *r, struct wd_dtb *s)
{
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	ECDSA_SIG *e_sig = NULL;
	int ret, len1, len2;
	BIGNUM *b_r, *b_s;

	e_sig = ECDSA_SIG_new();
	if (!e_sig) {
		fprintf(stderr, "failed to ECDSA_SIG_new\n");
		return OPENSSL_FAIL;
	}

	if (d2i_ECDSA_SIG(&e_sig, &p, sig_len) == NULL) {
		fprintf(stderr, "d2i_ECDSA_SIG error\n");
		ret = OPENSSL_FAIL;
		goto free_sig;
	}

	/* Ensure signature uses DER and doesn't have trailing garbage */
	len1 = i2d_ECDSA_SIG(e_sig, &der);
	if (len1 != sig_len || memcmp(sig, der, len1) != 0) {
		fprintf(stderr, "sig data error, derlen(%d), sig_len(%lu)\n",
		len1, sig_len);
		ret = OPENSSL_FAIL;
		goto free_der;
	}

	b_r = (void *)ECDSA_SIG_get0_r((const ECDSA_SIG *)e_sig);
	if (!b_r) {
		fprintf(stderr, "failed to get r\n");
		ret = OPENSSL_FAIL;
		goto free_der;
	}

	b_s = (void *)ECDSA_SIG_get0_s((const ECDSA_SIG *)e_sig);
	if (!b_s) {
		fprintf(stderr, "failed to get s\n");
		ret = OPENSSL_FAIL;
		goto free_der;
	}

	len1 = BN_num_bytes(b_r);
	len2 = BN_num_bytes(b_s);
	if (len1 > SM2_MAX_KEY_BYTES || len2 > SM2_MAX_KEY_BYTES) {
		fprintf(stderr, "r or s bytes = (%d, %d) error\n", len1, len2);
		ret = OPENSSL_FAIL;
		goto free_der;
	}
	r->dsize = BN_bn2bin(b_r, (void *)r->data);
	s->dsize = BN_bn2bin(b_s, (void *)s->data);
	ret = OPENSSL_SUCCESS;
free_der:
	OPENSSL_free(der);
free_sig:
	ECDSA_SIG_free(e_sig);

	return ret;
}

static int openssl_soft_verify(EVP_PKEY_CTX *ctx,
			  const unsigned char *sig, size_t siglen,
			  const unsigned char *tbs, size_t tbslen)
{
	const EVP_PKEY_METHOD *openssl_meth;
	PFUNC_VERIFY verify_pfunc = NULL;

	openssl_meth = hpre_get_openssl_pkey_meth(EVP_PKEY_SM2);
	EVP_PKEY_meth_get_verify(openssl_meth, NULL, &verify_pfunc);
	if (!verify_pfunc) {
		fprintf(stderr, "verify_pfunc is NULL\n");
		return OPENSSL_FAIL;
	}

	return (*verify_pfunc)(ctx, sig, siglen, tbs, tbslen);
}



static int hpre_sm2_verify(EVP_PKEY_CTX *ctx,
		      const unsigned char *sig, size_t siglen,
		      const unsigned char *tbs, size_t tbslen)
{
	struct hpre_sm2_priv_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	unsigned char buf_r[SM2_MAX_KEY_BYTES] = {0};
	unsigned char buf_s[SM2_MAX_KEY_BYTES] = {0};
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	struct wd_dtb e = {0};
	struct wd_dtb r = {0};
	struct wd_dtb s = {0};
	struct wcrypto_ecc_op_data opdata;
	int ret;

	ret = hpre_sm2_verify_check(ctx, sig, siglen, tbs, tbslen);
	if (!ret){
		US_ERR("sm2_verify_check failed.\n");
		goto do_soft;
	}

	if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
		ret = OPENSSL_FAIL;
		goto do_soft;
	}

	r.data = (void *)buf_r;
	s.data = (void *)buf_s;
	r.bsize = SM2_MAX_KEY_BYTES;
	s.bsize = SM2_MAX_KEY_BYTES;
	ret = hpre_sm2_sig_ber_to_bin(ec, (void *)sig, siglen, &r, &s);
	if (!ret)
		return OPENSSL_FAIL;

	e.data = (void *)tbs;
	e.dsize = tbslen;
	memset(&opdata, 0, sizeof(opdata));
	ret = hpre_sm2_verify_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, &e, &r, &s);
	if (!ret)
		goto do_soft;

	ret = hpre_sm2_update_public_key(ctx);
	if (!ret) {
		ret = OPENSSL_FAIL;
		US_ERR("sm2_verify_check failed,switch to soft.\n");
		goto uninit_iot;
	}

	ret = hpre_sm2_crypto(&opdata, smctx);
	if (!ret) {
		ret = OPENSSL_FAIL;
		fprintf(stderr, "failed to sm2_crypto in verify, ret = %d\n", ret);
		US_ERR("uadk_ecc_crypto failed,switch to soft.\n");
		goto uninit_iot;
	}
	ret = OPENSSL_SUCCESS;

uninit_iot:
	wcrypto_del_ecc_in(smctx->e_hpre_sm2_ctx->wd_ctx, opdata.in);
	if (ret == OPENSSL_SUCCESS){
		US_DEBUG("sm2_verify successed!\n");
		return OPENSSL_SUCCESS;
	}
do_soft:
	fprintf(stderr, "sm2_verify failed,switch to execute openssl software calculation.\n");
	US_ERR("sm2_verify failed,switch to execute openssl software calculation.\n");
	return openssl_soft_verify(ctx, sig, siglen, tbs, tbslen);
}

static EVP_PKEY_METHOD *hpre_sm2_create_pmeth()
{
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	if (g_hpre_sm2_method != NULL)
		return g_hpre_sm2_method;

	meth = EVP_PKEY_meth_new(EVP_PKEY_SM2, 0);
	if (meth == NULL) {
		fprintf(stderr, "failed to EVP_PKEY_meth_new\n");
		return NULL;
	}

	openssl_meth = hpre_get_openssl_pkey_meth(EVP_PKEY_SM2);
	if (!openssl_meth) {
		fprintf(stderr, "failed to get sm2 pkey methods\n");
		EVP_PKEY_meth_free(meth);
		return NULL;
	}

	EVP_PKEY_meth_copy(meth, openssl_meth);// 把一些软算功能信息复制过去

	EVP_PKEY_meth_set_init(meth, hpre_sm2_init);
	EVP_PKEY_meth_set_copy(meth, hpre_sm2_copy);
	EVP_PKEY_meth_set_ctrl(meth, hpre_sm2_ctrl, hpre_sm2_ctrl_str);
	EVP_PKEY_meth_set_digest_custom(meth, hpre_sm2_digest_custom);
	EVP_PKEY_meth_set_cleanup(meth, hpre_sm2_cleanup);
	EVP_PKEY_meth_set_encrypt(meth, hpre_sm2_encrypt_init, hpre_sm2_encrypt);
	EVP_PKEY_meth_set_decrypt(meth, hpre_sm2_decrypt_init, hpre_sm2_decrypt);
	EVP_PKEY_meth_set_sign(meth, hpre_sm2_sign_init, hpre_sm2_sign);
	EVP_PKEY_meth_set_verify(meth, hpre_sm2_verify_init, hpre_sm2_verify);

	return meth;
}

EVP_PKEY_METHOD *get_sm2_pkey_meth(void)
{
    int ret;

	if (g_hpre_sm2_method == NULL) {
		g_hpre_sm2_method = hpre_sm2_create_pmeth(g_hpre_sm2_method);
		if (!g_hpre_sm2_method) {
			fprintf(stderr, "failed to register hpre sm2 pmeth.\n");
			return NULL;
		}
	}

	return g_hpre_sm2_method;
}

int hpre_get_sm2_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid) {
    int ret;

    if (unlikely((nids == NULL) && ((pmeth == NULL) || (nid < 0)))) {
		if (pmeth != NULL)
			*pmeth = NULL;
		return OPENSSL_FAIL;
	}
    /* No specific pkeys => return a list of supported nids ... */
	if (!pmeth) {
		*nids = g_known_pkey_nids;
		return BLOCKSIZES_OF(g_known_pkey_nids);
	}
    
    switch (nid) {
	case EVP_PKEY_SM2:
		g_hpre_sm2_method = hpre_sm2_create_pmeth();
		if (!g_hpre_sm2_method) {
			fprintf(stderr, "failed to register hpre sm2 pmeth.\n");
			return 0;
		}
		*pmeth = g_hpre_sm2_method;
		break;
	default:
		fprintf(stderr, "not find nid %d\n", nid);
		return OPENSSL_FAIL;
	}
	return OPENSSL_SUCCESS;
}

int wd_sm2_init_qnode_pool(void)
{
	kae_queue_pool_destroy(g_hpre_sm2_qnode_pool, NULL);

	g_hpre_sm2_qnode_pool = kae_init_queue_pool(WCRYPTO_SM2);
	if (g_hpre_sm2_qnode_pool == NULL) {
		US_ERR("hpre rsa qnode poll init fail!\n");
		return KAE_FAIL;
	}

	return KAE_SUCCESS;
}

KAE_QUEUE_POOL_HEAD_S *wd_hpre_sm2_get_qnode_pool(void)
{
	return g_hpre_sm2_qnode_pool;
}


void wd_sm2_uninit_qnode_pool(void)
{
	kae_queue_pool_destroy(g_hpre_sm2_qnode_pool, NULL);
	g_hpre_sm2_qnode_pool = NULL;
}

// async poll thread create
int sm2_engine_ctx_poll(void *engnine_ctx)
{
	int ret = 0;
	struct hpre_sm2_engine_ctx *eng_ctx = (struct hpre_sm2_engine_ctx *)engnine_ctx;
	struct wd_queue *q = eng_ctx->qlist->kae_wd_queue;

POLL_AGAIN:
	ret = wcrypto_sm2_poll(q, 1);
	if (!ret) {
		goto POLL_AGAIN;
	} else if (ret < 0) {
		US_ERR("sm2 poll failed\n");
		return ret;
	}
	return ret;
}

int hpre_module_sm2_init(void) {

    /* init queue */
	wd_sm2_init_qnode_pool();

	(void)get_sm2_pkey_meth();

	/* register async poll func */
	async_register_poll_fn_v1(ASYNC_TASK_ECC, sm2_engine_ctx_poll);//ASYNC_TASK_ECC 按SVA代码包含sm2

    return OPENSSL_SUCCESS;
}