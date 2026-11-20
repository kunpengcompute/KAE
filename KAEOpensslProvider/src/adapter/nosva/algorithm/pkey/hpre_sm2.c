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
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>

#include "hpre_sm2.h"
#include "../../async/async_callback.h"
#include "../../async/async_task_queue.h"
#include "../../async/async_event.h"
#include "../../async/async_check.h"
#include "../../../common/kae_types.h"
#include "../../../common/kae_log.h"
#include "../../../common/kae_utils.h"
#include "../../wdwarp/wd_queue_memory.h"

#define SM2_DEFAULT_USERID "1234567812345678"
#define SM2_DEFAULT_USERID_LEN 16

KAE_QUEUE_POOL_HEAD_S *g_hpre_sm2_qnode_pool;

DECLARE_ASN1_FUNCTIONS(HPRE_SM2_Ciphertext)

ASN1_SEQUENCE(HPRE_SM2_Ciphertext) =
{
    ASN1_SIMPLE(HPRE_SM2_Ciphertext, C1x, BIGNUM),
    ASN1_SIMPLE(HPRE_SM2_Ciphertext, C1y, BIGNUM),
    ASN1_SIMPLE(HPRE_SM2_Ciphertext, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(HPRE_SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(HPRE_SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(HPRE_SM2_Ciphertext)

// 回调函数，返回值不按OPENSSL规范
static int hpre_sm2_get_rand(char *out, size_t out_len, void *usr)
{
    HPRE_SM2_RAND_CTX *ctx = usr;
    int count = SM2_GET_RAND_MAX_CNT;
    BIGNUM *k;
    int ret;

    if (!out || !ctx || !ctx->order || !ctx->libctx) {
        US_ERR("invalid SM2 random context.");
        return -1;
    }

    /* Keep DRBG's small AES operations out of the global KAE preference. */
    if (!ctx->bn_ctx) {
        ctx->bn_ctx = BN_CTX_new_ex(ctx->libctx);
        if (!ctx->bn_ctx)
            return -ENOMEM;
    }
    k = BN_new();
    if (!k)
        return -ENOMEM;

    do {
        ret = BN_priv_rand_range_ex(k, ctx->order, 0, ctx->bn_ctx);
        if (!ret) {
            US_ERR("failed to BN_priv_rand_range.");
            ret = -ENOMEM;
            goto err;
        }

        ret = BN_bn2binpad(k, (void *)out, (int)out_len);
        if (ret < 0) {
            ret = -ENOMEM;
            US_ERR("failed to BN_bn2binpad.");
            goto err;
        }
    } while (--count >= 0 && BN_is_zero(k));

    ret = 0;
    if (count < 0)
        ret = -1;
err:
    BN_clear_free(k);

    return ret;
}

static void hpre_sm2_rand_ctx_free(HPRE_SM2_RAND_CTX *ctx)
{
    if (!ctx)
        return;
    BN_CTX_free(ctx->bn_ctx);
    BN_clear_free(ctx->order);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

// 回调函数
static int hpre_sm2_compute_hash(const char *in, size_t in_len, char *out, size_t out_len, void *usr)
{
    const EVP_MD *digest = (const EVP_MD *)usr;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    int ret = 0;

    digest = digest ? digest : EVP_sm3();
    if (EVP_DigestInit(hash, digest) == 0 || EVP_DigestUpdate(hash, in, in_len) == 0 ||
        EVP_DigestFinal(hash, (void *)out, NULL) == 0) {
        US_ERR("compute hash failed.");
        ret = -1;
    }

    EVP_MD_CTX_free(hash);

    return ret;
}

static hpre_sm2_engine_ctx_t *wd_sm2_new_engine_ctx(KAE_QUEUE_DATA_NODE_S *q_node, hpre_sm2_priv_ctx *priv_ctx)
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

    if (e_hpre_sm2_ctx->qlist != NULL) {
        e_hpre_sm2_ctx->qlist->engine_ctx = NULL;
        (void)kae_put_node_to_pool(g_hpre_sm2_qnode_pool, e_hpre_sm2_ctx->qlist);
        e_hpre_sm2_ctx->qlist = NULL;
    }

    e_hpre_sm2_ctx = NULL;
}

hpre_sm2_engine_ctx_t *wd_sm2_get_engine_ctx(hpre_sm2_priv_ctx *priv_ctx)
{
    KAE_QUEUE_DATA_NODE_S *q_node = NULL;
    hpre_sm2_engine_ctx_t *e_hpre_sm2_ctx = NULL;

    if (unlikely(priv_ctx == NULL)) {
        US_ERR("sm2 cipher priv ctx NULL!");
        return NULL;
    }

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
    if (wd_sm2_init_engine_ctx(e_hpre_sm2_ctx) == KAE_FAIL) {  // todo
        US_WARN("init engine ctx fail!");
        wd_sm2_put_engine_ctx(e_hpre_sm2_ctx);
        OPENSSL_free(e_hpre_sm2_ctx);
        return NULL;
    }

    return e_hpre_sm2_ctx;
}

void hpre_free_sm2_eng_ctx(hpre_sm2_engine_ctx_t *eng_ctx, struct wcrypto_ecc_op_data opdata)
{
    if (!eng_ctx) {
        return;
    }
    if (opdata.in)
        wcrypto_del_ecc_in(eng_ctx->wd_ctx, opdata.in);
    if (opdata.out)
        wcrypto_del_ecc_out(eng_ctx->wd_ctx, opdata.out);

    wd_sm2_put_engine_ctx(eng_ctx);

    eng_ctx->wd_ctx = NULL;
    eng_ctx->qlist = NULL;
    eng_ctx->priv_ctx = NULL;
    eng_ctx->opdata.in = NULL;
    eng_ctx->opdata.out = NULL;

    OPENSSL_free(eng_ctx);
}

static void hpre_sm2_free_iot(hpre_sm2_engine_ctx_t *eng, struct wcrypto_ecc_op_data opdata)
{
    if (opdata.in != NULL)
        wcrypto_del_ecc_in(eng->wd_ctx, opdata.in);
    if (opdata.out != NULL)
        wcrypto_del_ecc_out(eng->wd_ctx, opdata.out);
    memset(&eng->opdata, 0, sizeof(eng->opdata));
}

void hpre_sm2_cleanup(SM2_PROV_CTX *ctx)
{
    struct wcrypto_ecc_op_data empty = {0};
    hpre_sm2_priv_ctx *priv;

    if (ctx == NULL || ctx->hsmctx == NULL)
        return;
    priv = ctx->hsmctx;
    hpre_free_sm2_eng_ctx(priv->e_hpre_sm2_ctx, empty);
    hpre_sm2_rand_ctx_free(priv->rand_ctx);
    OPENSSL_clear_free(priv, sizeof(*priv));
    ctx->hsmctx = NULL;
    ctx->init_status = 0;
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
#ifndef KAE_TONGSUO
        case NID_md4:
            return WCRYPTO_HASH_MD4;
#endif
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

int hpre_sm2_update_sess(SM2_PROV_CTX *sm2_pctx)
{
	const unsigned char sm2_order[] = {
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
		0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23
	};

    if (!sm2_pctx->hsmctx) {
        sm2_pctx->hsmctx = (hpre_sm2_priv_ctx *)OPENSSL_malloc(sizeof(hpre_sm2_priv_ctx));
        if (sm2_pctx->hsmctx == NULL) {
            US_ERR("hpre smctx malloc fail");
            return OPENSSL_FAIL;
        }
        kae_memset(sm2_pctx->hsmctx, 0, sizeof(hpre_sm2_priv_ctx));
    }

    hpre_sm2_priv_ctx *smctx = sm2_pctx->hsmctx;
    smctx->ctx.md = sm2_pctx->sm2_md->md;
    smctx->md_nid = sm2_pctx->sm2_md->md_nid;

    if (smctx->e_hpre_sm2_ctx == NULL) {
        smctx->e_hpre_sm2_ctx = wd_sm2_get_engine_ctx(smctx);
        if (smctx->e_hpre_sm2_ctx == NULL) {
            US_WARN("hpre sm2 failed to get engine ctx, switch to soft cipher");
            return OPENSSL_FAIL;
        }
    }

    // struct wcrypto_ecc_ctx_setup setup;
    hpre_sm2_engine_ctx_t *e_sm2_ctx = smctx->e_hpre_sm2_ctx;
    void *sess;
    HPRE_SM2_RAND_CTX *rand_ctx;
    int type;

    struct wd_queue *queue = smctx->e_hpre_sm2_ctx->qlist->kae_wd_queue;

    if (smctx->ctx.md) {
        /* Set hash method */
        e_sm2_ctx->setup.hash.cb = hpre_sm2_compute_hash;
        e_sm2_ctx->setup.hash.usr = (void *)smctx->ctx.md;
        type = hpre_sm2_get_hash_type(smctx->md_nid);
        if (type < 0) {
            wd_sm2_put_engine_ctx(smctx->e_hpre_sm2_ctx);
            US_ERR("uadk not support hash nid");
            return OPENSSL_FAIL;
        }
        e_sm2_ctx->setup.hash.type = type;
    }

    rand_ctx = OPENSSL_zalloc(sizeof(*rand_ctx));
    if (rand_ctx == NULL)
        return OPENSSL_FAIL;
    rand_ctx->libctx = sm2_pctx->libctx;
    rand_ctx->order = BN_bin2bn(sm2_order, sizeof(sm2_order), NULL);
    if (!rand_ctx->libctx || !rand_ctx->order) {
        hpre_sm2_rand_ctx_free(rand_ctx);
        return OPENSSL_FAIL;
    }
    e_sm2_ctx->setup.rand.cb = hpre_sm2_get_rand;
    e_sm2_ctx->setup.rand.usr = rand_ctx;
    e_sm2_ctx->setup.cb = (wcrypto_cb)hpre_sm2_cb;
    sess = wcrypto_create_ecc_ctx(queue, &e_sm2_ctx->setup);
    if (!sess) {
        US_ERR("failed to alloc sess");
        wd_sm2_put_engine_ctx(smctx->e_hpre_sm2_ctx);
        hpre_sm2_rand_ctx_free(rand_ctx);
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
    hpre_sm2_rand_ctx_free(smctx->rand_ctx);
    smctx->rand_ctx = rand_ctx;

    return OPENSSL_SUCCESS;
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
    US_ERR("failed to malloc params.");
    return OPENSSL_FAIL;
}

static int hpre_sm2_check_digest_evp_lib(const EVP_MD *digest, EVP_MD_CTX *hash, const size_t id_len, const uint8_t *id)
{
    uint8_t e_byte;
    uint16_t entl;
    if (!EVP_DigestInit(hash, digest)) {
        US_ERR("error evp lib.");
        return OPENSSL_FAIL;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
    if (id_len >= (UINT16_MAX >> TRANS_BITS_BYTES_SHIFT)) {
        US_ERR("id too large.");
        return OPENSSL_FAIL;
    }

    entl = (uint16_t)(id_len << TRANS_BITS_BYTES_SHIFT);

    /* Update the most significant (first) byte of 'entl' */
    e_byte = GET_MS_BYTE(entl);
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        US_ERR("error evp lib.");
        return OPENSSL_FAIL;
    }

    /* Update the least significant (second) byte of 'entl' */
    e_byte = GET_LS_BYTE(entl);
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        US_ERR("error evp lib.");
        return OPENSSL_FAIL;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        US_ERR("error evp lib.");
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int check_equation_param(struct hpre_sm2_param *param, EVP_MD_CTX *hash, uint8_t *buf, int p_bytes)
{
    if (BN_bn2binpad(param->a, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
        BN_bn2binpad(param->b, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes)) {
        US_ERR("failed to check equation param.");
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int check_base_point_group_param(struct hpre_sm2_param *param, BN_CTX *ctx, const EC_KEY *key)
{
    const EC_GROUP *group = EC_KEY_get0_group(key);

    if (!EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group), param->xG, param->yG, ctx)) {
        US_ERR("failed to check base point group param.");
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int check_base_point_param(struct hpre_sm2_param *param, EVP_MD_CTX *hash, uint8_t *buf, int p_bytes)
{
    if (BN_bn2binpad(param->xG, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
        BN_bn2binpad(param->yG, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes)) {
        US_ERR("failed to check base point param.");
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int check_pkey_point_group_param(struct hpre_sm2_param *param, BN_CTX *ctx, const EC_KEY *key)
{
    const EC_GROUP *group = EC_KEY_get0_group(key);

    if (!EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(key), param->xA, param->yA, ctx)) {
        US_ERR("failed to check pkey point group param.");
        return OPENSSL_FAIL;
    }
    return OPENSSL_SUCCESS;
}

static int check_pkey_point_param(
    struct hpre_sm2_param *param, EVP_MD_CTX *hash, uint8_t *buf, int p_bytes, uint8_t *out)
{
    if (BN_bn2binpad(param->xA, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
        BN_bn2binpad(param->yA, buf, p_bytes) < 0 || !EVP_DigestUpdate(hash, buf, p_bytes) ||
        !EVP_DigestFinal(hash, out, NULL)) {
        US_ERR("failed to check pkey point param.");
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

int hpre_sm2_compute_z_digest(
    uint8_t *out, const EVP_MD *digest, const uint8_t *id, const size_t id_len, const EC_KEY *key)
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
        US_ERR("failed to malloc sm2 param.");
        goto free_ctx;
    }

    if (!get_hpre_sm2_param(param, ctx))
        goto free_param;

    if (!hpre_sm2_check_digest_evp_lib(digest, hash, id_len, id))
        goto free_param;

    if (!EC_GROUP_get_curve(group, param->p, param->a, param->b, ctx)) {
        US_ERR("failed to get curve.");
        goto free_param;
    }

    p_bytes = BN_num_bytes(param->p);
    buf = OPENSSL_zalloc(p_bytes);
    if (!buf) {
        US_ERR("failed to malloc buf.");
        goto free_param;
    }

    if (!check_equation_param(param, hash, buf, p_bytes) || !check_base_point_group_param(param, ctx, key) ||
        !check_base_point_param(param, hash, buf, p_bytes) || !check_pkey_point_group_param(param, ctx, key) ||
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

static int hpre_sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len, size_t *ct_size)
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
    sz = ECC_POINT_SIZE(ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)) +
         ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING) + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_smctx_check(SM2_PROV_CTX *sm2_pctx)
{

    if (!sm2_pctx) {
        US_ERR("smctx is NULL.");
        return OPENSSL_FAIL;
    }

    hpre_sm2_priv_ctx *smctx = sm2_pctx->hsmctx;
    if (!smctx || !smctx->e_hpre_sm2_ctx) {
        hpre_sm2_update_sess(sm2_pctx);
    }

    // if (!smctx->e_hpre_sm2_ctx) {
    // 	hpre_sm2_update_sess(smctx);
    // }

    if (!smctx->e_hpre_sm2_ctx->wd_ctx) {
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_encrypt_check(
    PROV_SM2_ASYM_CTX *psm2ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    US_DEBUG("sm2_encrypt_check started.\n");
    hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;
    EC_KEY *ec_key = psm2ctx->ec_key;
    const EVP_MD *md;
    int c3_size;

    if (!hpre_sm2_smctx_check(psm2ctx->sm2_pctx)) {
        return OPENSSL_FAIL;
    }

    md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
    c3_size = EVP_MD_size(md);
    if (c3_size <= 0) {
        US_ERR("c3 size error.");
        return OPENSSL_FAIL;
    }

    if (!out) {
        if (!hpre_sm2_ciphertext_size(ec_key, md, inlen, outlen))
            return OPENSSL_FAIL;
        else
            return OPENSSL_SUCCESS;
    }

    if (inlen > UINT_MAX)
        return OPENSSL_FAIL;

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_encrypt_init_iot(void *sess, struct wcrypto_ecc_op_data *opdata, unsigned char *in, size_t inlen)
{
    struct wcrypto_ecc_out *ecc_out;
    struct wcrypto_ecc_in *ecc_in;
    struct wd_dtb e = {0};

    ecc_out = wcrypto_new_sm2_enc_out(sess, inlen);
    if (!ecc_out) {
        US_ERR("failed to new enc out.");
        return OPENSSL_FAIL;
    }

    e.data = (void *)in;
    e.dsize = inlen;
    ecc_in = wcrypto_new_sm2_enc_in(sess, NULL, &e);
    if (!ecc_in) {
        US_ERR("failed to new enc in.");
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
        US_ERR("pubkey not set!");
        return OPENSSL_FAIL;
    }

    group = EC_KEY_get0_group(eckey);
    len = EC_POINT_point2buf(group, point, SM2_OCTET_STRING, &point_bin, NULL);
    if (!len) {
        US_ERR("EC_POINT_point2buf error.");
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
        US_ERR("failed to set ecc pubkey.");
        ret = OPENSSL_FAIL;
    }

    OPENSSL_free(point_bin);

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_update_public_key(hpre_sm2_priv_ctx *smctx, EC_KEY *ec_key)
{
    const EC_GROUP *group;
    const EC_POINT *point;
    int ret;

    point = EC_KEY_get0_public_key(ec_key);
    if (!point) {
        US_ERR("pubkey not set!");
        return OPENSSL_FAIL;
    }

    if (smctx->pubkey) {
        group = EC_KEY_get0_group(ec_key);
        ret = EC_POINT_cmp(group, (void *)smctx->pubkey, point, NULL);
        if (!ret)
            return OPENSSL_SUCCESS;
    }

    ret = hpre_sm2_set_public_key(smctx->e_hpre_sm2_ctx->wd_ctx, ec_key);
    if (!ret)
        return OPENSSL_FAIL;

    smctx->pubkey = point;
    return OPENSSL_SUCCESS;
}

static int hpre_sync_do_sm2(struct hpre_sm2_engine_ctx *engine, struct wcrypto_ecc_op_data *opdata)
{
    int ret = wcrypto_do_sm2(engine->wd_ctx, opdata, NULL);
    if (ret != KAE_SUCCESS || opdata->status != 0) {
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int hpre_async_do_sm2(
    struct hpre_sm2_engine_ctx *eng_ctx, struct wcrypto_ecc_op_data *opdata, op_done_t *op_done)
{
    int ret = 0;
    int cnt = 0;
    enum task_type_wd type = ASYNC_TASK_WD_ECC;
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

int hpre_sm2_crypto(struct wcrypto_ecc_op_data *opdata, hpre_sm2_priv_ctx *smctx)
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

    opdata->status = smctx->e_hpre_sm2_ctx->opdata.status;
    US_DEBUG("hpre sm2 do async job success!");
    return opdata->status == 0 ? OPENSSL_SUCCESS : OPENSSL_FAIL;

err:
    US_ERR("hpre sm2 do async job err");
    (void)async_clear_async_event_notification_v1();
    async_cleanup_op_done_v1(&op);
    return OPENSSL_FAIL;
}

static int sm2_cipher_bin_to_ber(const EVP_MD *md, struct wcrypto_ecc_point *c1, struct wd_dtb *c2, struct wd_dtb *c3,
    unsigned char *ber, size_t *ber_len)
{
    struct hpre_sm2_ciphertext ctext_struct;
    int ciphertext_leni, ret;
    BIGNUM *x1, *y1;

    x1 = BN_bin2bn((void *)c1->x.data, c1->x.dsize, NULL);
    if (!x1) {
        US_ERR("failed to BN_bin2bn x1.");
        return OPENSSL_FAIL;
    }

    y1 = BN_bin2bn((void *)c1->y.data, c1->y.dsize, NULL);
    if (!y1) {
        US_ERR("failed to BN_bin2bn y1.");
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

    if (!ASN1_OCTET_STRING_set(ctext_struct.C3, (void *)c3->data, c3->dsize) ||
        !ASN1_OCTET_STRING_set(ctext_struct.C2, (void *)c2->data, c2->dsize)) {
        US_ERR("failed to ASN1_OCTET_STRING_set.");
        ret = OPENSSL_FAIL;
        goto free_y1;
    }

    ciphertext_leni = i2d_HPRE_SM2_Ciphertext(&ctext_struct, (unsigned char **)&ber);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        ret = OPENSSL_FAIL;
        goto free_y1;
    }
    *ber_len = (size_t)ciphertext_leni;
    ret = OPENSSL_SUCCESS;
free_y1:
    ASN1_OCTET_STRING_free(ctext_struct.C3);
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    BN_free(y1);
free_x1:
    BN_free(x1);

    return ret;
}

// 之后需要考虑下异常不走软算的场景
int hpre_sm2_encrypt(
    PROV_SM2_ASYM_CTX *psm2ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;
    struct wcrypto_ecc_point *c1 = NULL;
    struct wd_dtb *c2 = NULL;
    struct wd_dtb *c3 = NULL;
    struct wcrypto_ecc_op_data opdata;
    const EVP_MD *md;
    int ret;

    psm2ctx->sm2_pctx->hsmctx->ctx.md = psm2ctx->sm2_pctx->sm2_md->md;  // todo 看是不是能够直接用sm2_md->md

    ret = hpre_sm2_encrypt_check(psm2ctx, out, outlen, in, inlen);
    if (!ret) {
        US_ERR("hpre_sm2_encrypt_check failed ,then switch to soft!\n");
        goto do_soft;
    }

    if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
        ret = OPENSSL_FAIL;
        goto do_soft;
    }

    memset(&opdata, 0, sizeof(opdata));

    ret = hpre_sm2_encrypt_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, (void *)in, inlen);
    if (!ret) {
        US_ERR("sm2_encrypt_init_iot failed , then switch to soft!\n");
        goto do_soft;
    }

    ret = hpre_sm2_update_public_key(psm2ctx->sm2_pctx->hsmctx, psm2ctx->ec_key);
    if (!ret) {
        ret = OPENSSL_FAIL;
        US_ERR("update_public_key failed , then switch to soft!\n");
        goto uninit_iot;
    }

    ret = hpre_sm2_crypto(&opdata, smctx);  // wcrypto_do_sm2函数返回0是表示成功
    if (!ret) {
        ret = OPENSSL_FAIL;
        US_ERR("failed to sm2_crypto in encrypt, ret = %d\n", ret);
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

    US_DEBUG("hpre sm2 encrypt success!");
    ret = OPENSSL_SUCCESS;
uninit_iot:
    hpre_sm2_free_iot(smctx->e_hpre_sm2_ctx, opdata);
    if (ret == OPENSSL_SUCCESS)
        return ret;

do_soft:
    US_WARN("hpre_sm2_encrypt switch to execute openssl software calculation.\n");
    return KAE_CRYPTO_FAIL;
}

static int sm2_cipher_ber_to_bin(
    const EVP_MD *md, unsigned char *ber, size_t ber_len,
    struct wcrypto_ecc_point *c1, struct wd_dtb *c2, struct wd_dtb *c3)
{
    struct hpre_sm2_ciphertext *ctext_struct;
    const unsigned char *end;
    size_t len, len1, c2len, c3len, total;
    int md_size = EVP_MD_get_size(md);

    if (ber_len > LONG_MAX || md_size <= 0)
        return OPENSSL_FAIL;
    end = ber + ber_len;

    ctext_struct = d2i_HPRE_SM2_Ciphertext(NULL, (const unsigned char **)&ber, ber_len);
    if (!ctext_struct) {
        US_ERR("failed to d2i_SM2_Ciphertext.");
        return OPENSSL_FAIL;
    }

    if (ber != end || ctext_struct->C1x == NULL || ctext_struct->C1y == NULL ||
        ctext_struct->C2 == NULL || ctext_struct->C3 == NULL ||
        BN_is_negative(ctext_struct->C1x) || BN_is_negative(ctext_struct->C1y) ||
        ctext_struct->C2->length <= 0 || ctext_struct->C3->length != md_size)
        goto free_ctext;
    len = BN_num_bytes(ctext_struct->C1x);
    len1 = BN_num_bytes(ctext_struct->C1y);
    c2len = ctext_struct->C2->length;
    c3len = ctext_struct->C3->length;
    if (len > SM2_KEY_BYTES || len1 > SM2_KEY_BYTES || len > SIZE_MAX - len1)
        goto free_ctext;
    total = len + len1;
    if (c3len > SIZE_MAX - total || c2len > SIZE_MAX - total - c3len)
        goto free_ctext;
    total += c3len + c2len;
    c1->x.data = malloc(total);
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

    HPRE_SM2_Ciphertext_free(ctext_struct);
    return OPENSSL_SUCCESS;

free_ctext:
    HPRE_SM2_Ciphertext_free(ctext_struct);
    return OPENSSL_FAIL;
}

static int hpre_sm2_decrypt_init_iot(
    void *sess, struct wcrypto_ecc_op_data *opdata, struct wcrypto_ecc_point *c1, struct wd_dtb *c2, struct wd_dtb *c3)
{
    struct wcrypto_ecc_out *ecc_out;
    struct wcrypto_ecc_in *ecc_in;

    ecc_out = wcrypto_new_sm2_dec_out(sess, c2->dsize);
    if (!ecc_out) {
        US_ERR("failed to new dec out.");
        return OPENSSL_FAIL;
    }

    ecc_in = wcrypto_new_sm2_dec_in(sess, c1, c2, c3);
    if (!ecc_in) {
        US_ERR("failed to new dec in.");
        wcrypto_del_ecc_out(sess, ecc_out);
        return OPENSSL_FAIL;
    }

    opdata->op_type = WCRYPTO_SM2_DECRYPT;
    opdata->in = ecc_in;
    opdata->out = ecc_out;

    return OPENSSL_SUCCESS;
}

int hpre_sm2_set_private_key(void *sess, const EC_KEY *eckey)
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
        US_ERR("private key not set.");
        return OPENSSL_FAIL;
    }

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        US_ERR("failed to get ecc group.");
        return OPENSSL_FAIL;
    }

    degree = EC_GROUP_get_degree(group);
    buflen = BITS_TO_BYTES(degree);
    ecc_key = wcrypto_get_ecc_key(sess);
    prikey.data = (void *)bin;
    prikey.dsize = BN_bn2binpad(d, bin, buflen);

    ret = wcrypto_set_ecc_prikey(ecc_key, &prikey);
    if (ret != KAE_SUCCESS) {
        US_ERR("failed to set ecc prikey.");
        ret = OPENSSL_FAIL;
    }  // 是否考虑下其他返回码

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_update_private_key(hpre_sm2_priv_ctx *smctx, EC_KEY *ec_key)
{
    const BIGNUM *d;
    int ret;

    d = EC_KEY_get0_private_key(ec_key);
    if (!d) {
        US_ERR("private key not set.");
        return OPENSSL_FAIL;
    }

    if (smctx->prikey && !BN_cmp(d, smctx->prikey))
        return OPENSSL_SUCCESS;

    ret = hpre_sm2_set_private_key(smctx->e_hpre_sm2_ctx->wd_ctx, ec_key);
    if (!ret)
        return OPENSSL_FAIL;

    smctx->prikey = d;
    return OPENSSL_SUCCESS;
}

static int hpre_sm2_get_plaintext(struct wcrypto_ecc_op_data *opdata, unsigned char *out, size_t *outlen)
{
    struct wd_dtb *ptext = NULL;

    wcrypto_get_sm2_dec_out_params(opdata->out, &ptext);
    if (!ptext) {
        US_ERR("failed to get ptext.");
        return OPENSSL_FAIL;
    }

    if (*outlen < ptext->dsize) {
        US_ERR("invalid: outlen is less than data size.");
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
        US_ERR("invalid sm2 encoding.");
        return OPENSSL_FAIL;
    }

    *pt_size = sm2_ctext->C2->length;
    HPRE_SM2_Ciphertext_free(sm2_ctext);

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_decrypt_check(
    PROV_SM2_ASYM_CTX *psm2ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;
    const EVP_MD *md;
    int hash_size;

    if (!hpre_sm2_smctx_check(psm2ctx->sm2_pctx)) {
        return OPENSSL_FAIL;
    }

    if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
        US_ERR("sm2 ctx init failed.");
        return OPENSSL_FAIL;
    }

    md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;
    hash_size = EVP_MD_size(md);
    if (hash_size <= 0) {
        US_ERR("hash size <= 0.");
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

int hpre_sm2_decrypt(
    PROV_SM2_ASYM_CTX *psm2ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;
    struct wcrypto_ecc_point c1;
    struct wcrypto_ecc_op_data opdata;
    struct wd_dtb c2, c3;
    const EVP_MD *md;
    int ret;

    ret = hpre_sm2_decrypt_check(psm2ctx, out, outlen, in, inlen);
    if (!ret)
        goto do_soft;

    if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
        goto do_soft;
    }

    md = (smctx->ctx.md == NULL) ? EVP_sm3() : smctx->ctx.md;

    ret = sm2_cipher_ber_to_bin(md, (void *)in, inlen, &c1, &c2, &c3);
    if (!ret)
        goto do_soft;

    if (c3.dsize != EVP_MD_size(md)) {
        US_ERR("c3 dsize != hash_size.");
        goto free_c1;
    }

    memset(&opdata, 0, sizeof(opdata));
    ret = hpre_sm2_decrypt_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, &c1, &c2, &c3);
    if (!ret)
        goto free_c1;

    ret = hpre_sm2_update_private_key(psm2ctx->sm2_pctx->hsmctx, psm2ctx->ec_key);
    if (!ret) {
        goto uninit_iot;
    }

    ret = hpre_sm2_crypto(&opdata, smctx);
    if (!ret) {
        US_ERR("failed to sm2_crypto in decrypt.");
        goto uninit_iot;
    }

    ret = hpre_sm2_get_plaintext(&opdata, out, outlen);
    if (!ret)
        goto uninit_iot;

    US_DEBUG("hpre sm2 decrypt success!");
    ret = OPENSSL_SUCCESS;

uninit_iot:
    hpre_sm2_free_iot(smctx->e_hpre_sm2_ctx, opdata);
free_c1:
    free(c1.x.data);
    if (ret == OPENSSL_SUCCESS)  // 得考虑异常情况不走soft，抛异常
        return ret;
do_soft:
    US_WARN("hpre_sm2_decrypt switch to execute openssl software calculation.");
    return KAE_CRYPTO_FAIL;
}

static int hpre_sm2_sign_init_iot(
    void *sess, struct wcrypto_ecc_op_data *opdata, unsigned char *digest, size_t digest_len)
{
    struct wcrypto_ecc_out *ecc_out;
    struct wcrypto_ecc_in *ecc_in;
    struct wd_dtb e = {0};

    ecc_out = wcrypto_new_sm2_sign_out(sess);
    if (!ecc_out) {
        US_ERR("failed to new sign out.");
        return OPENSSL_FAIL;
    }

    e.data = (void *)digest;
    e.dsize = digest_len;
    ecc_in = wcrypto_new_sm2_sign_in(sess, &e, NULL, NULL, 1);
    if (!ecc_in) {
        US_ERR("failed to new sign in.");
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

static int hpre_sm2_sign_check(
    PROV_SM2_SIGN_CTX *psm2ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    // struct hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;
    EC_KEY *ec_key = psm2ctx->ec_key;

    const int sig_sz = ECDSA_size(ec_key);

    /*
     * If 'sig' is NULL, users can use sm2_decrypt API to obtain the valid 'siglen' first,
     * then users use the value of 'signlen' to alloc the memory of 'sig' and call the
     * sm2_decrypt API a second time to do the decryption task.
     */
    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return OPENSSL_SUCCESS;
    }

    if (!hpre_sm2_smctx_check(psm2ctx->sm2_pctx)) {
        return OPENSSL_FAIL;
    }

    if (sig_sz <= 0) {
        US_ERR("sig_sz error\n");
        return OPENSSL_FAIL;
    }

    if (*siglen < (size_t)sig_sz) {
        US_ERR("invalide: siglen < sig_sz.");
        return OPENSSL_FAIL;
    }

    if (tbslen > SM2_KEY_BYTES)
        return OPENSSL_FAIL;

    if (data_all_zero(tbs, tbslen))
        return OPENSSL_FAIL;

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_sign_bin_to_ber(EC_KEY *ec, struct wd_dtb *r, struct wd_dtb *s, unsigned char *sig, size_t *siglen)
{
    int ret = OPENSSL_FAIL;
    ECDSA_SIG *e_sig;
    BIGNUM *br, *bs;
    int sltmp;

    e_sig = ECDSA_SIG_new();
    if (!e_sig) {
        US_ERR("failed to ECDSA_SIG_new.");
        return OPENSSL_FAIL;
    }

    br = BN_bin2bn((void *)r->data, r->dsize, NULL);
    if (!br) {
        US_ERR("failed to BN_bin2bn r.");
        goto free_sig;
    }

    bs = BN_bin2bn((void *)s->data, s->dsize, NULL);
    if (!bs) {
        US_ERR("failed to BN_bin2bn s.");
        goto free_r;
    }

    ret = ECDSA_SIG_set0(e_sig, br, bs);
    if (!ret) {
        US_ERR("failed to ECDSA_SIG_set0.");
        goto free_s;
    }

    sltmp = i2d_ECDSA_SIG(e_sig, &sig);
    if (sltmp < 0) {
        US_ERR("failed to i2d_ECDSA_SIG.");
        goto free_s;
    }
    *siglen = (size_t)sltmp;
    ECDSA_SIG_free(e_sig);
    return OPENSSL_SUCCESS;

free_s:
    BN_free(bs);
free_r:
    BN_free(br);
free_sig:
    ECDSA_SIG_free(e_sig);

    return OPENSSL_FAIL;
}

int hpre_sm2_sign(
    PROV_SM2_SIGN_CTX *psm2ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;
    struct wd_dtb *r = NULL;
    struct wd_dtb *s = NULL;
    struct wcrypto_ecc_op_data opdata;
    int ret;

    ret = hpre_sm2_sign_check(psm2ctx, sig, siglen, tbs, tbslen);
    if (!ret)
        goto do_soft;

    if (smctx->init_status != HPRE_SM2_INIT_SUCC) {
        goto do_soft;
    }

    memset(&opdata, 0, sizeof(opdata));
    ret = hpre_sm2_sign_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, (void *)tbs, tbslen);
    if (!ret)
        goto do_soft;

    ret = hpre_sm2_update_private_key(psm2ctx->sm2_pctx->hsmctx, psm2ctx->ec_key);
    if (!ret) {
        goto uninit_iot;
    }

    ret = hpre_sm2_crypto(&opdata, smctx);
    if (!ret) {
        US_ERR("failed to sm2_crypto in sign.");
        goto uninit_iot;
    }

    wcrypto_get_sm2_sign_out_params(opdata.out, &r, &s);
    if (!r || !s) {
        goto uninit_iot;
    }

    ret = hpre_sm2_sign_bin_to_ber(NULL, r, s, sig, siglen);
    if (!ret)
        goto uninit_iot;

    US_DEBUG("hpre sm2 sign success!");
    ret = OPENSSL_SUCCESS;

uninit_iot:
    hpre_sm2_free_iot(smctx->e_hpre_sm2_ctx, opdata);

    if (ret == OPENSSL_SUCCESS) {
        US_DEBUG("sm2_sign successed!\n");
        return OPENSSL_SUCCESS;
    }
do_soft:
    US_WARN("sm2_sign failed, switch to execute openssl software calculation.\n");
    return KAE_CRYPTO_FAIL;
}

static int hpre_sm2_verify_check(
    PROV_SM2_SIGN_CTX *psm2ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    // struct hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;

    if (!hpre_sm2_smctx_check(psm2ctx->sm2_pctx)) {
        return OPENSSL_FAIL;
    }

    if (tbslen > SM2_KEY_BYTES)
        return OPENSSL_FAIL;

    if (data_all_zero(tbs, tbslen))
        return OPENSSL_FAIL;

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_verify_init_iot(
    void *sess, struct wcrypto_ecc_op_data *opdata, struct wd_dtb *e, struct wd_dtb *r, struct wd_dtb *s)
{
    struct wcrypto_ecc_in *ecc_in;

    ecc_in = wcrypto_new_sm2_verf_in(sess, e, r, s, NULL, 1);
    if (!ecc_in) {
        US_ERR("failed to new verf in.");
        return OPENSSL_FAIL;
    }

    opdata->op_type = WCRYPTO_SM2_VERIFY;
    opdata->in = ecc_in;

    return OPENSSL_SUCCESS;
}

static int hpre_sm2_sig_ber_to_bin(EC_KEY *ec, unsigned char *sig, size_t sig_len, struct wd_dtb *r, struct wd_dtb *s)
{
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    ECDSA_SIG *e_sig = NULL;
    int ret, len1, len2;
    BIGNUM *b_r, *b_s;

    if (sig_len > LONG_MAX)
        return OPENSSL_FAIL;

    e_sig = ECDSA_SIG_new();
    if (!e_sig) {
        US_ERR("failed to ECDSA_SIG_new.");
        return OPENSSL_FAIL;
    }

    if (d2i_ECDSA_SIG(&e_sig, &p, sig_len) == NULL) {
        US_ERR("d2i_ECDSA_SIG error.");
        ret = OPENSSL_FAIL;
        goto free_sig;
    }

    /* Ensure signature uses DER and doesn't have trailing garbage */
    len1 = i2d_ECDSA_SIG(e_sig, &der);
    if (len1 <= 0 || (size_t)len1 != sig_len || der == NULL || memcmp(sig, der, len1) != 0) {
        US_ERR("sig data error, len1 != sig_len.");
        ret = OPENSSL_FAIL;
        goto free_der;
    }

    b_r = (void *)ECDSA_SIG_get0_r((const ECDSA_SIG *)e_sig);
    if (!b_r) {
        US_ERR("failed to get r.");
        ret = OPENSSL_FAIL;
        goto free_der;
    }

    b_s = (void *)ECDSA_SIG_get0_s((const ECDSA_SIG *)e_sig);
    if (!b_s) {
        US_ERR("failed to get s.");
        ret = OPENSSL_FAIL;
        goto free_der;
    }

    if (BN_is_negative(b_r) || BN_is_negative(b_s) || BN_is_zero(b_r) || BN_is_zero(b_s)) {
        ret = OPENSSL_FAIL;
        goto free_der;
    }

    len1 = BN_num_bytes(b_r);
    len2 = BN_num_bytes(b_s);
    if (len1 > SM2_MAX_KEY_BYTES || len2 > SM2_MAX_KEY_BYTES) {
        US_ERR("r or s bytes error.");
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

int hpre_sm2_verify(
    PROV_SM2_SIGN_CTX *psm2ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    hpre_sm2_priv_ctx *smctx = psm2ctx->sm2_pctx->hsmctx;
    unsigned char buf_r[SM2_MAX_KEY_BYTES] = {0};
    unsigned char buf_s[SM2_MAX_KEY_BYTES] = {0};
    EC_KEY *ec_key = psm2ctx->ec_key;
    struct wd_dtb e = {0};
    struct wd_dtb r = {0};
    struct wd_dtb s = {0};
    struct wcrypto_ecc_op_data opdata;
    int ret;

    ret = hpre_sm2_verify_check(psm2ctx, sig, siglen, tbs, tbslen);
    if (!ret) {
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
    ret = hpre_sm2_sig_ber_to_bin(ec_key, (void *)sig, siglen, &r, &s);
    if (!ret)
        return OPENSSL_FAIL;

    e.data = (void *)tbs;
    e.dsize = tbslen;
    memset(&opdata, 0, sizeof(opdata));
    ret = hpre_sm2_verify_init_iot(smctx->e_hpre_sm2_ctx->wd_ctx, &opdata, &e, &r, &s);
    if (!ret)
        goto do_soft;

    ret = hpre_sm2_update_public_key(psm2ctx->sm2_pctx->hsmctx, psm2ctx->ec_key);
    if (!ret) {
        ret = OPENSSL_FAIL;
        US_ERR("sm2_verify_check failed,switch to soft.\n");
        goto uninit_iot;
    }

    ret = hpre_sm2_crypto(&opdata, smctx);
    if (!ret) {
        ret = OPENSSL_FAIL;
        US_ERR("uadk_ecc_crypto failed,switch to soft.\n");
        goto uninit_iot;
    }

    US_DEBUG("hpre sm2 verify success!");
    ret = OPENSSL_SUCCESS;

uninit_iot:
    hpre_sm2_free_iot(smctx->e_hpre_sm2_ctx, opdata);
    if (ret == OPENSSL_SUCCESS) {
        US_DEBUG("sm2_verify successed!\n");
        return OPENSSL_SUCCESS;
    }

do_soft:
    US_WARN("sm2_verify failed,switch to execute openssl software calculation.\n");
    return KAE_CRYPTO_FAIL;
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
    kae_queue_pool_destroy(g_hpre_sm2_qnode_pool, free);
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

int hpre_module_sm2_init(void)
{

    /* init queue */
    if (wd_sm2_init_qnode_pool() != KAE_SUCCESS)
        return OPENSSL_FAIL;

    /* register async poll func */
    async_register_poll_fn_v1(ASYNC_TASK_WD_ECC, sm2_engine_ctx_poll);  // ASYNC_TASK_WD_ECC 按SVA代码包含sm2

    return OPENSSL_SUCCESS;
}
