/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:    This file provides the implemenation for KAE engine rsa
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

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "hpre_rsa.h"
#include "hpre_wd.h"
#include "hpre_rsa_soft.h"
#include "async_poll.h"
#include "engine_types.h"
#include "engine_kae.h"
#include "hpre_rsa_utils.h"

#ifndef OPENSSL_NO_RSA
const int RSAPKEYMETH_IDX = 0;
#else
const int RSAPKEYMETH_IDX = -1;
#endif

const char *g_hpre_device = "hisi_hpre";
static RSA_METHOD *g_hpre_rsa_method = NULL;
static RSA_METHOD *g_soft_rsa_method = NULL;
static EVP_PKEY_METHOD *g_hpre_pkey_meth = NULL;

static int hpre_rsa_public_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int hpre_rsa_private_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int hpre_rsa_public_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int hpre_rsa_private_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int hpre_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

static int hpre_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);

static int hpre_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

RSA_METHOD *hpre_get_rsa_methods(void)
{
    int ret = 1;
    if (g_hpre_rsa_method != NULL) {
        return g_hpre_rsa_method;
    }
    if (g_soft_rsa_method != NULL) {
        return g_soft_rsa_method;
    }
    if (!kae_get_device(g_hpre_device)) {
        const RSA_METHOD *default_soft_method = RSA_PKCS1_OpenSSL();
        g_soft_rsa_method = RSA_meth_new("SOFT RSA METHOD", 0);
        ret &= RSA_meth_set_pub_enc(g_soft_rsa_method, RSA_meth_get_pub_enc(default_soft_method));
        ret &= RSA_meth_set_priv_enc(g_soft_rsa_method, RSA_meth_get_priv_enc(default_soft_method));
        ret &= RSA_meth_set_pub_dec(g_soft_rsa_method, RSA_meth_get_pub_dec(default_soft_method));
        ret &= RSA_meth_set_priv_dec(g_soft_rsa_method, RSA_meth_get_priv_dec(default_soft_method));
        ret &= RSA_meth_set_keygen(g_soft_rsa_method, hpre_rsa_soft_genkey);
        ret &= RSA_meth_set_mod_exp(g_soft_rsa_method, RSA_meth_get_mod_exp(default_soft_method));
        ret &= RSA_meth_set_bn_mod_exp(g_soft_rsa_method, RSA_meth_get_bn_mod_exp(default_soft_method));
        if (ret == 0) {
            US_ERR("Failed to set SOFT RSA methods");
            return NULL;
        }
        return g_soft_rsa_method;
    }

    g_hpre_rsa_method = RSA_meth_new("HPRE RSA method", 0);
    if (g_hpre_rsa_method == NULL) {
        KAEerr(KAE_F_HPRE_GET_RSA_METHODS, KAE_R_MALLOC_FAILURE);
        US_ERR("Failed to allocate HPRE RSA methods");
        return NULL;
    }

    ret &= RSA_meth_set_pub_enc(g_hpre_rsa_method, hpre_rsa_public_encrypt);
    ret &= RSA_meth_set_pub_dec(g_hpre_rsa_method, hpre_rsa_public_decrypt);
    ret &= RSA_meth_set_priv_enc(g_hpre_rsa_method, hpre_rsa_private_encrypt);
    ret &= RSA_meth_set_priv_dec(g_hpre_rsa_method, hpre_rsa_private_decrypt);
    ret &= RSA_meth_set_keygen(g_hpre_rsa_method, hpre_rsa_keygen);
    ret &= RSA_meth_set_mod_exp(g_hpre_rsa_method, hpre_rsa_mod_exp);
    ret &= RSA_meth_set_bn_mod_exp(g_hpre_rsa_method, hpre_bn_mod_exp);
    if (ret == 0) {
        KAEerr(KAE_F_HPRE_GET_RSA_METHODS, KAE_R_RSA_SET_METHODS_FAILURE);
        US_ERR("Failed to set HPRE RSA methods");
        return NULL;
    }

    return g_hpre_rsa_method;
}

static void hpre_free_rsa_methods(void)
{
    if (g_hpre_rsa_method != NULL) {
        RSA_meth_free(g_hpre_rsa_method);
        g_hpre_rsa_method = NULL;
    }
    if (g_soft_rsa_method != NULL) {
        RSA_meth_free(g_soft_rsa_method);
        g_soft_rsa_method = NULL;
    }
}


int hpre_engine_ctx_poll(void* engine_ctx)
{
    int ret;
    hpre_engine_ctx_t *eng_ctx = (hpre_engine_ctx_t *)engine_ctx;
    struct wd_queue *q = eng_ctx->qlist->kae_wd_queue;
poll_again:
    ret = wcrypto_rsa_poll(q, 1);
    if (!ret) {
        goto poll_again;
    } else if (ret < 0) {
        US_ERR("rsa poll fail!\n");
        return ret;
    }
    return ret;
}

int hpre_module_init()
{
    /* init queue */
    wd_hpre_init_qnode_pool();
    
    (void)get_rsa_pkey_meth();
    (void)hpre_get_rsa_methods();

    /* register async poll func */
    async_register_poll_fn(ASYNC_TASK_RSA, hpre_engine_ctx_poll);

    return 1;
}

EVP_PKEY_METHOD *get_rsa_pkey_meth(void)
{
    const EVP_PKEY_METHOD *def_rsa = EVP_PKEY_meth_get0(RSAPKEYMETH_IDX);
    if (g_hpre_pkey_meth == NULL) {
        g_hpre_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
        if (g_hpre_pkey_meth == NULL) {
            US_ERR("failed to new pkey meth");
            return NULL;
        }

        EVP_PKEY_meth_copy(g_hpre_pkey_meth, def_rsa);
    }

    return g_hpre_pkey_meth;
}

void hpre_destroy()
{
    hpre_free_rsa_methods();
}

//lint -save -e506
#undef GOTOEND_IF
#define GOTOEND_IF(cond, mesg, f, r) \
        if (cond) { \
            KAEerr(f, r); \
            US_ERR(mesg); \
            ret = HPRE_CRYPTO_FAIL; \
            rsa_soft_mark = 1; \
            goto end;\
        } \


static int hpre_rsa_check(const int flen, const BIGNUM *n, const BIGNUM *e,
                          int *num_bytes, RSA *rsa)
{
    int key_bits;
    if (n == NULL || e == NULL) {
        return HPRE_CRYPTO_FAIL;
    }

    if (check_pubkey_param(n, e) != HPRE_CRYPTO_SUCC) {
        return HPRE_CRYPTO_FAIL;
    }

    *num_bytes = BN_num_bytes(n);
    if (flen > *num_bytes) {
        KAEerr(KAE_F_HPRE_RSA_PUBDEC, KAE_R_DATA_GREATER_THEN_MOD_LEN);
        US_WARN("data length is large than num bytes of rsa->n");
        return HPRE_CRYPTO_FAIL;
    }

    key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return HPRE_CRYPTO_FAIL;
    }

    return HPRE_CRYPTO_SUCC;
}

static int hpre_rsa_prepare_opdata(const BIGNUM *n, int flen,
                                   const unsigned char *from,
                                   BN_CTX **bn_ctx,
                                   BIGNUM **bn_ret, BIGNUM **f_ret)
{
    BN_CTX *bn_ctx_tmp;
    BIGNUM *bn_ret_tmp = NULL;
    BIGNUM *f = NULL;
    bn_ctx_tmp = BN_CTX_new();
    if (bn_ctx_tmp == NULL) {
        KAEerr(KAE_F_HPRE_RSA_PUBDEC, KAE_R_MALLOC_FAILURE);
        US_ERR("fail to new BN_CTX.");
        return HPRE_CRYPTO_SOFT;
    }

    BN_CTX_start(bn_ctx_tmp);
    bn_ret_tmp = BN_CTX_get(bn_ctx_tmp);
    f = BN_CTX_get(bn_ctx_tmp);
    if (bn_ret_tmp == NULL || f == NULL) {
        KAEerr(KAE_F_HPRE_RSA_PUBDEC, KAE_R_MALLOC_FAILURE);
        US_ERR("fail to get BN_CTX.");
        return HPRE_CRYPTO_SOFT;
    }

    if (BN_bin2bn(from, flen, f) == NULL) {
        KAEerr(KAE_F_HPRE_RSA_PUBDEC, KAE_R_ERR_LIB_BN);
        US_ERR("fail to bin2bn");
        return HPRE_CRYPTO_SOFT;
    }

    if (BN_ucmp(f, n) >= 0) {
        KAEerr(KAE_F_HPRE_RSA_PUBDEC, KAE_R_DATA_TOO_LARGE_FOR_MODULUS);
        US_ERR("data is too large");
        return HPRE_CRYPTO_SOFT;
    }
    *bn_ctx = bn_ctx_tmp;
    *bn_ret = bn_ret_tmp;
    *f_ret = f;
    return HPRE_CRYPTO_SUCC;
}


static int hpre_rsa_public_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding)
{
    int rsa_soft_mark = 0;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    BIGNUM *ret_bn  = NULL;
    hpre_engine_ctx_t *eng_ctx = NULL;
    unsigned char *in_buf = NULL;
    BN_CTX *bn_ctx = NULL;
    int num_bytes = 0;

    if (hpre_rsa_check_para(flen, from, to, rsa) != HPRE_CRYPTO_SUCC) {
        return HPRE_CRYPTO_FAIL;
    }
    int key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return hpre_rsa_soft_calc(flen, from, to, rsa, padding, PUB_ENC);
    }

    eng_ctx = hpre_get_eng_ctx(rsa, 0);
    if (eng_ctx == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        rsa_soft_mark = 1;
        goto end_soft;
    }

    RSA_get0_key(rsa, &n, &e, &d);
    int ret = check_pubkey_param(n, e);
    GOTOEND_IF(ret != HPRE_CRYPTO_SUCC, "check public key fail",
        KAE_F_HPRE_RSA_PUBENC, KAE_R_PUBLIC_KEY_INVALID);

    bn_ctx = BN_CTX_new();
    GOTOEND_IF(bn_ctx == NULL, "bn_ctx MALLOC FAILED!",
        KAE_F_HPRE_RSA_PUBENC, KAE_R_MALLOC_FAILURE);

    BN_CTX_start(bn_ctx);
    ret_bn = BN_CTX_get(bn_ctx);
    num_bytes = BN_num_bytes(n);
    in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);
    GOTOEND_IF(ret_bn == NULL || in_buf == NULL, "PUBLIC_ENCRYPT RSA MALLOC FAILED!",
        KAE_F_HPRE_RSA_PUBENC, KAE_R_MALLOC_FAILURE);

    ret = hpre_rsa_padding(flen, from, in_buf, num_bytes, padding, PUB_ENC);
    GOTOEND_IF(ret == HPRE_CRYPTO_FAIL, "RSA PADDING FAILED",
        KAE_F_HPRE_RSA_PUBENC, KAE_R_RSA_PADDING_FAILURE);

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_VERIFY;
    eng_ctx->opdata.in = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, in_buf, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    GOTOEND_IF(HPRE_CRYPTO_FAIL == ret, "hpre rsa pub encrypt failed!",
        KAE_F_HPRE_RSA_PUBENC, KAE_R_PUBLIC_ENCRYPTO_FAILURE);

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, ret_bn);
    ret = BN_bn2binpad(ret_bn, to, num_bytes);

    US_DEBUG("hpre rsa public encrypt success!");

end:
    hpre_free_bn_ctx_buf(bn_ctx, in_buf, num_bytes);
    hpre_free_eng_ctx(eng_ctx);

end_soft:
    if (rsa_soft_mark == 1) {
        ret = hpre_rsa_soft_calc(flen, from, to, rsa, padding, PUB_ENC);
    }

    return ret;
}


static int hpre_rsa_private_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding)
{
    int ret = HPRE_CRYPTO_FAIL;
    int rsa_soft_mark = 0;
    hpre_engine_ctx_t *eng_ctx = NULL;
    BIGNUM *f = (BIGNUM *)NULL;
    BIGNUM *bn_ret = (BIGNUM *)NULL;
    BIGNUM *res = (BIGNUM *)NULL;
    const BIGNUM *n = (const BIGNUM *)NULL;
    const BIGNUM *e = (const BIGNUM *)NULL;
    const BIGNUM *d = (const BIGNUM *)NULL;
    const BIGNUM *p = (const BIGNUM *)NULL;
    const BIGNUM *q = (const BIGNUM *)NULL;
    const BIGNUM *dmp1 = (const BIGNUM *)NULL;
    const BIGNUM *dmq1 = (const BIGNUM *)NULL;
    const BIGNUM *iqmp = (const BIGNUM *)NULL;
    unsigned char *in_buf = (unsigned char *)NULL;
    BN_CTX *bn_ctx = NULL;
    int num_bytes = 0;

    if (hpre_rsa_check_para(flen, from, to, rsa) != HPRE_CRYPTO_SUCC) {
        return HPRE_CRYPTO_FAIL;
    }

    int key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return hpre_rsa_soft_calc(flen, from, to, rsa, padding, PRI_ENC);
    }

    eng_ctx = hpre_get_eng_ctx(rsa, 0);
    if (eng_ctx == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        rsa_soft_mark = 1;
        goto end_soft;
    }

    bn_ctx = BN_CTX_new();
    GOTOEND_IF(bn_ctx == NULL, "PRI_ENC MALLOC_FAILURE ",
        KAE_F_HPRE_RSA_PRIENC, KAE_R_MALLOC_FAILURE);

    BN_CTX_start(bn_ctx);
    f = BN_CTX_get(bn_ctx);
    bn_ret = BN_CTX_get(bn_ctx);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    int version = RSA_get_version(rsa);
    RSA_get0_key(rsa, &n, &e, &d);
    num_bytes = BN_num_bytes(n);
    in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);
    GOTOEND_IF(bn_ret == NULL || in_buf == NULL, "OpenSSL malloc failure",
        KAE_F_HPRE_RSA_PRIENC, KAE_R_MALLOC_FAILURE);

    ret = hpre_rsa_padding(flen, from, in_buf, num_bytes, padding, PRI_ENC);
    GOTOEND_IF(ret == HPRE_CRYPTO_FAIL, "RSA PADDING FAILED!",
        KAE_F_HPRE_RSA_PRIENC, KAE_R_RSA_PADDING_FAILURE);

    GOTOEND_IF(NULL == BN_bin2bn(in_buf, num_bytes, f), "BN_bin2bn failure",
        KAE_F_HPRE_RSA_PRIENC, KAE_R_ERR_LIB_BN);

    ret = BN_ucmp(f, n);
    GOTOEND_IF(ret >= 0, "RSA PADDING FAILED!",
        KAE_F_HPRE_RSA_PRIENC, KAE_R_DATA_TOO_LARGE_FOR_MODULUS);

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    hpre_rsa_fill_prikey(rsa, eng_ctx, version, p, q, dmp1, dmq1, iqmp);

    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_SIGN;
    eng_ctx->opdata.in = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, in_buf, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    if (ret == HPRE_CRYPTO_FAIL) {
        US_WARN("hpre rsa priv encrypt failed!");
        rsa_soft_mark = 1;
        goto end;
    }

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, bn_ret);

    if (hpre_get_prienc_res(padding, f, n, bn_ret, &res) == HPRE_CRYPTO_FAIL) {
        goto end;
    }

    ret = BN_bn2binpad(res, to, num_bytes);

    US_DEBUG("hpre rsa priv encrypt success!");

    end:
    hpre_free_bn_ctx_buf(bn_ctx, in_buf, num_bytes);
    hpre_free_eng_ctx(eng_ctx);

    end_soft:
    if (rsa_soft_mark == 1) {
        ret = hpre_rsa_soft_calc(flen, from, to, rsa, padding, PRI_ENC);
    }

    return ret;
}

static int hpre_rsa_public_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding)
{
    hpre_engine_ctx_t *eng_ctx = NULL;
    BIGNUM *bn_ret = NULL;
    BIGNUM *f = NULL;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;

    int num_bytes = 0;
    int rsa_soft_mark = 0;
    unsigned char *buf = NULL;

    if (hpre_rsa_check_para(flen, from, to, rsa) != HPRE_CRYPTO_SUCC) {
        return HPRE_CRYPTO_FAIL;
    }

    RSA_get0_key(rsa, &n, &e, &d);
    int ret = hpre_rsa_check(flen, n, e, &num_bytes, rsa);
    if (ret == HPRE_CRYPTO_FAIL) {
        rsa_soft_mark = 1;
        goto end_soft;
    }

    eng_ctx = hpre_get_eng_ctx(rsa, 0);
    if (eng_ctx == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        rsa_soft_mark = 1;
        goto end_soft;
    }

    buf = (unsigned char *)OPENSSL_malloc(num_bytes);
    if (buf == NULL) {
        rsa_soft_mark = 1;
        goto end;
    }

    ret = hpre_rsa_prepare_opdata(n, flen, from, &bn_ctx, &bn_ret, &f);
    if (ret == HPRE_CRYPTO_SOFT) {
        rsa_soft_mark = 1;
        goto end;
    }

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_VERIFY;
    eng_ctx->opdata.in = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, from, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    GOTOEND_IF(HPRE_CRYPTO_FAIL == ret, "hpre rsa pub decrypt failed!",
        KAE_F_HPRE_RSA_PUBDEC, KAE_R_PUBLIC_DECRYPTO_FAILURE);

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, bn_ret);
    if ((padding == RSA_X931_PADDING) && ((bn_get_words(bn_ret)[0] & 0xf) != 12)) { // not 12 then BN_sub
        GOTOEND_IF(!BN_sub(bn_ret, n, bn_ret), "BN_sub failed",
            KAE_F_HPRE_RSA_PUBDEC, KAE_R_ERR_LIB_BN);
    }
    int len = BN_bn2binpad(bn_ret, buf, num_bytes);
    ret = check_rsa_padding(to, num_bytes, buf, len, padding, PUB_DEC);
    if (ret == HPRE_CRYPTO_FAIL) {
        US_WARN("hpre rsa check padding failed.switch to soft");
        rsa_soft_mark = 1;
        goto end;
    }
    
    US_DEBUG("hpre rsa public decrypt success!");

end:
    hpre_free_bn_ctx_buf(bn_ctx, buf, num_bytes);
    hpre_free_eng_ctx(eng_ctx);

end_soft:
    if (rsa_soft_mark == 1) {
        ret = hpre_rsa_soft_calc(flen, from, to, rsa, padding, PUB_DEC);
    }

    return ret;
}

static int hpre_rsa_private_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding)
{
    int ret = HPRE_CRYPTO_FAIL;
    const BIGNUM *n = (const BIGNUM *)NULL;
    const BIGNUM *e = (const BIGNUM *)NULL;
    const BIGNUM *d = (const BIGNUM *)NULL;
    const BIGNUM *p = (const BIGNUM *)NULL;
    const BIGNUM *q = (const BIGNUM *)NULL;
    const BIGNUM *dmp1 = (const BIGNUM *)NULL;
    const BIGNUM *dmq1 = (const BIGNUM *)NULL;
    const BIGNUM *iqmp = (const BIGNUM *)NULL;
    BIGNUM *f = (BIGNUM *)NULL;
    BIGNUM *bn_ret = (BIGNUM *)NULL;
    int len;
    int rsa_soft_mark = 0;
    unsigned char *buf = (unsigned char *)NULL;
    BN_CTX *bn_ctx = NULL;

    if (hpre_rsa_check_para(flen, from, to, rsa) != HPRE_CRYPTO_SUCC) {
        return HPRE_CRYPTO_FAIL;
    }

    RSA_get0_key(rsa, &n, &e, &d);
    int num_bytes = BN_num_bytes(n);
    if (flen > num_bytes) {
        KAEerr(KAE_F_HPRE_RSA_PRIDEC, KAE_R_DATA_GREATER_THEN_MOD_LEN);
        US_ERR("PRIVATE_DECRYPT DATA_GREATER_THAN_MOD_LEN");
        return HPRE_CRYPTO_FAIL;
    }

    int key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return hpre_rsa_soft_calc(flen, from, to, rsa, padding, PRI_DEC);
    }

    hpre_engine_ctx_t *eng_ctx = hpre_get_eng_ctx(rsa, 0);
    if (eng_ctx == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        rsa_soft_mark = 1;
        goto end_soft;
    }

    bn_ctx = BN_CTX_new();
    GOTOEND_IF(bn_ctx == NULL, "bn_ctx MALLOC FAILED!",
        KAE_F_HPRE_RSA_PRIDEC, KAE_R_ERR_LIB_BN);

    BN_CTX_start(bn_ctx);
    f = BN_CTX_get(bn_ctx);
    bn_ret = BN_CTX_get(bn_ctx);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    int version = RSA_get_version(rsa);
    buf = (unsigned char *)OPENSSL_malloc(num_bytes);
    GOTOEND_IF(bn_ret == NULL || buf == NULL, "PRIVATE_DECRYPT ERR_R_MALLOC_FAILURE",
        KAE_F_HPRE_RSA_PRIDEC,  KAE_R_MALLOC_FAILURE);

    GOTOEND_IF(BN_bin2bn(from, (int) flen, f) == NULL, "BN_bin2bn failure",
        KAE_F_HPRE_RSA_PRIDEC, KAE_R_ERR_LIB_BN);

    GOTOEND_IF(BN_ucmp(f, n) >= 0, "PRIVATE_DECRYPT, RSA_R_DATA_TOO_LARGE_FOR_MODULUS",
        KAE_F_HPRE_RSA_PRIDEC, KAE_R_DATA_TOO_LARGE_FOR_MODULUS);

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    hpre_rsa_fill_prikey(rsa, eng_ctx, version, p, q, dmp1, dmq1, iqmp);

    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_SIGN;
    eng_ctx->opdata.in = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out = eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool,
        eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, from, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    if (ret == HPRE_CRYPTO_FAIL) {
        US_WARN("hpre rsa priv decrypt failed.switch to soft");
        rsa_soft_mark = 1;
        goto end;
    }

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, bn_ret);
    len = BN_bn2binpad(bn_ret, buf, num_bytes);
    ret = check_rsa_padding(to, num_bytes, buf, len, padding, PRI_DEC);
    if (ret == HPRE_CRYPTO_FAIL) {
        US_WARN("hpre rsa check padding failed.switch to soft");
        rsa_soft_mark = 1;
        goto end;
    }

    US_DEBUG("hpre rsa priv decrypt success!");

end:
    hpre_free_bn_ctx_buf(bn_ctx, buf, num_bytes);
    hpre_free_eng_ctx(eng_ctx);

end_soft:
    if (rsa_soft_mark == 1) {
        ret = hpre_rsa_soft_calc(flen, from, to, rsa, padding, PRI_DEC);
    }
    return ret;
}

static int hpre_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    int ret = HPRE_CRYPTO_FAIL;
    int rsa_soft_mark = 0;
    struct wcrypto_rsa_pubkey *pubkey = NULL;
    struct wcrypto_rsa_prikey *prikey = NULL;
    struct wd_dtb *wd_e = NULL;
    struct wd_dtb *wd_p = NULL;
    struct wd_dtb *wd_q = NULL;

    if (bits < RSA_MIN_MODULUS_BITS) {
        KAEerr(KAE_F_HPRE_RSA_KEYGEN, KAE_R_RSA_KEY_SIZE_TOO_SMALL);
        US_ERR("RSA_BUILTIN_KEYGEN RSA_R_KEY_SIZE_TOO_SMALL");
        return HPRE_CRYPTO_FAIL;
    }

    if (!check_bit_useful(bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return hpre_rsa_soft_genkey(rsa, bits, e, cb);
    }

    hpre_engine_ctx_t *eng_ctx = hpre_get_eng_ctx(rsa, bits);
    if (eng_ctx == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        rsa_soft_mark = 1;
        goto end_soft;
    }

    BIGNUM *e_value = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    GOTOEND_IF(e_value == NULL || p == NULL || q == NULL, "e_value or p or q MALLOC FAILED.",
        KAE_F_HPRE_RSA_KEYGEN, KAE_R_ERR_LIB_BN);

    GOTOEND_IF(hpre_rsa_primegen(bits, e, p, q, cb) == OPENSSL_FAIL, "hisi_rsa_primegen failed",
        KAE_F_HPRE_RSA_KEYGEN, KAE_R_GET_PRIMEKEY_FAILURE);

    GOTOEND_IF(BN_copy(e_value, e) == NULL, "copy e failed",
        KAE_F_HPRE_RSA_KEYGEN, KAE_R_ERR_LIB_BN);

    wcrypto_get_rsa_pubkey(eng_ctx->ctx, &pubkey);
    wcrypto_get_rsa_pubkey_params(pubkey, &wd_e, NULL);
    wd_e->dsize = BN_bn2bin(e_value, (unsigned char *)wd_e->data);
    wcrypto_get_rsa_prikey(eng_ctx->ctx, &prikey);
    wcrypto_get_rsa_crt_prikey_params(prikey, NULL, NULL, NULL, &wd_q, &wd_p);
    wd_q->dsize = BN_bn2bin(q, (unsigned char *)wd_q->data);
    wd_p->dsize = BN_bn2bin(p, (unsigned char *)wd_p->data);

    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_GENKEY;
    ret = hpre_fill_keygen_opdata(eng_ctx->ctx, &eng_ctx->opdata);
    if (ret != KAE_SUCCESS) {
        US_WARN("hpre_fill_keygen_opdata failed");
        rsa_soft_mark = 1;
        goto end;
    }
    ret = hpre_rsa_sync(eng_ctx->ctx, &eng_ctx->opdata);
    if (ret == HPRE_CRYPTO_FAIL) {
        US_WARN("hpre generate rsa key failed.switch to soft");
        rsa_soft_mark = 1;
        goto end;
    }
    ret = hpre_rsa_get_keygen_param(&eng_ctx->opdata, eng_ctx->ctx, rsa,
                                    e_value, p, q);

    US_DEBUG("hpre rsa keygen success!");

end:
    hpre_free_eng_ctx(eng_ctx);

end_soft:
    if (rsa_soft_mark == 1) {
        ret = hpre_rsa_soft_genkey(rsa, bits, e, cb);
    }
    return ret;
}

static int hpre_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    US_DEBUG("- Started\n");
    return RSA_meth_get_mod_exp(RSA_PKCS1_OpenSSL())
                                (r0, I, rsa, ctx);
}

static int hpre_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    US_DEBUG("- Started\n");
    return RSA_meth_get_bn_mod_exp(RSA_PKCS1_OpenSSL())
                                    (r, a, p, m, ctx, m_ctx);
}

