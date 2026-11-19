/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:    This file provides the implementation for KAE engine rsa
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
#include "hpre_rsa_utils.h"
#include "hpre_rsa_wd.h"
#include "hpre_dh.h"
#include "hpre_sm2.h"
#include "../../async/async_poll.h"
#include "../../../common/kae_types.h"
#include "../../../common/kae_log.h"

#ifndef OPENSSL_NO_RSA
const int RSAPKEYMETH_IDX;
#else
const int RSAPKEYMETH_IDX = -1;
#endif

// lint -save -e506
#undef GOTOEND_IF
#define GOTOEND_IF(cond, mesg, f, r) \
    do {                             \
        if (cond) {                  \
            KAEerr(f, r);            \
            US_ERR(mesg);            \
            ret = OPENSSL_FAIL;      \
            goto end;                \
        }                            \
    } while (0)

int hpre_rsa_ctx_poll(void *engine_ctx)
{
    int ret;
    hpre_rsa_ctx_t *eng_ctx = (hpre_rsa_ctx_t *)engine_ctx;
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

int hpre_module_rsa_init(void)
{
    wd_hpre_init_qnode_pool();
    /* register async poll func */
    async_register_poll_fn_v1(ASYNC_TASK_WD_RSA, hpre_rsa_ctx_poll);

    return 1;
}

static int hpre_rsa_check(const int flen, const BIGNUM *n, const BIGNUM *e, int *num_bytes, RSA *rsa)
{
    int key_bits;

    if (n == NULL || e == NULL)
        return OPENSSL_FAIL;

    if (check_pubkey_param(n, e) != OPENSSL_SUCCESS)
        return OPENSSL_FAIL;

    *num_bytes = BN_num_bytes(n);
    if (flen > *num_bytes) {
        KAEerr(KAE_F_HPRE_RSA_PUBDEC, KAE_R_DATA_GREATER_THEN_MOD_LEN);
        US_WARN("data length is large than num bytes of rsa->n");
        return OPENSSL_FAIL;
    }

    key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return OPENSSL_FAIL;
    }

    return OPENSSL_SUCCESS;
}

static int hpre_rsa_new_bn(
    const BIGNUM *n, int flen, const unsigned char *from, BN_CTX **bn_ctx, BIGNUM **bn_ret, BIGNUM **f)
{
    BN_CTX *bn_ctx_tmp;
    BIGNUM *bn_ret_tmp = NULL;
    BIGNUM *f_tmp = NULL;

    bn_ctx_tmp = BN_CTX_new();
    if (bn_ctx_tmp == NULL) {
        US_ERR("fail to new BN_CTX.");
        return OPENSSL_FAIL;
    }

    BN_CTX_start(bn_ctx_tmp);
    bn_ret_tmp = BN_CTX_get(bn_ctx_tmp);
    f_tmp = BN_CTX_get(bn_ctx_tmp);
    if (bn_ret_tmp == NULL || f_tmp == NULL) {
        US_ERR("fail to get BN_CTX.");
        return OPENSSL_FAIL;
    }

    if (BN_bin2bn(from, flen, f_tmp) == NULL) {
        US_ERR("fail to bin2bn");
        return OPENSSL_FAIL;
    }

    if (BN_ucmp(f_tmp, n) >= 0) {
        US_ERR("data is too large");
        return OPENSSL_FAIL;
    }
    *bn_ctx = bn_ctx_tmp;
    *bn_ret = bn_ret_tmp;
    *f = f_tmp;
    return OPENSSL_SUCCESS;
}

int hpre_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    struct wcrypto_rsa_pubkey *pubkey = NULL;
    struct wcrypto_rsa_prikey *prikey = NULL;
    struct wd_dtb *wd_e = NULL;
    struct wd_dtb *wd_p = NULL;
    struct wd_dtb *wd_q = NULL;
    BIGNUM *e_value = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    hpre_rsa_ctx_t *eng_ctx;
    int ret;

    if (bits < RSA_MIN_MODULUS_BITS) {
        US_ERR("rsa key size too small");
        return OPENSSL_FAIL;
    }
    if (!check_bit_useful(bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return OPENSSL_FAIL;
    }
    if ((eng_ctx = hpre_get_rsa_eng_ctx(rsa, bits, 1)) == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        return KAE_CRYPTO_FAIL;
    }

    e_value = BN_new();
    p = BN_new();
    q = BN_new();

    GOTOEND_IF(e_value == NULL || p == NULL || q == NULL,
        "e_value or p or q MALLOC FAILED.",
        KAE_F_HPRE_RSA_KEYGEN,
        KAE_R_ERR_LIB_BN);
    GOTOEND_IF(hpre_rsa_primegen(bits, e, p, q, cb) == OPENSSL_FAIL,
        "hisi_rsa_primegen failed",
        KAE_F_HPRE_RSA_KEYGEN,
        KAE_R_GET_PRIMEKEY_FAILURE);
    GOTOEND_IF(BN_copy(e_value, e) == NULL, "copy e failed", KAE_F_HPRE_RSA_KEYGEN, KAE_R_ERR_LIB_BN);

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
        US_WARN("hpre fill keygen opdata failed");
        ret = KAE_CRYPTO_FAIL;
        goto end;
    }
    ret = hpre_rsa_sync(eng_ctx->ctx, &eng_ctx->opdata);
    if (ret == OPENSSL_FAIL) {
        US_WARN("hpre generate rsa key failed.switch to soft");
        goto end;
    }
    ret = hpre_rsa_get_keygen_param(&eng_ctx->opdata, eng_ctx->ctx, rsa, e_value, p, q);

    US_DEBUG("hpre rsa keygen success!");

end:
    hpre_free_rsa_eng_ctx(eng_ctx);

    return ret;
}

int hpre_rsa_private_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    hpre_rsa_ctx_t *eng_ctx = NULL;
    BIGNUM *f = NULL;
    BIGNUM *bn_ret = NULL;
    BN_CTX *bn_ctx = NULL;
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
    int num_bytes = 0;
    int key_bits;
    int version;
    int ret;

    if (hpre_rsa_check_param(flen, from, to, rsa) != OPENSSL_SUCCESS)
        return OPENSSL_FAIL;

    key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return OPENSSL_FAIL;
    }

    if ((eng_ctx = hpre_get_rsa_eng_ctx(rsa, 0, 0)) == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        return KAE_CRYPTO_FAIL;
    }

    bn_ctx = BN_CTX_new();

    GOTOEND_IF(bn_ctx == NULL, "PRI_ENC MALLOC_FAILURE ", KAE_F_HPRE_RSA_PRIENC, KAE_R_MALLOC_FAILURE);

    BN_CTX_start(bn_ctx);
    f = BN_CTX_get(bn_ctx);
    bn_ret = BN_CTX_get(bn_ctx);

    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    RSA_get0_key(rsa, &n, &e, &d);
    version = RSA_get_version(rsa);
    num_bytes = BN_num_bytes(n);

    in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);
    GOTOEND_IF(bn_ret == NULL || in_buf == NULL, "OpenSSL malloc failure", KAE_F_HPRE_RSA_PRIENC, KAE_R_MALLOC_FAILURE);

    ret = hpre_rsa_padding(flen, from, in_buf, num_bytes, padding, PRI_ENC);
    GOTOEND_IF(ret == OPENSSL_FAIL, "RSA PADDING FAILED!", KAE_F_HPRE_RSA_PRIENC, KAE_R_RSA_PADDING_FAILURE);

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    hpre_rsa_fill_prikey(rsa, eng_ctx, version, p, q, dmp1, dmq1, iqmp);

    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_SIGN;
    eng_ctx->opdata.in =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, in_buf, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    if (ret == OPENSSL_FAIL) {
        US_WARN("hpre rsa priv encrypt failed!");
        goto end;
    }

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, bn_ret);

    if (hpre_get_prienc_res(padding, f, n, bn_ret, &res) == OPENSSL_FAIL)
        goto end;

    ret = BN_bn2binpad(res, to, num_bytes);

    US_DEBUG("hpre rsa priv encrypt success!");

end:
    hpre_free_bn_ctx_buf(bn_ctx, in_buf, num_bytes);
    hpre_free_rsa_eng_ctx(eng_ctx);

    return ret;
}

int hpre_rsa_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    BIGNUM *ret_bn = NULL;
    hpre_rsa_ctx_t *eng_ctx = NULL;
    unsigned char *in_buf = NULL;
    BN_CTX *bn_ctx = NULL;
    int num_bytes = 0;
    int key_bits;
    int ret;

    if (!to)
        return RSA_size(rsa);

    if (hpre_rsa_check_param(flen, from, to, rsa) != OPENSSL_SUCCESS)
        return OPENSSL_FAIL;

    key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then back to soft!");
        return OPENSSL_FAIL;
    }

    if ((eng_ctx = hpre_get_rsa_eng_ctx(rsa, 0, 0)) == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        return KAE_CRYPTO_FAIL;
    }

    RSA_get0_key(rsa, &n, &e, &d);
    ret = check_pubkey_param(n, e);
    GOTOEND_IF(ret != OPENSSL_SUCCESS, "check public key fail", KAE_F_HPRE_RSA_PUBENC, KAE_R_PUBLIC_KEY_INVALID);

    bn_ctx = BN_CTX_new();

    GOTOEND_IF(bn_ctx == NULL, "bn_ctx MALLOC FAILED!", KAE_F_HPRE_RSA_PUBENC, KAE_R_MALLOC_FAILURE);
    BN_CTX_start(bn_ctx);
    ret_bn = BN_CTX_get(bn_ctx);
    num_bytes = BN_num_bytes(n);
    in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);

    GOTOEND_IF(ret_bn == NULL || in_buf == NULL,
        "PUBLIC_ENCRYPT RSA MALLOC FAILED!",
        KAE_F_HPRE_RSA_PUBENC,
        KAE_R_MALLOC_FAILURE);

    ret = hpre_rsa_padding(flen, from, in_buf, num_bytes, padding, PUB_ENC);
    GOTOEND_IF(ret == OPENSSL_FAIL, "RSA PADDING FAILED", KAE_F_HPRE_RSA_PUBENC, KAE_R_RSA_PADDING_FAILURE);

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_VERIFY;
    eng_ctx->opdata.in =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, in_buf, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    GOTOEND_IF(
        ret == OPENSSL_FAIL, "hpre rsa pub encrypt failed!", KAE_F_HPRE_RSA_PUBENC, KAE_R_PUBLIC_ENCRYPTO_FAILURE);

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, ret_bn);
    ret = BN_bn2binpad(ret_bn, to, num_bytes);

    US_DEBUG("hpre rsa public encrypt success!");

end:
    hpre_free_bn_ctx_buf(bn_ctx, in_buf, num_bytes);
    hpre_free_rsa_eng_ctx(eng_ctx);

    return ret;
}

int hpre_rsa_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    hpre_rsa_ctx_t *eng_ctx = NULL;
    const BIGNUM *n = (const BIGNUM *)NULL;
    const BIGNUM *e = (const BIGNUM *)NULL;
    const BIGNUM *d = (const BIGNUM *)NULL;
    const BIGNUM *p = (const BIGNUM *)NULL;
    const BIGNUM *q = (const BIGNUM *)NULL;
    const BIGNUM *dmp1 = (const BIGNUM *)NULL;
    const BIGNUM *dmq1 = (const BIGNUM *)NULL;
    const BIGNUM *iqmp = (const BIGNUM *)NULL;
    BIGNUM *bn_ret = NULL;
    BIGNUM *f = NULL;
    BN_CTX *bn_ctx = NULL;
    unsigned char *buf = (unsigned char *)NULL;
    int num_bytes, key_bits, version;
    int ret, len;

    if (hpre_rsa_check_param(flen, from, to, rsa) != OPENSSL_SUCCESS)
        return OPENSSL_FAIL;

    RSA_get0_key(rsa, &n, &e, &d);
    num_bytes = BN_num_bytes(n);
    if (flen > num_bytes) {
        US_ERR("flen is no equal to num_byte");
        return OPENSSL_FAIL;
    }

    key_bits = RSA_bits(rsa);
    if (!check_bit_useful(key_bits)) {
        US_WARN("op sizes not supported by hpre engine then switch soft!");
        return KAE_CRYPTO_FAIL;
    }

    if ((eng_ctx = hpre_get_rsa_eng_ctx(rsa, 0, 0)) == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        return KAE_CRYPTO_FAIL;
    }

    ret = hpre_rsa_new_bn(n, flen, from, &bn_ctx, &bn_ret, &f);
    if (ret == OPENSSL_FAIL) {
        goto end;
    }

    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    version = RSA_get_version(rsa);
    buf = (unsigned char *)OPENSSL_malloc(num_bytes);

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    hpre_rsa_fill_prikey(rsa, eng_ctx, version, p, q, dmp1, dmq1, iqmp);

    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_SIGN;
    eng_ctx->opdata.in =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, from, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    if (ret == OPENSSL_FAIL) {
        US_WARN("hpre rsa priv decrypt failed.");
        goto end;
    }

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, bn_ret);
    len = BN_bn2binpad(bn_ret, buf, num_bytes);
    ret = check_rsa_padding(to, num_bytes, buf, len, padding, PRI_DEC);
    if (ret == OPENSSL_FAIL) {
        US_WARN("hpre rsa check padding failed.");
        goto end;
    }

    US_DEBUG("hpre rsa priv decrypt success!");

end:
    hpre_free_bn_ctx_buf(bn_ctx, buf, num_bytes);
    hpre_free_rsa_eng_ctx(eng_ctx);

    return ret;
}

int hpre_rsa_public_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    hpre_rsa_ctx_t *eng_ctx = NULL;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *f = NULL;
    BIGNUM *bn_ret = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    int num_bytes = 0;
    unsigned char *buf = NULL;
    int ret, len;

    if (!to)
        return RSA_size(rsa);

    if (hpre_rsa_check_param(flen, from, to, rsa) != OPENSSL_SUCCESS)
        return KAE_CRYPTO_FAIL;

    RSA_get0_key(rsa, &n, &e, &d);
    ret = hpre_rsa_check(flen, n, e, &num_bytes, rsa);
    if (ret == OPENSSL_FAIL) {
        return ret;
    }

    if ((eng_ctx = hpre_get_rsa_eng_ctx(rsa, 0, 0)) == NULL) {
        US_WARN("get eng ctx fail then switch to soft!");
        return KAE_CRYPTO_FAIL;
    }

    ret = hpre_rsa_new_bn(n, flen, from, &bn_ctx, &bn_ret, &f);
    if (ret == OPENSSL_FAIL) {
        goto end;
    }

    buf = (unsigned char *)OPENSSL_malloc(num_bytes);
    if (buf == NULL) {
        ret = OPENSSL_FAIL;
        goto end;
    }

    hpre_rsa_fill_pubkey(e, n, eng_ctx);
    eng_ctx->opdata.in_bytes = eng_ctx->priv_ctx.key_size;
    eng_ctx->opdata.op_type = WCRYPTO_RSA_VERIFY;
    eng_ctx->opdata.in =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    eng_ctx->opdata.out =
        eng_ctx->rsa_setup.br.alloc(eng_ctx->qlist->kae_queue_mem_pool, eng_ctx->qlist->kae_queue_mem_pool->block_size);
    kae_memcpy(eng_ctx->opdata.in, from, eng_ctx->opdata.in_bytes);

    ret = hpre_rsa_crypto(eng_ctx, &eng_ctx->opdata);
    GOTOEND_IF(
        ret == OPENSSL_FAIL, "hpre rsa pub decrypt failed!", KAE_F_HPRE_RSA_PUBDEC, KAE_R_PUBLIC_DECRYPTO_FAILURE);

    BN_bin2bn((const unsigned char *)eng_ctx->opdata.out, eng_ctx->opdata.out_bytes, bn_ret);
    if ((padding == RSA_X931_PADDING) && ((bn_get_words(bn_ret)[0] & 0xf) != 12)) {  // not 12 then BN_sub
        GOTOEND_IF(!BN_sub(bn_ret, n, bn_ret), "BN_sub failed", KAE_F_HPRE_RSA_PUBDEC, KAE_R_ERR_LIB_BN);
    }
    len = BN_bn2binpad(bn_ret, buf, num_bytes);
    ret = check_rsa_padding(to, num_bytes, buf, len, padding, PUB_DEC);
    if (ret == OPENSSL_FAIL) {
        US_WARN("hpre rsa check padding failed.switch to soft");
        goto end;
    }

    US_DEBUG("hpre rsa public decrypt success!");

end:
    hpre_free_bn_ctx_buf(bn_ctx, buf, num_bytes);
    hpre_free_rsa_eng_ctx(eng_ctx);

    return ret;
}