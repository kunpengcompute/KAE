/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for KAE engine utils dealing with wrapdrive
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

#include "engine_types.h"
#include "engine_log.h"
#include "hpre_rsa.h"
#include "hpre_wd.h"
#include "wd_rsa.h"

BN_ULONG *bn_get_words(const BIGNUM *a)
{
    return a->d;
}

void hpre_free_bn_ctx_buf(BN_CTX *bn_ctx, unsigned char *in_buf, int num)
{
    if (bn_ctx != NULL) {
        BN_CTX_end(bn_ctx);
    }
    BN_CTX_free(bn_ctx);
    if (in_buf != NULL) {
        OPENSSL_clear_free(in_buf, num);
    }
}

/* check parameter */
int hpre_rsa_check_para(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa)
{
    if ((rsa == NULL || from == NULL || to == NULL || flen <= 0)) {
        US_ERR("RSA key %p, input %p or output %p are NULL, \
            or flen invalid length.\n", rsa, from, to);
        return HPRE_CRYPTO_FAIL;
    }
    return HPRE_CRYPTO_SUCC;
}

int hpre_get_prienc_res(int padding, BIGNUM *f, const BIGNUM *n, BIGNUM *bn_ret, BIGNUM **res)
{
    if (padding == RSA_X931_PADDING) {
        if (!BN_sub(f, n, bn_ret)) {
            return HPRE_CRYPTO_FAIL;
        }
        if (BN_cmp(bn_ret, f) > 0) {
            *res = f;
        } else {
            *res = bn_ret;
        }
    } else {
        *res = bn_ret;
    }
    return HPRE_CRYPTO_SUCC;
}

/**
 * func:
 * desc:
 *      Check HPRE rsa bits
 *
 * @param bit :rsa bit
 * @return
 *        succ: 1
 *        fail: 0
 */
int check_bit_useful(const int bit)
{
    switch (bit) {
        case RSA1024BITS:
        case RSA2048BITS:
        case RSA3072BITS:
        case RSA4096BITS:
            return 1;
        default:
            break;
    }
    return 0;
}

/**
 *
 * @param n
 * @param e
 * @return  success 1 / failed 0
 */
int check_pubkey_param(const BIGNUM *n, const BIGNUM *e)
{
    if (BN_num_bits(n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
        KAEerr(KAE_F_CHECK_PUBKEY_PARAM, KAE_R_MODULE_TOO_LARGE);
        US_ERR("RSA MODULUS TOO LARGE!");
        return HPRE_CRYPTO_FAIL;
    }

    if (BN_ucmp(n, e) <= 0) {
        KAEerr(KAE_F_CHECK_PUBKEY_PARAM, KAE_R_INVAILED_E_VALUE);
        US_ERR("RSA E VALUE IS NOT VALID!");
        return HPRE_CRYPTO_FAIL;
    }

    /* for large moduli, enforce exponent limit */
    if (BN_num_bits(n) > OPENSSL_RSA_SMALL_MODULUS_BITS) {
        if (BN_num_bits(e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
            KAEerr(KAE_F_CHECK_PUBKEY_PARAM, KAE_R_INVAILED_E_VALUE);
            US_ERR("RSA E VALUE IS NOT VALID!");
            return HPRE_CRYPTO_FAIL;
        }
    }
    return HPRE_CRYPTO_SUCC;
}

static int hpre_pubenc_padding(int flen, const unsigned char *from,
    unsigned char *buf, int num, int padding)
{
    int ret = HPRE_CRYPTO_FAIL;

    switch (padding) {
        case RSA_PKCS1_PADDING:
            ret = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
            break;
        case RSA_PKCS1_OAEP_PADDING:
            ret = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen,
                                             NULL, 0);
            break;
        case RSA_SSLV23_PADDING:
            ret = RSA_padding_add_SSLv23(buf, num, from, flen);
            break;
        case RSA_NO_PADDING:
            ret = RSA_padding_add_none(buf, num, from, flen);
            break;
        default:
            KAEerr(KAE_F_HPRE_PUBENC_PADDING, KAE_R_UNKNOW_PADDING_TYPE);
            US_ERR("RSA UNKNOWN PADDING TYPE!");
            ret = HPRE_CRYPTO_FAIL;
    }
    if (ret <= 0) {
        US_ERR("padding error: ret = %d", ret);
        ret = HPRE_CRYPTO_FAIL;
    } else {
        ret = HPRE_CRYPTO_SUCC;
    }
    return ret;
}

static int hpre_prienc_padding(int flen, const unsigned char *from,
    unsigned char *buf, int num, int padding)
{
    int ret = HPRE_CRYPTO_FAIL;

    switch (padding) {
        case RSA_PKCS1_PADDING:
            ret =  RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
            break;
        case RSA_X931_PADDING:
            ret = RSA_padding_add_X931(buf, num, from, flen);
            break;
        case RSA_NO_PADDING:
            ret = RSA_padding_add_none(buf, num, from, flen);
            break;
        default:
            KAEerr(KAE_F_HPRE_PRIENC_PADDING, KAE_R_UNKNOW_PADDING_TYPE);
            US_ERR("RSA UNKNOWN PADDING TYPE!");
            ret = HPRE_CRYPTO_FAIL;
    }
    if (ret <= 0) {
        US_DEBUG("padding error: ret = %d", ret);
        ret = HPRE_CRYPTO_FAIL;
    } else {
        ret = HPRE_CRYPTO_SUCC;
    }
    return ret;
}

/**
 * func:
 *
 * @param flen      [IN]    - size in bytes of input
 * @param from      [IN]    - pointer to the input
 * @param buf       [OUT]   - pointer to output data
 * @param num       [IN]    - pointer to public key structure
 * @param padding   [IN]    - Padding scheme
 * @param type      [IN]    - Padding type
 * @return
 *      SUCCESS: 1
 *      FAIL:    0
 * desc:
 *      rsa encrypt padding.
 *
 */
int hpre_rsa_padding(int flen, const unsigned char *from, unsigned char *buf,
                     int num, int padding, int type)
{
    int ret = HPRE_CRYPTO_FAIL;

    if (type == PUB_ENC) {
        return hpre_pubenc_padding(flen, from, buf, num, padding);
    } else if (type == PRI_ENC) {
        return hpre_prienc_padding(flen, from, buf, num, padding);
    }

    US_ERR("hpre rsa padding type error.");
    return ret;
}

static int hpre_check_pubdec_padding(unsigned char *to, int num,
    const unsigned char *buf, int len, int padding)
{
    int ret = HPRE_CRYPTO_FAIL;

    switch (padding) {
        case RSA_PKCS1_PADDING:
            ret = RSA_padding_check_PKCS1_type_1(to, num, buf, len, num);
            break;
        case RSA_X931_PADDING:
            ret = RSA_padding_check_X931(to, num, buf, len, num);
            break;
        case RSA_NO_PADDING:
            kae_memcpy(to, buf, len);
            ret = len;
            break;
        default:
            KAEerr(KAE_F_CHECK_HPRE_PUBDEC_PADDING, KAE_R_UNKNOW_PADDING_TYPE);
            US_ERR("RSA UNKNOWN PADDING TYPE!");
            ret = HPRE_CRYPTO_FAIL;
    }

    if (ret == -1) {
        US_ERR("FAIL ret = %d.", ret);
        ret = HPRE_CRYPTO_FAIL;
    }
    return ret;
}

static int hpre_check_pridec_padding(unsigned char *to, int num,
    const unsigned char *buf, int len, int padding)
{
    int ret = HPRE_CRYPTO_FAIL;
    switch (padding) {
        case RSA_PKCS1_PADDING:
            ret = RSA_padding_check_PKCS1_type_2(to, num, buf, len, num);
            break;
        case RSA_PKCS1_OAEP_PADDING:
            ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, len, num,
                                               NULL, 0);
            break;
        case RSA_SSLV23_PADDING:
            ret = RSA_padding_check_SSLv23(to, num, buf, len, num);
            break;
        case RSA_NO_PADDING:
            kae_memcpy(to, buf, len);
            ret = len;
            break;
        default:
            KAEerr(KAE_F_CHECK_HPRE_PRIDEC_PADDING, KAE_R_UNKNOW_PADDING_TYPE);
            US_ERR("RSA UNKNOWN PADDING TYPE!");
            ret = HPRE_CRYPTO_FAIL;
    }

    if (ret == -1) {
        US_ERR("FAIL ret = %d.", ret);
        ret = HPRE_CRYPTO_FAIL;
    }
    return ret;
}

/**
 * func:
 *
 * @param len       [IN]    - size in bytes of output
 * @param to        [IN]    - pointer to the output
 * @param buf       [OUT]   - pointer to output data
 * @param num       [IN]    - pointer to public key structure
 * @param padding   [IN]    - Padding scheme
 * @param type      [IN]    - Padding type
 * @return
 *      SUCCESS: 1
 *      FAIL:    0
 * desc:
 *      rsa decrypt padding.
 *
 */
int check_rsa_padding(unsigned char *to, int num,
                      const unsigned char *buf, int len, int padding, int type)
{
    int ret = HPRE_CRYPTO_FAIL;

    if (type == PUB_DEC) {
        return hpre_check_pubdec_padding(to, num, buf, len, padding);
    } else if (type == PRI_DEC) {
        return hpre_check_pridec_padding(to, num, buf, len, padding);
    }

    US_ERR("hpre rsa padding type error.");
    return ret;
}

static int check_primeequal(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *prime)
{
    int j;

    for (j = 0; j < i; j++) {
        BIGNUM *prev_prime = NULL;

        if (j == 0) {
            prev_prime = rsa_p;
        } else {
            prev_prime = rsa_q;
        }

        if (!BN_cmp(prime, prev_prime)) {
            return KAE_FAIL;
        }
    }
    return KAE_SUCCESS;
}

static int prime_mul_res(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1, BN_CTX *ctx, BN_GENCB *cb)
{
    if (i == 1) {
        /* we get at least 2 primes */
        if (!BN_mul(r1, rsa_p, rsa_q, ctx)) {
            goto err;
        }
    } else {
        /* i == 0, do nothing */
        if (!BN_GENCB_call(cb, 3, i)) { // When a random p has been found, call BN_GENCB_call(cb, 3, *i)
            goto err;
        }
        goto cont;
    }
    return KAE_SUCCESS;
err:
    return -1;
cont:
    return 1;
}
static int check_prime_sufficient(int *i, int *bitsr, int *bitse, int *n, BIGNUM *rsa_p, BIGNUM *rsa_q,
    BIGNUM *r1, BIGNUM *r2, BN_CTX *ctx, BN_GENCB *cb)
{
    BN_ULONG bitst;
    static int retries = 0;

    /* calculate n immediately to see if it's sufficient */
    int ret = prime_mul_res(*i, rsa_p, rsa_q, r1, ctx, cb);
    if (ret != KAE_SUCCESS) {
        return ret;
    }
    if (!BN_rshift(r2, r1, *bitse - 4)) { // right shift *bitse - 4
        goto err;
    }
    bitst = BN_get_word(r2);
    if (bitst < 0x9 || bitst > 0xF) {
        *bitse -= bitsr[*i];
        if (!BN_GENCB_call(cb, 2, *n++)) { // When the n-th is rejected, call BN_GENCB_call(cb, 2, n)
            goto err;
        }
        if (retries == 4) { // retries max is 4
            *i = -1;
            *bitse = 0;
            retries = 0;
            goto cont;
        }
        retries++;
        goto redo;
    }

    if (!BN_GENCB_call(cb, 3, *i)) { // When a random p has been found, call BN_GENCB_call(cb, 3, *i)
        goto err;
    }
    retries = 0;
    return 0;
err:
    return -1;
redo:
    return -2; // if redo return -2
cont:
    return 1;
}
static void set_primes(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM **prime)
{
    if (i == 0) {
        *prime = rsa_p;
    } else {
        *prime = rsa_q;
    }
    BN_set_flags(*prime, BN_FLG_CONSTTIME);
}
static int check_prime_useful(int *n, BIGNUM *prime, BIGNUM *r1, BIGNUM *r2, 
    BIGNUM *e_value, BN_CTX *ctx, BN_GENCB *cb)
{
    if (!BN_sub(r2, prime, BN_value_one())) {
        goto err;
    }
    ERR_set_mark();
    BN_set_flags(r2, BN_FLG_CONSTTIME);
    if (BN_mod_inverse(r1, r2, e_value, ctx) != NULL) {
        goto br;
    }
    unsigned long error = ERR_peek_last_error();
    if (ERR_GET_LIB(error) == ERR_LIB_BN
        && ERR_GET_REASON(error) == BN_R_NO_INVERSE) {
        ERR_pop_to_mark();
    } else {
        goto err;
    }
    if (!BN_GENCB_call(cb, 2, *n++)) { // When the n-th is rejected, call BN_GENCB_call(cb, 2, n)
        goto err;
    }
    return 0;
err:
    return -1;
br:
    return 1;
}
static void switch_p_q(BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *p, BIGNUM *q)
{
    BIGNUM *tmp = (BIGNUM *)NULL;

    if (BN_cmp(rsa_p, rsa_q) < 0) {
        tmp = rsa_p;
        rsa_p = rsa_q;
        rsa_q = tmp;
    }
    BN_copy(q, rsa_q);
    BN_copy(p, rsa_p);
}
static int hpre_get_prime_once(int i, const int *bitsr, int *n, BIGNUM *prime, BIGNUM *rsa_p, BIGNUM *rsa_q,
    BIGNUM *r1, BIGNUM *r2, BIGNUM *e_value, BN_CTX *ctx, BN_GENCB *cb)
{
    int adj = 0;
    int ret = KAE_FAIL;

    for (;;) {
redo:
        if (!BN_generate_prime_ex(prime, bitsr[i] + adj, 0, (const BIGNUM *)NULL, (const BIGNUM *)NULL, cb)) {
            goto err;
        }
        /*
 * prime should not be equal to p, q, r_3...
 * (those primes prior to this one)
 */
        if (check_primeequal(i, rsa_p, rsa_q, prime) == KAE_FAIL) {
            goto redo;
        }

        ret = check_prime_useful(n, prime, r1, r2, e_value, ctx, cb);
        if (ret == KAE_FAIL) {
            goto err;
        } else if (ret == 1) {
            break;
        }
    }
    return ret;
err:
    return KAE_FAIL;
}

int hpre_rsa_primegen(int bits, BIGNUM *e_value, BIGNUM *p, BIGNUM *q, BN_GENCB *cb)
{
    int ok = -1;
    int primes = 2;
    int n = 0;
    int bitse = 0;
    int i = 0;
    int bitsr[2];                // 2 bits
    BN_CTX *ctx = (BN_CTX *)NULL;
    BIGNUM *r1 = (BIGNUM *)NULL;
    BIGNUM *r2 = (BIGNUM *)NULL;
    BIGNUM *prime = (BIGNUM *)NULL;
    BIGNUM *rsa_p, *rsa_q;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        goto err;
    }
    BN_CTX_start(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    rsa_p = BN_CTX_get(ctx);
    rsa_q = BN_CTX_get(ctx);
    if (rsa_q == NULL) {
        goto err;
    }
    /* divide bits into 'primes' pieces evenly */
    int quo = bits / primes;
    bitsr[0] = quo;
    bitsr[1] = quo;
    /* generate p, q and other primes (if any) */
    for (i = 0; i < primes; i++) {
        set_primes(i, rsa_p, rsa_q, &prime);
redo:
        if (hpre_get_prime_once(i, bitsr, &n, prime, rsa_p, rsa_q, r1, r2, e_value, ctx, cb) == KAE_FAIL) {
            goto err;
        }

        bitse += bitsr[i];
        int ret = check_prime_sufficient(&i, bitsr, &bitse, &n, rsa_p, rsa_q, r1, r2, ctx, cb);
        if (ret == -1) {
            goto err;
        } else if (ret == -2) { // ret = -2 goto redo
            goto redo;
        } else if (ret == 1) {
            continue;
        }
    }
    switch_p_q(rsa_p, rsa_q, p, q);
    ok = 1;
    err:
    if (ok == -1) {
        KAEerr(KAE_F_HPRE_RSA_PRIMEGEN, KAE_R_ERR_LIB_BN);
        US_ERR("rsa prime gen failed");
        ok = 0;
    }
    hpre_free_bn_ctx_buf(ctx, NULL, 0);
    return ok;
}
