/*
 * Copyright (C) 2025. Huawei Technologies Co.,Ltd.All rights reserved.
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
#include <openssl/base.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/target.h>  // OPENSSL_64_BIT or OPENSSL_32_BIT
#include <assert.h>
#include <ctype.h>
#include <stdint.h>

#include "../../utils/engine_log.h"

#include "bssl_rsa.h"
#if defined(BORINGSSL_CONSTANT_TIME_VALIDATION)  // to define
#include <valgrind/memcheck.h>
#endif

#if defined(OPENSSL_64_BIT)
typedef uint64_t crypto_word_t;
#elif defined(OPENSSL_32_BIT)
typedef uint32_t crypto_word_t;
#else
#error "Must define either OPENSSL_32_BIT or OPENSSL_64_BIT"
#endif
#define CONSTTIME_TRUE_W ~((crypto_word_t)0)

#if defined(BORINGSSL_CONSTANT_TIME_VALIDATION)
#define CONSTTIME_SECRET(ptr, len) VALGRIND_MAKE_MEM_UNDEFINED(ptr, len)
#define CONSTTIME_DECLASSIFY(ptr, len) VALGRIND_MAKE_MEM_DEFINED(ptr, len)
#else
#define CONSTTIME_SECRET(ptr, len)
#define CONSTTIME_DECLASSIFY(ptr, len)
#endif

static RSA_METHOD *g_hpre_rsa_method = NULL;
static RSA_METHOD rsa_null_meth = {.common = {.is_static = 1}};

int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))(BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx)
{
    // return meth->rsa_mod_exp;
    return 0;
}

int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))(
    BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    // return meth->bn_mod_exp;
    return 0;
}

int RSA_padding_add_PKCS1_OAEP(
    uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len, const uint8_t *param, size_t param_len)
{
    return RSA_padding_add_PKCS1_OAEP_mgf1(to, to_len, from, from_len, param, param_len, NULL, NULL);
}

RSA_METHOD *bssl_soft_rsa_meth_new(const char *name, int flags)
{
    RSA_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));
    if (meth) {
        meth->flags = flags;
    }
    return meth;
}

void bssl_soft_rsa_meth_free(RSA_METHOD *meth)
{
    if (meth) {
        OPENSSL_free(meth);
    }
}

int bssl_soft_rsa_set_priv_meth(RSA_METHOD *meth,
    int (*sign_raw)(
        RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding),
    int (*decrypt)(
        RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding))
{
    if (!meth || !sign_raw || !decrypt) {
        return 0;
    }

    meth->common.is_static = 1;
    meth->sign_raw = sign_raw;
    meth->decrypt = decrypt;

    return 1;
}

RSA_METHOD *bssl_soft_get_default_RSA_methods(void)
{
    return &rsa_null_meth;
}

int RSA_private_encrypt_default(size_t flen, const uint8_t *from, uint8_t *to, RSA *rsa, int padding)
{
    int ret = 0;
    size_t rsa_len = 0;

    US_DEBUG("kae bssl hpre rsa priv enc failed, switch to soft.");
    rsa_len = RSA_size(rsa);
    RSA_METHOD *origin_meth = rsa->meth;
    rsa->meth = bssl_soft_get_default_RSA_methods();
    ret = RSA_sign_raw(rsa, &rsa_len, to, rsa_len, from, flen, padding);
    rsa->meth = origin_meth;

    if (ret == 0) {
        return -1;
    }
    return rsa_len;
}

int RSA_private_decrypt_default(size_t flen, const uint8_t *from, uint8_t *to, RSA *rsa, int padding)
{
    int ret = 0;
    size_t rsa_len = 0;

    US_DEBUG("kae bssl hpre rsa priv dec failed, switch to soft.");
    rsa_len = RSA_size(rsa);
    RSA_METHOD *origin_meth = rsa->meth;
    rsa->meth = bssl_soft_get_default_RSA_methods();
    ret = RSA_decrypt(rsa, &rsa_len, to, rsa_len, from, flen, padding);
    rsa->meth = origin_meth;

    if (ret == 0) {
        return -1;
    }
    return rsa_len;
}

static int rand_nonzero(uint8_t *out, size_t len)
{
    if (!RAND_bytes(out, len)) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        while (out[i] == 0) {
            if (!RAND_bytes(out + i, 1)) {
                return 0;
            }
        }
    }

    return 1;
}

int bssl_soft_rsa_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len)
{
    if (from_len > to_len) {
        return 0;
    }

    if (from_len < to_len) {
        return 0;
    }

    memcpy(to, from, from_len);
    return 1;
}

int bssl_soft_rsa_padding_check_none(unsigned char *to, int tlen, const unsigned char *from, int flen, int num)
{

    if (flen > tlen) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return -1;
    }

    memset(to, 0, tlen - flen);
    memcpy(to + tlen - flen, from, flen);
    return tlen;
}

int bssl_soft_rsa_padding_add_pkcs1_type_1(uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len)
{
    /* See RFC 8017, section 9.2. */
    if (to_len < RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        return 0;
    }

    to[0] = 0;
    to[1] = 1;
    memset(to + 2, 0xff, to_len - 3 - from_len);
    to[to_len - from_len - 1] = 0;
    memcpy(to + to_len - from_len, from, from_len);
    return 1;
}

int bssl_soft_rsa_padding_check_pkcs1_type_1(unsigned char *to, int tlen, const unsigned char *from, int flen, int num)
{
    int i, j;
    const unsigned char *p;

    p = from;

    /*
     * The format is
     * 00 || 01 || PS || 00 || D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     */

    if (num < RSA_PKCS1_PADDING_SIZE)
        return -1;

    /* Accept inputs with and without the leading 0-byte. */
    if (num == flen) {
        if ((*p++) != 0x00) {
            return -1;
        }
        flen--;
    }

    if ((num != (flen + 1)) || (*(p++) != 0x01)) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_BLOCK_TYPE_IS_NOT_01);
        return -1;
    }

    /* scan over padding data */
    j = flen - 1; /* one for type. */
    for (i = 0; i < j; i++) {
        if (*p != 0xff) { /* should decrypt to 0xff */
            if (*p == 0) {
                p++;
                break;
            } else {
                OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_FIXED_HEADER_DECRYPT);
                return -1;
            }
        }
        p++;
    }

    if (i == j) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_NULL_BEFORE_BLOCK_MISSING);
        return -1;
    }

    if (i < 8) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_PAD_BYTE_COUNT);
        return -1;
    }
    i++; /* Skip over the '\0' */
    j -= i;
    if (j > tlen) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return -1;
    }
    memcpy(to, p, (unsigned int)j);

    return j;
}

int bssl_soft_rsa_padding_add_pkcs1_type_2(uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len)
{
    // See RFC 8017, section 7.2.1.
    if (to_len < RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        return 0;
    }

    to[0] = 0;
    to[1] = 2;

    size_t padding_len = to_len - 3 - from_len;
    if (!rand_nonzero(to + 2, padding_len)) {
        return 0;
    }

    to[2 + padding_len] = 0;
    memcpy(to + to_len - from_len, from, from_len);
    return 1;
}

static inline crypto_word_t constant_time_msb_w(crypto_word_t a)
{
    return 0u - (a >> (sizeof(a) * 8 - 1));
}

static inline crypto_word_t constant_time_is_zero_w(crypto_word_t a)
{
    return constant_time_msb_w(~a & (a - 1));
}

static inline crypto_word_t constant_time_eq_w(crypto_word_t a, crypto_word_t b)
{
    return constant_time_is_zero_w(a ^ b);
}

static inline crypto_word_t value_barrier_w(crypto_word_t a)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(a) : /* no inputs */);
#endif
    return a;
}

static inline crypto_word_t constant_time_select_w(crypto_word_t mask, crypto_word_t a, crypto_word_t b)
{
    mask = value_barrier_w(mask);
    return (mask & a) | (~mask & b);
}

static inline crypto_word_t constant_time_lt_w(crypto_word_t a, crypto_word_t b)
{

    return constant_time_msb_w(a ^ ((a ^ b) | ((a - b) ^ a)));
}

static inline crypto_word_t constant_time_ge_w(crypto_word_t a, crypto_word_t b)
{
    return ~constant_time_lt_w(a, b);
}

static inline void *OPENSSL_memcpy(void *dst, const void *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    return memcpy(dst, src, n);
}

int bssl_soft_rsa_padding_check_pkcs1_type_2(
    uint8_t *out, size_t out_len, const uint8_t *from, size_t from_len, size_t max_out)
{
    if (from_len == 0) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_EMPTY_PUBLIC_KEY);
        return 0;
    }

    if (from_len < RSA_PKCS1_PADDING_SIZE) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    crypto_word_t first_byte_is_zero = constant_time_eq_w(from[0], 0);
    crypto_word_t second_byte_is_two = constant_time_eq_w(from[1], 2);

    crypto_word_t zero_index = 0, looking_for_index = CONSTTIME_TRUE_W;
    for (size_t i = 2; i < from_len; i++) {
        crypto_word_t equals0 = constant_time_is_zero_w(from[i]);
        zero_index = constant_time_select_w(looking_for_index & equals0, i, zero_index);
        looking_for_index = constant_time_select_w(equals0, 0, looking_for_index);
    }

    // The input must begin with 00 02.
    crypto_word_t valid_index = first_byte_is_zero;
    valid_index &= second_byte_is_two;

    // We must have found the end of PS.
    valid_index &= ~looking_for_index;

    // PS must be at least 8 bytes long, and it starts two bytes into |from|.
    valid_index &= constant_time_ge_w(zero_index, 2 + 8);

    // Skip the zero byte.
    zero_index++;

    CONSTTIME_DECLASSIFY(&valid_index, sizeof(valid_index));
    CONSTTIME_DECLASSIFY(&zero_index, sizeof(zero_index));

    if (!valid_index) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_PKCS_DECODING_ERROR);
        return 0;
    }

    const size_t msg_len = from_len - zero_index;
    if (msg_len > max_out) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_PKCS_DECODING_ERROR);
        return 0;
    }

    OPENSSL_memcpy(out, &from[zero_index], msg_len);

    return msg_len;
}

int PKCS1_MGF1(uint8_t *out, size_t len, const uint8_t *seed, size_t seed_len, const EVP_MD *md)
{
    int ret = 0;
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    // FIPS_service_indicator_lock_state();

    size_t md_len = EVP_MD_size(md);

    for (uint32_t i = 0; len > 0; i++) {
        uint8_t counter[4];
        counter[0] = (uint8_t)(i >> 24);
        counter[1] = (uint8_t)(i >> 16);
        counter[2] = (uint8_t)(i >> 8);
        counter[3] = (uint8_t)i;
        if (!EVP_DigestInit_ex(&ctx, md, NULL) || !EVP_DigestUpdate(&ctx, seed, seed_len) ||
            !EVP_DigestUpdate(&ctx, counter, sizeof(counter))) {
            goto err;
        }

        if (md_len <= len) {
            if (!EVP_DigestFinal_ex(&ctx, out, NULL)) {
                goto err;
            }
            out += md_len;
            len -= md_len;
        } else {
            uint8_t digest[EVP_MAX_MD_SIZE];
            if (!EVP_DigestFinal_ex(&ctx, digest, NULL)) {
                goto err;
            }
            OPENSSL_memcpy(out, digest, len);
            len = 0;
        }
    }

    ret = 1;

err:
    EVP_MD_CTX_cleanup(&ctx);
    // FIPS_service_indicator_unlock_state();
    return ret;
}

static inline crypto_word_t constant_time_declassify_w(crypto_word_t v)
{

    CONSTTIME_DECLASSIFY(&v, sizeof(v));
    return value_barrier_w(v);
}

int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len)
{
    const uint8_t *a = (const uint8_t *)(in_a);
    const uint8_t *b = (const uint8_t *)(in_b);
    uint8_t x = 0;

    for (size_t i = 0; i < len; i++) {
        x |= a[i] ^ b[i];
    }

    return x;
}

int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *out, size_t out_len, size_t max_out, const uint8_t *from,
    size_t from_len, const uint8_t *param, size_t param_len, const EVP_MD *md, const EVP_MD *mgf1md)
{
    uint8_t *db = NULL;

    {
        if (md == NULL) {
            md = EVP_sha1();
        }
        if (mgf1md == NULL) {
            mgf1md = md;
        }

        size_t mdlen = EVP_MD_size(md);

        if (from_len < 1 + 2 * mdlen + 1) {
            // 'from_len' is the length of the modulus, i.e. does not depend on the
            // particular ciphertext.
            goto decoding_err;
        }

        size_t dblen = from_len - mdlen - 1;
        db = (uint8_t *)(OPENSSL_malloc(dblen));
        if (db == NULL) {
            goto err;
        }

        const uint8_t *maskedseed = from + 1;
        const uint8_t *maskeddb = from + 1 + mdlen;

        uint8_t seed[EVP_MAX_MD_SIZE];
        if (!PKCS1_MGF1(seed, mdlen, maskeddb, dblen, mgf1md)) {
            goto err;
        }
        for (size_t i = 0; i < mdlen; i++) {
            seed[i] ^= maskedseed[i];
        }

        if (!PKCS1_MGF1(db, dblen, seed, mdlen, mgf1md)) {
            goto err;
        }
        for (size_t i = 0; i < dblen; i++) {
            db[i] ^= maskeddb[i];
        }

        uint8_t phash[EVP_MAX_MD_SIZE];
        if (!EVP_Digest(param, param_len, phash, NULL, md, NULL)) {
            goto err;
        }

        crypto_word_t bad = ~constant_time_is_zero_w(CRYPTO_memcmp(db, phash, mdlen));
        bad |= ~constant_time_is_zero_w(from[0]);

        crypto_word_t looking_for_one_byte = CONSTTIME_TRUE_W;
        size_t one_index = 0;
        for (size_t i = mdlen; i < dblen; i++) {
            crypto_word_t equals1 = constant_time_eq_w(db[i], 1);
            crypto_word_t equals0 = constant_time_eq_w(db[i], 0);
            one_index = constant_time_select_w(looking_for_one_byte & equals1, i, one_index);
            looking_for_one_byte = constant_time_select_w(equals1, 0, looking_for_one_byte);
            bad |= looking_for_one_byte & ~equals0;
        }

        bad |= looking_for_one_byte;

        // Whether the overall padding was valid or not in OAEP is public.
        if (constant_time_declassify_w(bad)) {
            goto decoding_err;
        }

        // Once the padding is known to be valid, the output length is also public.
        static_assert(sizeof(size_t) <= sizeof(crypto_word_t), "size_t does not fit in crypto_word_t");
        one_index = constant_time_declassify_w(one_index);

        one_index++;
        size_t mlen = dblen - one_index;
        if (max_out < mlen) {
            OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
            goto err;
        }

        OPENSSL_memcpy(out, db + one_index, mlen);

        OPENSSL_free(db);
        return mlen;
    }
decoding_err:
    // To avoid chosen ciphertext attacks, the error message should not reveal
    // which kind of decoding error happened.
    OPENSSL_PUT_ERROR(RSA, RSA_R_OAEP_DECODING_ERROR);
err:
    OPENSSL_free(db);
    return 0;
}

int bssl_soft_rsa_padding_check_pkcs1_OAEP(unsigned char *out, int out_len, const unsigned char *from, int from_len,
    int max_out, const unsigned char *p, int pl)
{
    return RSA_padding_check_PKCS1_OAEP_mgf1(out, out_len, max_out, from, max_out, NULL, 0, NULL, NULL);
}

int bssl_soft_rsa_padding_add_sslv23(unsigned char *to, int tlen, const unsigned char *f, int fl)
{
    return 1;
}

int bssl_soft_rsa_padding_check_sslv23(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len)
{
    return fl;
}

int bssl_soft_rsa_padding_add_x931(unsigned char *to, int tlen, const unsigned char *f, int fl)
{
    return 1;
}

int bssl_soft_rsa_padding_check_x931(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len)
{
    return fl;
}