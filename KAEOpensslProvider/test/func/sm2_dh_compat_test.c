/*
 * Copyright 2026 Huawei Technologies Co.,Ltd.All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/async.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dh_vectors.h"

#define HW "provider=kae_provider"
#define SW "provider=default"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); goto done; } } while (0)

struct operation {
    const char *algorithm;
    size_t size;
    int job;
};

static double seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static EVP_PKEY *sm2_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", HW);
    EVP_PKEY *key = NULL;
    if (ctx && EVP_PKEY_keygen_init(ctx) > 0)
        EVP_PKEY_generate(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int raw_signature(EVP_PKEY *key)
{
    EVP_PKEY_CTX *sign = NULL, *verify = NULL, *soft_sign = NULL, *soft_verify = NULL, *copy = NULL;
    unsigned char digest[32], sig[128], repeated[128];
    size_t n, repeated_len;
    int ok = 0;
    sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, HW);
    verify = EVP_PKEY_CTX_new_from_pkey(NULL, key, HW);
    soft_sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, SW);
    soft_verify = EVP_PKEY_CTX_new_from_pkey(NULL, key, SW);
    CHECK(sign && verify && soft_sign && soft_verify);
    CHECK(EVP_PKEY_sign_init(sign) > 0 && EVP_PKEY_sign_init(soft_sign) > 0);
    CHECK(EVP_PKEY_verify_init(verify) > 0 && EVP_PKEY_verify_init(soft_verify) > 0);
    CHECK(EVP_PKEY_CTX_set_signature_md(sign, EVP_sm3()) > 0);
    CHECK(EVP_PKEY_CTX_set_signature_md(verify, EVP_sm3()) > 0);
    CHECK(EVP_PKEY_CTX_set_signature_md(soft_sign, EVP_sm3()) > 0);
    CHECK(EVP_PKEY_CTX_set_signature_md(soft_verify, EVP_sm3()) > 0);
    copy = EVP_PKEY_CTX_dup(sign);
    CHECK(copy);
    for (int i = 0; i < 8; i++) {
        memset(digest, i + 1, sizeof(digest));
        n = 0;
        CHECK(EVP_PKEY_sign(sign, NULL, &n, digest, sizeof(digest)) > 0 && n <= sizeof(sig));
        CHECK(EVP_PKEY_sign(i & 1 ? sign : copy, sig, &n, digest, sizeof(digest)) > 0);
        CHECK(EVP_PKEY_verify(soft_verify, sig, n, digest, sizeof(digest)) == 1);
        CHECK(EVP_PKEY_verify(verify, sig, n, digest, sizeof(digest)) == 1);
        n = sizeof(sig);
        CHECK(EVP_PKEY_sign(soft_sign, sig, &n, digest, sizeof(digest)) > 0);
        CHECK(EVP_PKEY_verify(verify, sig, n, digest, sizeof(digest)) == 1);
    }
    /* Reusing an operation context must not reuse the signing nonce. */
    n = sizeof(sig);
    repeated_len = sizeof(repeated);
    CHECK(EVP_PKEY_sign(sign, sig, &n, digest, sizeof(digest)) > 0);
    CHECK(EVP_PKEY_sign(sign, repeated, &repeated_len, digest, sizeof(digest)) > 0);
    CHECK(EVP_PKEY_verify(soft_verify, sig, n, digest, sizeof(digest)) == 1);
    CHECK(EVP_PKEY_verify(soft_verify, repeated, repeated_len, digest, sizeof(digest)) == 1);
    CHECK(n != repeated_len || memcmp(sig, repeated, n) != 0);
    ok = 1;
done:
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(verify);
    EVP_PKEY_CTX_free(soft_sign);
    EVP_PKEY_CTX_free(soft_verify);
    EVP_PKEY_CTX_free(copy);
    return ok;
}

static int stream_verify(EVP_PKEY *key, const char *prop, const unsigned char *id, size_t idlen,
    const unsigned char *msg, size_t len, const unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit_ex(ctx, NULL, "SM3", NULL, prop, key, NULL) > 0 &&
        EVP_PKEY_CTX_set1_id(EVP_MD_CTX_get_pkey_ctx(ctx), id, idlen) > 0 &&
        EVP_DigestVerifyUpdate(ctx, msg, len) > 0 &&
        EVP_DigestVerifyFinal(ctx, sig, siglen) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int signature_bounds(EVP_PKEY *key)
{
    EVP_PKEY_CTX *sign = NULL, *verify = NULL;
    ECDSA_SIG *parsed = NULL, *modified = NULL;
    BIGNUM *r = NULL, *s = NULL;
    unsigned char digest[32] = {1}, sig[128], bad[128], *out;
    const unsigned char *in;
    size_t len = sizeof(sig);
    int ok = 0, encoded;

    sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, SW);
    verify = EVP_PKEY_CTX_new_from_pkey(NULL, key, HW);
    CHECK(sign && verify && EVP_PKEY_sign_init(sign) > 0 && EVP_PKEY_verify_init(verify) > 0);
    CHECK(EVP_PKEY_CTX_set_signature_md(sign, EVP_sm3()) > 0);
    CHECK(EVP_PKEY_CTX_set_signature_md(verify, EVP_sm3()) > 0);
    CHECK(EVP_PKEY_sign(sign, sig, &len, digest, sizeof(digest)) > 0);
    CHECK(EVP_PKEY_verify(verify, sig, len, digest, sizeof(digest)) == 1);
    in = sig;
    parsed = d2i_ECDSA_SIG(NULL, &in, len);
    CHECK(parsed);
    for (int i = 0; i < 4; i++) {
        r = BN_dup(ECDSA_SIG_get0_r(parsed));
        s = BN_dup(ECDSA_SIG_get0_s(parsed));
        modified = ECDSA_SIG_new();
        CHECK(r && s && modified);
        if (i >= 2)
            BN_zero(i == 2 ? r : s);
        CHECK(ECDSA_SIG_set0(modified, r, s));
        r = s = NULL;
        CHECK(i2d_ECDSA_SIG(modified, NULL) <= (int)sizeof(bad));
        out = bad;
        encoded = i2d_ECDSA_SIG(modified, &out);
        CHECK(encoded > 0 && bad[0] == 0x30 && bad[1] < 128 && bad[2] == 0x02);
        /* The ECDSA encoder writes unsigned scalars; set the DER sign bit explicitly. */
        if (i < 2) {
            size_t start = i ? 6 + bad[3] : 4;
            CHECK(start < (size_t)encoded);
            bad[start] |= 0x80;
        }
        CHECK(encoded > 0 && EVP_PKEY_verify(verify, bad, encoded, digest, sizeof(digest)) <= 0);
        ERR_clear_error();
        ECDSA_SIG_free(modified);
        modified = NULL;
    }
    ok = 1;
done:
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(parsed);
    ECDSA_SIG_free(modified);
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(verify);
    return ok;
}

static int oneshot_signature(EVP_PKEY *key, size_t len)
{
    unsigned char *msg = OPENSSL_malloc(len ? len : 1), sig[128];
    unsigned char id[] = "KAE one-shot reuse";
    EVP_MD_CTX *sign = EVP_MD_CTX_new(), *verify = EVP_MD_CTX_new(), *copy = EVP_MD_CTX_new();
    EVP_PKEY *other = NULL;
    size_t n;
    int ok = 0;

    CHECK(msg && sign && verify && copy);
    other = sm2_key();
    CHECK(other);
    for (int j = 0; j < 3; j++) {
        EVP_PKEY *chosen = j == 2 ? other : key;
        id[0] = (unsigned char)('A' + j);
        OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, id, j ? sizeof(id) - 1 : 0),
            OSSL_PARAM_END
        };
        CHECK(EVP_MD_CTX_reset(sign) > 0 && EVP_MD_CTX_reset(verify) > 0);
        CHECK(EVP_DigestSignInit_ex(sign, NULL, "SM3", NULL, HW, chosen, params) > 0);
        CHECK(EVP_DigestVerifyInit_ex(verify, NULL, "SM3", NULL, HW, chosen, params) > 0);
        for (int i = 0; i < 5; i++) {
            memset(msg, i + j, len);
            CHECK(EVP_DigestSignInit_ex(sign, NULL, "SM3", NULL, HW, i & 1 ? chosen : NULL, params) > 0);
            CHECK(EVP_DigestVerifyInit_ex(verify, NULL, "SM3", NULL, HW, i & 1 ? chosen : NULL, params) > 0);
            n = 0;
            CHECK(EVP_DigestSign(sign, NULL, &n, msg, len) > 0 && n <= sizeof(sig));
            CHECK(EVP_DigestSign(sign, sig, &n, msg, len) > 0);
            CHECK(EVP_MD_CTX_copy_ex(copy, verify) > 0);
            CHECK(EVP_DigestVerify(verify, sig, n, msg, len) == 1);
            CHECK(stream_verify(chosen, SW, id, params[0].data_size, msg, len, sig, n));
            CHECK(EVP_DigestVerify(copy, sig, n, msg, len) == 1);
        }
    }
    ok = 1;
done:
    OPENSSL_free(msg);
    EVP_MD_CTX_free(sign);
    EVP_MD_CTX_free(verify);
    EVP_MD_CTX_free(copy);
    EVP_PKEY_free(other);
    return ok;
}

static int stream_signature(EVP_PKEY *key, size_t len)
{
    /* Keep message buffers off OpenSSL's 32 KiB ASYNC stack under ASAN. */
    unsigned char *msg = OPENSSL_malloc(len ? len : 1), sig[128];
    const unsigned char id[] = "KAE SM2 interoperability";
    EVP_MD_CTX *ctx = NULL, *copy = NULL;
    int ok = 0;
    size_t n;
    CHECK(msg);
    memset(msg, 0x5a, len);
    for (int j = 0; j < 3; j++) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, (void *)id, j ? sizeof(id) - 1 : 0),
            OSSL_PARAM_END
        };
        ctx = EVP_MD_CTX_new();
        copy = EVP_MD_CTX_new();
        CHECK(ctx && copy);
        CHECK(EVP_DigestSignInit_ex(ctx, NULL, "SM3", NULL, HW, key, NULL) > 0);
        CHECK(EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(ctx), params) > 0);
        CHECK(EVP_DigestSignUpdate(ctx, msg, len / 2) > 0);
        CHECK(EVP_MD_CTX_copy_ex(copy, ctx) > 0);
        CHECK(EVP_DigestSignUpdate(ctx, msg + len / 2, len - len / 2) > 0);
        CHECK(EVP_DigestSignUpdate(copy, msg + len / 2, len - len / 2) > 0);
        for (int k = 0; k < 2; k++) {
            EVP_MD_CTX *chosen = k ? copy : ctx;
            n = 0;
            CHECK(EVP_DigestSignFinal(chosen, NULL, &n) > 0 && n <= sizeof(sig));
            CHECK(EVP_DigestSignFinal(chosen, sig, &n) > 0);
            CHECK(stream_verify(key, SW, id, params[0].data_size, msg, len, sig, n));
            CHECK(stream_verify(key, HW, id, params[0].data_size, msg, len, sig, n));
        }
        EVP_MD_CTX_free(ctx);
        EVP_MD_CTX_free(copy);
        ctx = copy = NULL;
        ctx = EVP_MD_CTX_new();
        CHECK(EVP_DigestSignInit_ex(ctx, NULL, "SM3", NULL, SW, key, NULL) > 0);
        CHECK(EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(ctx), params) > 0);
        CHECK(EVP_DigestSignUpdate(ctx, msg, len) > 0);
        n = sizeof(sig);
        CHECK(EVP_DigestSignFinal(ctx, sig, &n) > 0);
        CHECK(stream_verify(key, HW, id, params[0].data_size, msg, len, sig, n));
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
    CHECK(oneshot_signature(key, len));
    ok = 1;
done:
    OPENSSL_free(msg);
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(copy);
    return ok;
}

static int encryption(EVP_PKEY *key, size_t len, const char *digest)
{
    EVP_PKEY_CTX *enc = NULL, *dec = NULL, *swenc = NULL, *swdec = NULL, *copy = NULL;
    unsigned char msg[1024], cipher[1280], plain[1280];
    size_t n, pn;
    int ok = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, (char *)digest, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES, "provider=default", 0),
        OSSL_PARAM_END
    };
    enc = EVP_PKEY_CTX_new_from_pkey(NULL, key, HW);
    dec = EVP_PKEY_CTX_new_from_pkey(NULL, key, HW);
    swenc = EVP_PKEY_CTX_new_from_pkey(NULL, key, SW);
    swdec = EVP_PKEY_CTX_new_from_pkey(NULL, key, SW);
    CHECK(enc && dec && swenc && swdec);
    CHECK(EVP_PKEY_encrypt_init_ex(enc, params) > 0 && EVP_PKEY_encrypt_init_ex(swenc, params) > 0);
    CHECK(EVP_PKEY_decrypt_init_ex(dec, params) > 0 && EVP_PKEY_decrypt_init_ex(swdec, params) > 0);
    copy = EVP_PKEY_CTX_dup(enc);
    CHECK(copy);
    for (int i = 0; i < 5; i++) {
        memset(msg, i + 7, len);
        n = 0;
        CHECK(EVP_PKEY_encrypt(enc, NULL, &n, msg, len) > 0 && n <= sizeof(cipher));
        CHECK(EVP_PKEY_encrypt(i & 1 ? enc : copy, cipher, &n, msg, len) > 0);
        pn = sizeof(plain);
        CHECK(EVP_PKEY_decrypt(swdec, plain, &pn, cipher, n) > 0 && pn == len && !memcmp(plain, msg, len));
        pn = 0;
        CHECK(EVP_PKEY_decrypt(dec, NULL, &pn, cipher, n) > 0 && pn <= sizeof(plain));
        CHECK(EVP_PKEY_decrypt(dec, plain, &pn, cipher, n) > 0 && pn == len && !memcmp(plain, msg, len));
        n = sizeof(cipher);
        CHECK(EVP_PKEY_encrypt(swenc, cipher, &n, msg, len) > 0);
        pn = sizeof(plain);
        CHECK(EVP_PKEY_decrypt(dec, plain, &pn, cipher, n) > 0 && pn == len && !memcmp(plain, msg, len));
    }
    ok = 1;
done:
    EVP_PKEY_CTX_free(enc);
    EVP_PKEY_CTX_free(dec);
    EVP_PKEY_CTX_free(swenc);
    EVP_PKEY_CTX_free(swdec);
    EVP_PKEY_CTX_free(copy);
    return ok;
}

static EVP_PKEY *dh_key(size_t bits, int named, const char *prop)
{
    EVP_PKEY_CTX *ctx = NULL, *from = NULL;
    EVP_PKEY *params_key = NULL, *key = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *p = NULL, *g = NULL;
    char group[32];
    if (named) {
        snprintf(group, sizeof(group), "ffdhe%zu", bits);
        OSSL_PARAM group_params[] = { OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0), OSSL_PARAM_END };
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", prop);
        if (ctx && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_CTX_set_params(ctx, group_params) > 0)
            EVP_PKEY_generate(ctx, &key);
    } else {
        const unsigned char *bytes = bits == 2048 ? dhtest_2048 : bits == 3072 ? dhtest_3072 : dhtest_4096;
        p = BN_bin2bn(bytes, bits / 8, NULL);
        g = BN_new();
        bld = OSSL_PARAM_BLD_new();
        CHECK(p && g && bld && BN_set_word(g, 2));
        CHECK(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p) &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g));
        params = OSSL_PARAM_BLD_to_param(bld);
        from = EVP_PKEY_CTX_new_from_name(NULL, "DH", prop);
        CHECK(params && from && EVP_PKEY_fromdata_init(from) > 0 &&
            EVP_PKEY_fromdata(from, &params_key, EVP_PKEY_KEY_PARAMETERS, params) > 0);
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params_key, prop);
        CHECK(ctx && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_generate(ctx, &key) > 0);
    }
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(from);
    EVP_PKEY_free(params_key);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(g);
    return key;
}

static int dh_test(size_t bits, int named)
{
    EVP_PKEY *a = NULL, *b = NULL;
    EVP_PKEY_CTX *actx = NULL, *bctx = NULL, *copy = NULL;
    unsigned char out[1024], reference[1024];
    int ok = 0;
    size_t n, rn;

    a = dh_key(bits, named, HW);
    b = dh_key(bits, named, SW);
    CHECK(a && b);
    CHECK(!strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(a)), "kae_provider"));
    actx = EVP_PKEY_CTX_new_from_pkey(NULL, a, HW);
    bctx = EVP_PKEY_CTX_new_from_pkey(NULL, b, SW);
    CHECK(actx && bctx && EVP_PKEY_derive_init(actx) > 0 && EVP_PKEY_derive_init(bctx) > 0);
    CHECK(EVP_PKEY_derive_set_peer(actx, b) > 0 && EVP_PKEY_derive_set_peer(bctx, a) > 0);
    for (int pad = 0; pad <= 1; pad++) {
        CHECK(EVP_PKEY_CTX_set_dh_pad(actx, pad) > 0 && EVP_PKEY_CTX_set_dh_pad(bctx, pad) > 0);
        copy = EVP_PKEY_CTX_dup(actx);
        CHECK(copy);
        rn = sizeof(reference);
        CHECK(EVP_PKEY_derive(bctx, reference, &rn) > 0);
        for (int i = 0; i < 5; i++) {
            n = 0;
            CHECK(EVP_PKEY_derive(actx, NULL, &n) > 0 && n <= sizeof(out));
            CHECK(EVP_PKEY_derive(i & 1 ? actx : copy, out, &n) > 0 && n == rn && !CRYPTO_memcmp(out, reference, n));
        }
        EVP_PKEY_CTX_free(copy);
        copy = NULL;
    }
    ok = 1;
done:
    OPENSSL_cleanse(out, sizeof(out));
    OPENSSL_cleanse(reference, sizeof(reference));
    EVP_PKEY_CTX_free(actx);
    EVP_PKEY_CTX_free(bctx);
    EVP_PKEY_CTX_free(copy);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    return ok;
}

static int perform(void *opaque)
{
    struct operation *op = *(struct operation **)opaque;
    EVP_PKEY *key = NULL;
    int ok;
    if (!strcmp(op->algorithm, "rand-private") || !strcmp(op->algorithm, "rand-public")) {
        unsigned char bytes[8193];
        bytes[op->size] = 0x5a;
        for (int i = 0; i < 8; i++) {
            int rc = !strcmp(op->algorithm, "rand-private") ?
                RAND_priv_bytes(bytes, (int)op->size) : RAND_bytes(bytes, (int)op->size);
            if (rc != 1 || bytes[op->size] != 0x5a) {
                OPENSSL_cleanse(bytes, sizeof(bytes));
                return 0;
            }
        }
        OPENSSL_cleanse(bytes, sizeof(bytes));
        return 1;
    }
    if (!strncmp(op->algorithm, "dh", 2))
        return dh_test(op->size, !strcmp(op->algorithm, "dh"));
    key = sm2_key();
    if (!key || strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(key)), "kae_provider")) {
        EVP_PKEY_free(key);
        return 0;
    }
    if (!strcmp(op->algorithm, "sm2-sign"))
        ok = raw_signature(key);
    else if (!strcmp(op->algorithm, "sm2-bounds"))
        ok = signature_bounds(key);
    else if (!strcmp(op->algorithm, "sm2-stream"))
        ok = stream_signature(key, op->size);
    else
        ok = encryption(key, op->size, !strcmp(op->algorithm, "sm2-sha256") ? "SHA256" : "SM3");
    EVP_PKEY_free(key);
    return ok;
}

/* Match OpenSSL's ASYNC_JOB API, with one independently owned context per job. */
static int execute(struct operation *ops, int count, int asynchronous, unsigned long *pauses)
{
    ASYNC_JOB *jobs[32] = {0};
    ASYNC_WAIT_CTX *wait[32] = {0};
    int done[32] = {0}, ready[32], results[32] = {0};
    int remaining = count, ok = 1;
    double deadline = seconds() + 60;
    if (!asynchronous) {
        struct operation *op = ops;
        return perform(&op);
    }
    if (!ASYNC_init_thread(count, count))
        return 0;
    for (int i = 0; i < count; ++i) {
        ready[i] = 1;
        if (!(wait[i] = ASYNC_WAIT_CTX_new()))
            _Exit(5);
    }
    while (remaining) {
        struct pollfd fds[256];
        int owner[256];
        nfds_t nfds = 0;
        for (int i = 0; i < count; ++i) {
            struct operation *op = &ops[i];
            if (done[i])
                continue;
            if (ready[i]) {
                int status = ASYNC_start_job(&jobs[i], wait[i], &results[i],
                                             perform, &op, sizeof(op));
                ready[i] = 0;
                if (status == ASYNC_FINISH) {
                    done[i] = 1;
                    --remaining;
                    ok = ok && results[i];
                    continue;
                }
                if (status != ASYNC_PAUSE)
                    _Exit(6);
                ++*pauses;
            }
            OSSL_ASYNC_FD one[8];
            size_t n = 0;
            if (!ASYNC_WAIT_CTX_get_all_fds(wait[i], NULL, &n) || n > 8 ||
                !ASYNC_WAIT_CTX_get_all_fds(wait[i], one, &n))
                _Exit(7);
            if (!n)
                ready[i] = 1;
            for (size_t j = 0; j < n; ++j) {
                fds[nfds] = (struct pollfd){one[j], POLLIN, 0};
                owner[nfds++] = i;
            }
        }
        if (nfds) {
            int rc = poll(fds, nfds, 1000);
            if (rc < 0)
                _Exit(8);
            for (nfds_t j = 0; j < nfds; ++j) {
                if (fds[j].revents & POLLIN)
                    ready[owner[j]] = 1;
                if (fds[j].revents & (POLLERR | POLLHUP | POLLNVAL))
                    _Exit(9);
            }
        }
        if (seconds() > deadline)
            _Exit(124);
    }
    for (int i = 0; i < count; ++i)
        ASYNC_WAIT_CTX_free(wait[i]);
    ASYNC_cleanup_thread();
    return ok;
}


int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *kae = NULL;
    struct operation ops[32] = {0};
    unsigned long pauses = 0;
    int count, ok = 0, asynchronous;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 4) {
        fprintf(stderr, "Usage: %s sm2-sign|sm2-stream|sm2-crypt|sm2-sha256|sm2-bounds|dh|dh-pg|rand-private|rand-public SIZE sync|async|async32\n", argv[0]);
        return 2;
    }
    if ((strcmp(argv[1], "sm2-sign") && strcmp(argv[1], "sm2-stream") &&
         strcmp(argv[1], "sm2-crypt") && strcmp(argv[1], "sm2-sha256") &&
         strcmp(argv[1], "sm2-bounds") && strcmp(argv[1], "dh") && strcmp(argv[1], "dh-pg") &&
         strcmp(argv[1], "rand-private") && strcmp(argv[1], "rand-public")) ||
        (strcmp(argv[3], "sync") && strcmp(argv[3], "async") && strcmp(argv[3], "async32")))
        return 2;
    count = !strcmp(argv[3], "async32") ? 32 : 1;
    asynchronous = strcmp(argv[3], "sync") != 0;
    size_t size = strtoul(argv[2], NULL, 10);
    if (size > 8192 || (!strncmp(argv[1], "sm2", 3) && size > 1024) ||
        (!strncmp(argv[1], "dh", 2) && size != 2048 && size != 3072 && size != 4096 && size != 6144 && size != 8192) ||
        (!strcmp(argv[1], "dh-pg") && size > 4096))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    if (def == NULL || kae == NULL)
        goto done;
    for (int i = 0; i < count; i++) {
        ops[i].algorithm = argv[1];
        ops[i].size = size;
        ops[i].job = i;
    }
    ok = execute(ops, count, asynchronous, &pauses);
    printf("%s algorithm=%s size=%zu mode=%s jobs=%d async_pauses=%lu\n",
        ok ? "PASS" : "FAIL", argv[1], size, argv[3], count, pauses);
done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    OSSL_PROVIDER_unload(kae);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
