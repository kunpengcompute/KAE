/* Copyright 2026 Huawei Technologies Co.,Ltd. SPDX-License-Identifier: Apache-2.0 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/async.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dh_vectors.h"

struct operation {
    EVP_PKEY *key, *peer;
    EVP_PKEY_CTX *ctx;
    unsigned char expected[512], output[512];
    size_t size;
    double deadline;
    unsigned long count;
};

static double seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* Fixed, public benchmark inputs only. Never use these exponents as real keys. */
static BIGNUM *test_exponent(int bits, int seed)
{
    unsigned char bytes[64];
    for (int i = 0; i < bits / 8; ++i)
        bytes[i] = (unsigned char)(seed * 17 + i * 13 + 1);
    bytes[0] |= 0x80;
    return BN_bin2bn(bytes, bits / 8, NULL);
}

static EVP_PKEY *make_key(const BIGNUM *p, const BIGNUM *g,
                         const BIGNUM *pub, const BIGNUM *priv, ENGINE *engine)
{
    EVP_PKEY *key = NULL;
    if (engine) {
        DH *dh = DH_new();
        BIGNUM *dp = BN_dup(p), *dg = BN_dup(g);
        BIGNUM *dy = BN_dup(pub), *dx = priv ? BN_dup(priv) : NULL;
        if (!dh || !dp || !dg || !dy || (priv && !dx))
            goto legacy_done;
        if (!DH_set0_pqg(dh, dp, NULL, dg))
            goto legacy_done;
        dp = dg = NULL;
        if (!DH_set0_key(dh, dy, dx))
            goto legacy_done;
        dy = dx = NULL;
        if (!DH_set_method(dh, ENGINE_get_DH(engine)) || DH_get0_q(dh))
            goto legacy_done;
        key = EVP_PKEY_new();
        if (key && !EVP_PKEY_set1_DH(key, dh)) {
            EVP_PKEY_free(key);
            key = NULL;
        }
legacy_done:
        BN_free(dp);
        BN_free(dg);
        BN_free(dy);
        BN_clear_free(dx);
        DH_free(dh);
        return key;
    }
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *from = NULL;
    BIGNUM *q = NULL;
    if (!builder || !OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_FFC_P, p) ||
        !OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_FFC_G, g) ||
        !OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PUB_KEY, pub) ||
        (priv && !OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, priv)))
        goto provider_done;
    params = OSSL_PARAM_BLD_to_param(builder);
    from = EVP_PKEY_CTX_new_from_name(NULL, "DH", "provider=kae_provider");
    if (!params || !from || EVP_PKEY_fromdata_init(from) <= 0 ||
        EVP_PKEY_fromdata(from, &key, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) <= 0)
        goto provider_error;
    if (!EVP_PKEY_get0_provider(key) ||
        strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(key)), "kae_provider") ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_FFC_Q, &q) || q)
        goto provider_error;
    ERR_clear_error();
    goto provider_done;
provider_error:
    EVP_PKEY_free(key);
    key = NULL;
provider_done:
    BN_free(q);
    EVP_PKEY_CTX_free(from);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    return key;
}

static int prepare(struct operation *op, int bits, int index, ENGINE *engine)
{
    const unsigned char *bytes = bits == 2048 ? dhtest_2048 :
                                 bits == 3072 ? dhtest_3072 : dhtest_4096;
    int priv_bits = bits == 2048 ? 256 : bits == 3072 ? 288 : 336;
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *p = BN_bin2bn(bytes, bits / 8, NULL), *g = BN_new();
    BIGNUM *x = test_exponent(priv_bits, index + 1);
    BIGNUM *peer_x = test_exponent(priv_bits, index + 67);
    BIGNUM *pub = BN_new(), *peer_pub = BN_new(), *secret = BN_new();
    int ok = 0;
    op->size = bits / 8;
    if (!bnctx || !p || !g || !x || !peer_x || !pub || !peer_pub || !secret ||
        !BN_set_word(g, 2) || !BN_mod_exp(pub, g, x, p, bnctx) ||
        !BN_mod_exp(peer_pub, g, peer_x, p, bnctx) ||
        !BN_mod_exp(secret, peer_pub, x, p, bnctx) ||
        BN_bn2binpad(secret, op->expected, (int)op->size) != (int)op->size)
        goto done;
    op->key = make_key(p, g, pub, x, engine);
    op->peer = make_key(p, g, peer_pub, NULL, engine);
    if (!op->key || !op->peer)
        goto done;
    op->ctx = engine ? EVP_PKEY_CTX_new(op->key, engine) :
        EVP_PKEY_CTX_new_from_pkey(NULL, op->key, "provider=kae_provider");
    if (!op->ctx || EVP_PKEY_derive_init(op->ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(op->ctx, op->peer) <= 0 ||
        EVP_PKEY_CTX_set_dh_pad(op->ctx, 1) <= 0)
        goto done;
    ok = 1;
done:
    BN_free(p);
    BN_free(g);
    BN_clear_free(x);
    BN_clear_free(peer_x);
    BN_free(pub);
    BN_free(peer_pub);
    BN_clear_free(secret);
    BN_CTX_free(bnctx);
    return ok;
}

static int perform(void *opaque)
{
    struct operation *op = *(struct operation **)opaque;
    do {
        size_t n = op->size;
        if (EVP_PKEY_derive(op->ctx, op->output, &n) <= 0 || n != op->size)
            return 0;
        ++op->count;
    } while (seconds() < op->deadline);
    return CRYPTO_memcmp(op->output, op->expected, op->size) == 0;
}

static int execute(struct operation *ops, int count, unsigned long *pauses)
{
    ASYNC_JOB *jobs[32] = {0};
    ASYNC_WAIT_CTX *wait[32] = {0};
    int done[32] = {0}, ready[32], results[32] = {0};
    int remaining = count, ok = 1;
    double timeout = seconds() + 30;
    if (count == 1) {
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
            if (rc < 0 && errno != EINTR)
                _Exit(8);
            for (nfds_t j = 0; j < nfds; ++j) {
                if (fds[j].revents & POLLIN)
                    ready[owner[j]] = 1;
                if (fds[j].revents & (POLLERR | POLLHUP | POLLNVAL))
                    _Exit(9);
            }
        }
        if (seconds() > timeout)
            _Exit(124);
    }
    for (int i = 0; i < count; ++i)
        ASYNC_WAIT_CTX_free(wait[i]);
    ASYNC_cleanup_thread();
    return ok;
}

int main(int argc, char **argv)
{
    struct operation ops[32] = {0};
    OSSL_PROVIDER *def = NULL, *provider = NULL;
    ENGINE *engine = NULL;
    unsigned long pauses = 0, total = 0;
    int ok = 0, initialized = 0;
    if (argc != 5) {
        fprintf(stderr, "Usage: %s BITS sync|async32 engine|provider SECONDS\n", argv[0]);
        return 2;
    }
    int bits = atoi(argv[1]), count = !strcmp(argv[2], "async32") ? 32 : 1;
    double duration = atof(argv[4]);
    if ((bits != 2048 && bits != 3072 && bits != 4096) || duration < 0 || duration > 10 ||
        (strcmp(argv[2], "sync") && strcmp(argv[2], "async32")) ||
        (strcmp(argv[3], "engine") && strcmp(argv[3], "provider")))
        return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    def = OSSL_PROVIDER_load(NULL, "default");
    if (!def)
        goto done;
    if (!strcmp(argv[3], "engine")) {
        engine = ENGINE_by_id("kae");
        if (!engine || !(initialized = ENGINE_init(engine)))
            goto done;
    } else if (!(provider = OSSL_PROVIDER_load(NULL, "kae_provider"))) {
        goto done;
    }
    for (int i = 0; i < count; ++i)
        if (!prepare(&ops[i], bits, i, engine))
            goto done;
    printf("PARAM bits=%d q_present=0 g=2 private_bits=%d jobs=%d backend=%s source=openssl-speed-dhtest\n",
           bits, bits == 2048 ? 256 : bits == 3072 ? 288 : 336, count, argv[3]);
    double warmup_end = seconds() + (duration > 0 ? 0.3 : 0);
    for (int i = 0; i < count; ++i)
        ops[i].deadline = warmup_end;
    if (!execute(ops, count, &pauses))
        goto done;
    pauses = 0;
    double start = seconds();
    for (int i = 0; i < count; ++i) {
        ops[i].count = 0;
        ops[i].deadline = start + duration;
    }
    if (!execute(ops, count, &pauses))
        goto done;
    double elapsed = seconds() - start;
    for (int i = 0; i < count; ++i) {
        if (!ops[i].count)
            goto done;
        total += ops[i].count;
    }
    printf("BENCH dh-pg bits=%d mode=%s backend=%s operations=%lu elapsed=%.9f ops_per_second=%.6f pauses=%lu\n",
           bits, argv[2], argv[3], total, elapsed, total / elapsed, pauses);
    printf("PASS q_present=0 same-inputs=1 padded-secret-matches-software=1 verified-jobs=%d\n", count);
    ok = 1;
done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    for (int i = 0; i < 32; ++i) {
        EVP_PKEY_CTX_free(ops[i].ctx);
        EVP_PKEY_free(ops[i].key);
        EVP_PKEY_free(ops[i].peer);
        OPENSSL_cleanse(ops[i].expected, sizeof(ops[i].expected));
        OPENSSL_cleanse(ops[i].output, sizeof(ops[i].output));
    }
    if (initialized)
        ENGINE_finish(engine);
    ENGINE_free(engine);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
