/* Copyright 2026 Huawei Technologies Co.,Ltd. SPDX-License-Identifier: Apache-2.0 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/async.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "dh_vectors.h"

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "FAIL line=%d expression=%s\n", __LINE__, #x); \
    ERR_print_errors_fp(stderr); exit(1); } } while (0)
#define CAPACITY 32768

static ENGINE *engine;
static const char *backend, *keytype, *prop;
static const char *fixture_password;

struct operation {
    EVP_PKEY *key, *pub, *peer_key, *peer_pub;
    EVP_PKEY_CTX *ctx;
    unsigned char plain[CAPACITY], input[CAPACITY], output[CAPACITY];
    size_t size, input_len, output_len;
    int decrypt, padding, check_only;
    double deadline;
    unsigned long count;
};

static double monotime(void)
{
    struct timespec ts;
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void pathname(char *out, size_t capacity, const char *dir, const char *name, const char *suffix)
{
    int n = snprintf(out, capacity, "%s/%s.%s", dir, name, suffix);
    REQUIRE(n > 0 && (size_t)n < capacity);
}

static EVP_PKEY *generate(int bits)
{
    EVP_PKEY *key = NULL;
    if (!strcmp(keytype, "DH")) {
        const unsigned char *bytes = bits == 2048 ? dhtest_2048 : bits == 3072 ? dhtest_3072 : dhtest_4096;
        DH *dh = DH_new();
        BIGNUM *p = BN_bin2bn(bytes, bits / 8, NULL), *g = BN_new();
        REQUIRE(dh && p && g && BN_set_word(g, 2));
        REQUIRE(DH_set0_pqg(dh, p, NULL, g));
        REQUIRE(DH_set_length(dh, bits == 2048 ? 256 : bits == 3072 ? 288 : 336));
        REQUIRE(DH_generate_key(dh) && !DH_get0_q(dh));
        key = EVP_PKEY_new();
        REQUIRE(key && EVP_PKEY_assign_DH(key, dh));
    } else {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, keytype, "provider=default");
        REQUIRE(ctx && EVP_PKEY_keygen_init(ctx) > 0);
        if (!strcmp(keytype, "RSA"))
            REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0);
        REQUIRE(EVP_PKEY_generate(ctx, &key) > 0);
        EVP_PKEY_CTX_free(ctx);
    }
    return key;
}

static void write_key(EVP_PKEY *key, const char *dir, const char *name)
{
    char path[4096];
    const char *suffixes[] = {"pem", "der", "enc.pem", "enc.der", "pub.pem", "pub.der"};
    for (int i = 0; i < 6; i++) {
        pathname(path, sizeof(path), dir, name, suffixes[i]);
        BIO *out = BIO_new_file(path, "wb");
        const EVP_CIPHER *cipher = i == 2 || i == 3 ? EVP_aes_256_cbc() : NULL;
        REQUIRE(out);
        if (i < 4) {
            int ok = i & 1 ? i2d_PKCS8PrivateKey_bio(out, key, cipher,
                fixture_password, (int)strlen(fixture_password), NULL, NULL) :
                PEM_write_bio_PKCS8PrivateKey(out, key, cipher,
                fixture_password, (int)strlen(fixture_password), NULL, NULL);
            REQUIRE(ok);
        } else {
            REQUIRE(i == 4 ? PEM_write_bio_PUBKEY(out, key) : i2d_PUBKEY_bio(out, key));
        }
        REQUIRE(BIO_free(out));
    }
}

static EVP_PKEY *read_key(const char *dir, const char *name, const char *format, int public_only)
{
    char path[4096];
    int der = strstr(format, "der") != NULL;
    const char *suffix = public_only ? der ? "pub.der" : "pub.pem" : format;
    EVP_PKEY *key = NULL;
    pathname(path, sizeof(path), dir, name, suffix);
    BIO *in = BIO_new_file(path, "rb");
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&key, der ? "DER" : "PEM", NULL,
        NULL, public_only ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, NULL, "provider=default");
    REQUIRE(in && ctx && OSSL_DECODER_CTX_set_passphrase(ctx,
        (const unsigned char *)fixture_password, strlen(fixture_password)));
    REQUIRE(OSSL_DECODER_from_bio(ctx, in) && key && EVP_PKEY_is_a(key, keytype));
    OSSL_DECODER_CTX_free(ctx);
    BIO_free(in);
    if (!strcmp(keytype, "DH")) {
        BIGNUM *q = NULL;
        REQUIRE(!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_FFC_Q, &q) && !q);
        ERR_clear_error();
    }
    if (public_only) {
        BIGNUM *secret = NULL;
        const char *param = !strcmp(keytype, "RSA") ? OSSL_PKEY_PARAM_RSA_D : OSSL_PKEY_PARAM_PRIV_KEY;
        REQUIRE(!EVP_PKEY_get_bn_param(key, param, &secret) && !secret);
        ERR_clear_error();
    }
    return key;
}

static void selected(EVP_PKEY_CTX *ctx, int soft)
{
    const OSSL_PROVIDER *p = EVP_PKEY_CTX_get0_provider(ctx);
    if (engine && !soft)
        REQUIRE(p == NULL);
    else
        REQUIRE(p && !strcmp(OSSL_PROVIDER_get0_name(p), soft ? "default" :
            !strcmp(backend, "provider") ? "kae_provider" : "default"));
}

static EVP_PKEY_CTX *newctx(EVP_PKEY *key, int soft)
{
    EVP_PKEY_CTX *ctx = engine && !soft ? EVP_PKEY_CTX_new(key, engine) :
        EVP_PKEY_CTX_new_from_pkey(NULL, key, soft ? "provider=default" : prop);
    REQUIRE(ctx);
    return ctx;
}

static EVP_PKEY_CTX *cryptctx(EVP_PKEY *key, int decrypt, int padding, int soft)
{
    EVP_PKEY_CTX *ctx = newctx(key, soft);
    REQUIRE((decrypt ? EVP_PKEY_decrypt_init(ctx) : EVP_PKEY_encrypt_init(ctx)) > 0);
    selected(ctx, soft);
    if (!strcmp(keytype, "RSA")) {
        REQUIRE(EVP_PKEY_CTX_set_rsa_padding(ctx, padding) > 0);
        if (padding == RSA_PKCS1_OAEP_PADDING) {
            REQUIRE(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0);
            REQUIRE(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0);
        }
    }
    return ctx;
}

static void crypt(EVP_PKEY_CTX *ctx, int decrypt, unsigned char *out, size_t *len,
                  const unsigned char *in, size_t inlen)
{
    REQUIRE((decrypt ? EVP_PKEY_decrypt(ctx, out, len, in, inlen) :
        EVP_PKEY_encrypt(ctx, out, len, in, inlen)) > 0);
}

static void sm2_signatures(struct operation *op)
{
    const char id[] = "kae-file-sm2-id";
    unsigned char sig[256];
    for (int direction = 0; direction < 2; direction++) {
        int sign_soft = direction, verify_soft = !direction;
        EVP_MD_CTX *sign = EVP_MD_CTX_new(), *verify = EVP_MD_CTX_new();
        EVP_PKEY_CTX *sp = newctx(op->key, sign_soft), *vp = newctx(op->pub, verify_soft);
        size_t n = sizeof(sig);
        REQUIRE(sign && verify && EVP_PKEY_CTX_set1_id(sp, id, strlen(id)) > 0 &&
            EVP_PKEY_CTX_set1_id(vp, id, strlen(id)) > 0);
        EVP_MD_CTX_set_pkey_ctx(sign, sp);
        EVP_MD_CTX_set_pkey_ctx(verify, vp);
        REQUIRE(EVP_DigestSignInit(sign, NULL, EVP_sm3(), engine && !sign_soft ? engine : NULL, op->key) > 0);
        REQUIRE(EVP_DigestVerifyInit(verify, NULL, EVP_sm3(), engine && !verify_soft ? engine : NULL, op->pub) > 0);
        selected(sp, sign_soft);
        selected(vp, verify_soft);
        REQUIRE(EVP_DigestSignUpdate(sign, op->plain, op->size) > 0 && EVP_DigestSignFinal(sign, sig, &n) > 0);
        REQUIRE(EVP_DigestVerifyUpdate(verify, op->plain, op->size) > 0 && EVP_DigestVerifyFinal(verify, sig, n) == 1);
        EVP_MD_CTX_free(sign);
        EVP_MD_CTX_free(verify);
        EVP_PKEY_CTX_free(sp);
        EVP_PKEY_CTX_free(vp);
    }
}

static void dh_check(struct operation *op)
{
    for (int pad = 0; pad <= 1; pad++) {
        EVP_PKEY_CTX *a = newctx(op->key, 0), *b = newctx(op->peer_key, 1);
        size_t an = sizeof(op->output), bn = sizeof(op->input);
        REQUIRE(EVP_PKEY_derive_init(a) > 0 && EVP_PKEY_derive_init(b) > 0);
        selected(a, 0);
        selected(b, 1);
        REQUIRE(EVP_PKEY_CTX_set_dh_pad(a, pad) > 0 && EVP_PKEY_CTX_set_dh_pad(b, pad) > 0);
        REQUIRE(EVP_PKEY_derive_set_peer(a, op->peer_pub) > 0 && EVP_PKEY_derive_set_peer(b, op->pub) > 0);
        REQUIRE(EVP_PKEY_derive(a, op->output, &an) > 0 && EVP_PKEY_derive(b, op->input, &bn) > 0);
        REQUIRE(an && an == bn && CRYPTO_memcmp(op->output, op->input, an) == 0);
        EVP_PKEY_CTX_free(a);
        EVP_PKEY_CTX_free(b);
    }
}

static int perform(void *opaque)
{
    struct operation *op = *(struct operation **)opaque;
    if (op->check_only) {
        if (!strcmp(keytype, "DH")) {
            dh_check(op);
        } else {
            for (int direction = 0; direction < 2; direction++) {
                EVP_PKEY_CTX *enc = cryptctx(op->pub, 0, op->padding, direction);
                EVP_PKEY_CTX *dec = cryptctx(op->key, 1, op->padding, !direction);
                size_t cn = sizeof(op->input), pn = sizeof(op->output);
                crypt(enc, 0, op->input, &cn, op->plain, op->size);
                crypt(dec, 1, op->output, &pn, op->input, cn);
                REQUIRE(pn == op->size && !CRYPTO_memcmp(op->output, op->plain, pn));
                EVP_PKEY_CTX_free(enc);
                EVP_PKEY_CTX_free(dec);
            }
            if (!strcmp(keytype, "SM2"))
                sm2_signatures(op);
        }
        op->count++;
        return 1;
    }
    do {
        op->output_len = sizeof(op->output);
        crypt(op->ctx, op->decrypt, op->output, &op->output_len, op->input, op->input_len);
        op->count++;
    } while (monotime() < op->deadline);
    return 1;
}

static unsigned long execute(struct operation *ops, int count)
{
    ASYNC_JOB *jobs[32] = {0};
    ASYNC_WAIT_CTX *wait[32] = {0};
    int done[32] = {0}, ready[32], results[32] = {0}, remaining = count;
    unsigned long pauses = 0;
    double deadline = monotime() + 120;
    if (count == 1) {
        struct operation *op = ops;
        REQUIRE(perform(&op) == 1);
        return 0;
    }
    REQUIRE(ASYNC_init_thread(count, count));
    for (int i = 0; i < count; i++) {
        ready[i] = 1;
        REQUIRE((wait[i] = ASYNC_WAIT_CTX_new()) != NULL);
    }
    while (remaining) {
        struct pollfd fds[256];
        int owner[256];
        nfds_t nfds = 0;
        for (int i = 0; i < count; i++) {
            struct operation *op = &ops[i];
            if (done[i])
                continue;
            if (ready[i]) {
                int status = ASYNC_start_job(&jobs[i], wait[i], &results[i], perform, &op, sizeof(op));
                ready[i] = 0;
                if (status == ASYNC_FINISH) {
                    REQUIRE(results[i] == 1);
                    done[i] = 1;
                    remaining--;
                    continue;
                }
                REQUIRE(status == ASYNC_PAUSE);
                pauses++;
            }
            OSSL_ASYNC_FD one[8];
            size_t n = 0;
            REQUIRE(ASYNC_WAIT_CTX_get_all_fds(wait[i], NULL, &n) && n <= 8);
            REQUIRE(ASYNC_WAIT_CTX_get_all_fds(wait[i], one, &n));
            if (!n)
                ready[i] = 1;
            for (size_t j = 0; j < n; j++) {
                fds[nfds] = (struct pollfd){one[j], POLLIN, 0};
                owner[nfds++] = i;
            }
        }
        if (nfds) {
            int rc = poll(fds, nfds, 1000);
            REQUIRE(rc >= 0 || errno == EINTR);
            for (nfds_t j = 0; rc > 0 && j < nfds; j++) {
                REQUIRE(!(fds[j].revents & (POLLERR | POLLHUP | POLLNVAL)));
                if (fds[j].revents & POLLIN)
                    ready[owner[j]] = 1;
            }
        }
        REQUIRE(monotime() < deadline);
    }
    for (int i = 0; i < count; i++)
        ASYNC_WAIT_CTX_free(wait[i]);
    ASYNC_cleanup_thread();
    return pauses;
}

static void benchmark(struct operation *ops, int count, double duration, const char *algorithm,
                      const char *action, const char *mode)
{
    for (int i = 0; i < count; i++) {
        struct operation *op = &ops[i];
        op->check_only = 0;
        op->ctx = cryptctx(op->decrypt ? op->key : op->pub, op->decrypt, op->padding, 0);
        if (op->decrypt) {
            EVP_PKEY_CTX *enc = cryptctx(op->pub, 0, op->padding, 1);
            op->input_len = sizeof(op->input);
            crypt(enc, 0, op->input, &op->input_len, op->plain, op->size);
            EVP_PKEY_CTX_free(enc);
        } else {
            memcpy(op->input, op->plain, op->size);
            op->input_len = op->size;
        }
    }
    double until = monotime() + 0.3;
    for (int i = 0; i < count; i++)
        ops[i].deadline = until;
    execute(ops, count);
    double start = monotime();
    for (int i = 0; i < count; i++) {
        ops[i].count = 0;
        ops[i].deadline = start + duration;
    }
    unsigned long pauses = execute(ops, count), total = 0;
    double elapsed = monotime() - start;
    for (int i = 0; i < count; i++) {
        struct operation *op = &ops[i];
        REQUIRE(op->count > 0);
        total += op->count;
        if (op->decrypt) {
            REQUIRE(op->output_len == op->size && !CRYPTO_memcmp(op->output, op->plain, op->size));
        } else {
            EVP_PKEY_CTX *dec = cryptctx(op->key, 1, op->padding, 1);
            size_t n = sizeof(op->input);
            crypt(dec, 1, op->input, &n, op->output, op->output_len);
            REQUIRE(n == op->size && !CRYPTO_memcmp(op->input, op->plain, n));
            EVP_PKEY_CTX_free(dec);
        }
    }
    printf("BENCH pkey-file algorithm=%s action=%s backend=%s mode=%s bytes=%zu operations=%lu elapsed=%.9f ops_per_second=%.6f pauses=%lu\n",
        algorithm, action, backend, mode, ops[0].size, total, elapsed, total / elapsed, pauses);
}

int main(int argc, char **argv)
{
    const char *alg = argc > 2 ? argv[2] : "";
    int bits = 0;
    if (!strcmp(alg, "sm2")) {
        keytype = "SM2";
        bits = 256;
    } else if (!strncmp(alg, "rsa", 3)) {
        keytype = "RSA";
        bits = atoi(alg + 3);
        REQUIRE(bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096);
    } else if (!strncmp(alg, "dh", 2)) {
        keytype = "DH";
        bits = atoi(alg + 2);
        REQUIRE(bits == 2048 || bits == 3072 || bits == 4096);
    } else {
        fprintf(stderr, "Usage: %s prepare ALG DIRECTORY\n       %s check|bench ALG FORMAT BACKEND MODE DIRECTORY ACTION BYTES SECONDS\n",
            argv[0], argv[0]);
        return 2;
    }
    fixture_password = getenv("KAE_TEST_FILE_PASSPHRASE");
    if (fixture_password == NULL || fixture_password[0] == '\0') {
        fprintf(stderr, "Set KAE_TEST_FILE_PASSPHRASE to the same value for prepare and check/bench\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    umask(0077);
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default"), *provider = NULL;
    REQUIRE(def);
    if (argc == 4 && !strcmp(argv[1], "prepare")) {
        REQUIRE(mkdir(argv[3], 0700) == 0);
        for (int i = 0; i < 2; i++) {
            EVP_PKEY *key = generate(bits);
            write_key(key, argv[3], i ? "peer" : "key");
            if (!i && !strcmp(keytype, "DH")) {
                char path[4096];
                pathname(path, sizeof(path), argv[3], "parameters", "pem");
                BIO *out = BIO_new_file(path, "wb");
                REQUIRE(out && PEM_write_bio_Parameters(out, key));
                BIO_free(out);
            }
            EVP_PKEY_free(key);
        }
        printf("PASS prepared algorithm=%s private=PKCS8 public=SPKI encrypted=AES-256-CBC\n", alg);
        OSSL_PROVIDER_unload(def);
        return 0;
    }
    REQUIRE(argc == 10 && (!strcmp(argv[1], "check") || !strcmp(argv[1], "bench")));
    REQUIRE(!strcmp(argv[3], "pem") || !strcmp(argv[3], "der") || !strcmp(argv[3], "enc.pem") || !strcmp(argv[3], "enc.der"));
    backend = argv[4];
    REQUIRE(!strcmp(backend, "provider") || !strcmp(backend, "engine") || !strcmp(backend, "default"));
    REQUIRE(!strcmp(argv[5], "sync") || !strcmp(argv[5], "async32"));
    const char *action = argv[7];
    REQUIRE(!strcmp(action, "encrypt") || !strcmp(action, "decrypt") ||
        !strcmp(action, "encrypt-oaep") || !strcmp(action, "decrypt-oaep") || !strcmp(action, "derive"));
    REQUIRE(!strcmp(keytype, "DH") ? !strcmp(action, "derive") : strcmp(action, "derive"));
    prop = !strcmp(backend, "provider") ? "provider=kae_provider" : "provider=default";
    if (!strcmp(backend, "provider"))
        REQUIRE((provider = OSSL_PROVIDER_load(NULL, "kae_provider")) != NULL);
    if (!strcmp(backend, "engine")) {
        engine = ENGINE_by_id("kae");
        /* Legacy RSA/DH need their low-level methods, but a global PKEY default
         * would also intercept the explicitly selected provider reference. */
        REQUIRE(engine && ENGINE_init(engine) && ENGINE_set_default_RSA(engine) &&
            ENGINE_set_default_DH(engine));
    }
    int count = !strcmp(argv[5], "async32") ? 32 : 1;
    size_t size = (size_t)strtoul(argv[8], NULL, 10);
    double duration = strtod(argv[9], NULL);
    REQUIRE(size > 0 && size <= 16384 && duration >= 0 && duration <= 30);
    int is_check = !strcmp(argv[1], "check");
    REQUIRE(is_check || (strcmp(keytype, "DH") && duration > 0));
    EVP_PKEY *key = read_key(argv[6], "key", argv[3], 0), *pub = read_key(argv[6], "key", argv[3], 1);
    EVP_PKEY *peer = read_key(argv[6], "peer", argv[3], 0), *peer_pub = read_key(argv[6], "peer", argv[3], 1);
    REQUIRE(EVP_PKEY_get_bits(key) == bits && EVP_PKEY_eq(key, pub) == 1);
    struct operation *ops = OPENSSL_zalloc(sizeof(*ops) * count);
    REQUIRE(ops);
    for (int i = 0; i < count; i++) {
        ops[i].key = key;
        ops[i].pub = pub;
        ops[i].peer_key = peer;
        ops[i].peer_pub = peer_pub;
        ops[i].size = size;
        ops[i].padding = strstr(action, "oaep") ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
        ops[i].decrypt = !strncmp(action, "decrypt", 7);
        ops[i].check_only = 1;
        for (size_t j = 0; j < size; j++)
            ops[i].plain[j] = (unsigned char)(i * 17 + j * 13 + 5);
    }
    unsigned long pauses = execute(ops, count);
    printf("PASS file-key algorithm=%s format=%s backend=%s mode=%s jobs=%d bytes=%zu pauses=%lu public_only=1 q_present=%s\n",
        alg, argv[3], backend, argv[5], count, size, pauses, !strcmp(keytype, "DH") ? "0" : "na");
    if (!is_check)
        benchmark(ops, count, duration, alg, action, argv[5]);
    for (int i = 0; i < count; i++)
        EVP_PKEY_CTX_free(ops[i].ctx);
    OPENSSL_clear_free(ops, sizeof(*ops) * count);
    EVP_PKEY_free(key);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(peer_pub);
    if (engine) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(def);
    return 0;
}
