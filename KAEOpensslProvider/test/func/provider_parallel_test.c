/* Copyright 2026 Huawei Technologies Co.,Ltd. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/async.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dh_vectors.h"

#define HARD "provider=kae_provider"
#define SOFT "provider=default"
#define MAX_JOBS 32
#define MAX_THREADS 8
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #x); \
    ERR_print_errors_fp(stderr); exit(1); } } while (0)

struct instance {
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *def, *kae;
    const char *properties;
    const char *expected;
    int owned;
};

struct worker;
struct operation {
    struct worker *worker;
    const char *name;
    unsigned int id;
    unsigned long checks;
};

struct worker {
    struct instance *instance;
    pthread_barrier_t *barrier;
    EVP_PKEY *rsa;
    const char *scope;
    unsigned int index, jobs, rounds;
    unsigned long checks, pauses;
};

static const char *algorithms[] = {
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "SM4-CBC",
    "AES-128-ECB", "AES-192-ECB", "AES-256-ECB", "SM4-ECB",
    "AES-128-CTR", "AES-192-CTR", "AES-256-CTR", "SM4-CTR",
    "AES-128-CFB", "AES-192-CFB", "AES-256-CFB", "SM4-CFB",
    "AES-128-OFB", "AES-192-OFB", "AES-256-OFB", "SM4-OFB",
    "AES-128-XTS", "AES-256-XTS", "MD5", "SM3", "rsa2048",
    "sm2", "dh2048", "rand-public", "rand-private"
};

static double monotime(void)
{
    struct timespec ts;
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void fill(unsigned char *out, size_t size, uint32_t seed)
{
    uint32_t state = seed + UINT32_C(0x9e3779b9);
    for (size_t i = 0; i < size; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out[i] = (unsigned char)state;
    }
}

static int is_cipher(const char *name)
{
    return !strncmp(name, "AES-", 4) || !strncmp(name, "SM4-", 4);
}

static int is_digest(const char *name)
{
    return !strcmp(name, "MD5") || !strcmp(name, "SM3");
}

static int valid_scope(const char *name)
{
    if (!strcmp(name, "mixed") || !strcmp(name, "rsa1024") ||
        !strcmp(name, "rsa3072") || !strcmp(name, "rsa4096") ||
        !strcmp(name, "dh3072") || !strcmp(name, "dh4096"))
        return 1;
    for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++)
        if (!strcmp(name, algorithms[i]))
            return 1;
    return 0;
}

static const char *properties(struct operation *op)
{
    if ((is_cipher(op->name) || is_digest(op->name)) && getenv("KAE_TEST_NO_SEC"))
        return "?provider=kae_provider";
    return op->worker->instance->properties;
}

static const char *expected(struct operation *op)
{
    if ((is_cipher(op->name) || is_digest(op->name)) && getenv("KAE_TEST_NO_SEC"))
        return "default";
    return op->worker->instance->expected;
}

static void check_provider(const OSSL_PROVIDER *provider, const char *name)
{
    REQUIRE(provider && !strcmp(OSSL_PROVIDER_get0_name(provider), name));
}

static int cipher_transform(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher,
    unsigned char *out, const unsigned char *in, size_t size,
    const unsigned char *key, const unsigned char *iv, int encrypt)
{
    int used = 0, tail = 0;
    return EVP_CipherInit_ex2(ctx, cipher, key, iv, encrypt, NULL) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_CipherUpdate(ctx, out, &used, in, (int)size) == 1 &&
        EVP_CipherFinal_ex(ctx, out + used, &tail) == 1 &&
        used + tail == (int)size;
}

static void cipher_round(struct operation *op, unsigned int round)
{
    static const size_t sizes[] = {16, 64, 256, 1024, 8192, 16384, 262160};
    struct instance *inst = op->worker->instance;
    size_t size = sizes[round % (sizeof(sizes) / sizeof(sizes[0]))];
    unsigned char key[64], iv[16];
    unsigned char *plain = OPENSSL_malloc(size + 32);
    unsigned char *actual = OPENSSL_malloc(size + 32);
    unsigned char *reference = OPENSSL_malloc(size + 32);
    EVP_CIPHER *hw = EVP_CIPHER_fetch(inst->ctx, op->name, properties(op));
    EVP_CIPHER *sw = EVP_CIPHER_fetch(inst->ctx, op->name, SOFT);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *ref = EVP_CIPHER_CTX_new();
    REQUIRE(plain && actual && reference && hw && sw && ctx && ref);
    check_provider(EVP_CIPHER_get0_provider(hw), expected(op));
    check_provider(EVP_CIPHER_get0_provider(sw), "default");
    fill(key, sizeof(key), op->id * 101 + round);
    fill(iv, sizeof(iv), op->id * 503 + round);
    fill(plain, size, op->id * 1009 + round);
    memset(actual + size, 0x5a, 32);
    REQUIRE(cipher_transform(ref, sw, reference, plain, size, key, iv, 1));
    memcpy(actual, plain, size);
    REQUIRE(cipher_transform(ctx, hw, actual, round & 1 ? actual : plain, size, key, iv, 1));
    REQUIRE(!CRYPTO_memcmp(actual, reference, size));
    REQUIRE(cipher_transform(ctx, hw, actual, actual, size, key, iv, 0));
    REQUIRE(!CRYPTO_memcmp(actual, plain, size));
    for (size_t i = 0; i < 32; i++)
        REQUIRE(actual[size + i] == 0x5a);
    op->checks += 2;
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(ref);
    EVP_CIPHER_free(hw);
    EVP_CIPHER_free(sw);
    OPENSSL_clear_free(plain, size + 32);
    OPENSSL_clear_free(actual, size + 32);
    OPENSSL_clear_free(reference, size + 32);
}

static void digest_round(struct operation *op, unsigned int round)
{
    static const size_t sizes[] = {0, 1, 16, 64, 256, 511, 512, 513,
                                  8191, 8192, 8193, 16384, 524289};
    struct instance *inst = op->worker->instance;
    size_t size = sizes[round % (sizeof(sizes) / sizeof(sizes[0]))];
    unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
    unsigned int an, bn;
    unsigned char *data = OPENSSL_malloc(size + 1);
    EVP_MD *hw = EVP_MD_fetch(inst->ctx, op->name, properties(op));
    EVP_MD *sw = EVP_MD_fetch(inst->ctx, op->name, SOFT);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(), *copy = EVP_MD_CTX_new();
    REQUIRE(data && hw && sw && ctx && copy);
    check_provider(EVP_MD_get0_provider(hw), expected(op));
    check_provider(EVP_MD_get0_provider(sw), "default");
    fill(data, size, op->id * 1009 + round);
    REQUIRE(EVP_Digest(data, size, b, &bn, sw, NULL));
    REQUIRE(EVP_Digest(data, size, a, &an, hw, NULL));
    REQUIRE(an == bn && !CRYPTO_memcmp(a, b, an));
    REQUIRE(EVP_DigestInit_ex2(ctx, hw, NULL));
    REQUIRE(EVP_DigestUpdate(ctx, data, size / 2));
    REQUIRE(EVP_MD_CTX_copy_ex(copy, ctx));
    REQUIRE(EVP_DigestUpdate(copy, data + size / 2, size - size / 2));
    REQUIRE(EVP_DigestFinal_ex(copy, a, &an));
    REQUIRE(an == bn && !CRYPTO_memcmp(a, b, an));
    REQUIRE(EVP_DigestUpdate(ctx, data + size / 2, size - size / 2));
    REQUIRE(EVP_DigestFinal_ex(ctx, a, &an));
    REQUIRE(an == bn && !CRYPTO_memcmp(a, b, an));
    op->checks += 3;
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(copy);
    EVP_MD_free(hw);
    EVP_MD_free(sw);
    OPENSSL_free(data);
}

static EVP_PKEY *generate_key(OSSL_LIB_CTX *libctx, const char *name,
                              const char *prop, int bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, name, prop);
    EVP_PKEY *key = NULL;
    REQUIRE(ctx && EVP_PKEY_keygen_init(ctx) > 0);
    if (!strcmp(name, "RSA"))
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0);
    REQUIRE(EVP_PKEY_generate(ctx, &key) > 0);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static void signature_round(struct operation *op, EVP_PKEY *key, unsigned int round, int sm2)
{
    struct instance *inst = op->worker->instance;
    unsigned char digest[32], sig[1024];
    fill(digest, sizeof(digest), op->id * 701 + round);
    for (int direction = 0; direction < 2; direction++) {
        const char *sp = direction ? SOFT : properties(op);
        const char *vp = direction ? properties(op) : SOFT;
        EVP_PKEY_CTX *sign = EVP_PKEY_CTX_new_from_pkey(inst->ctx, key, sp);
        EVP_PKEY_CTX *verify = EVP_PKEY_CTX_new_from_pkey(inst->ctx, key, vp);
        EVP_MD *md = EVP_MD_fetch(inst->ctx, sm2 ? "SM3" : "SHA256", SOFT);
        size_t n = sizeof(sig);
        REQUIRE(sign && verify && md && EVP_PKEY_sign_init(sign) > 0 && EVP_PKEY_verify_init(verify) > 0);
        check_provider(EVP_PKEY_CTX_get0_provider(sign), direction ? "default" : expected(op));
        check_provider(EVP_PKEY_CTX_get0_provider(verify), direction ? expected(op) : "default");
        REQUIRE(EVP_PKEY_CTX_set_signature_md(sign, md) > 0 && EVP_PKEY_CTX_set_signature_md(verify, md) > 0);
        if (!sm2) {
            int pad = round & 1 ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
            REQUIRE(EVP_PKEY_CTX_set_rsa_padding(sign, pad) > 0 && EVP_PKEY_CTX_set_rsa_padding(verify, pad) > 0);
            if (pad == RSA_PKCS1_PSS_PADDING) {
                REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(sign, 32) > 0);
                REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(verify, 32) > 0);
            }
        }
        REQUIRE(EVP_PKEY_sign(sign, sig, &n, digest, sizeof(digest)) > 0);
        REQUIRE(EVP_PKEY_verify(verify, sig, n, digest, sizeof(digest)) == 1);
        op->checks++;
        EVP_PKEY_CTX_free(sign);
        EVP_PKEY_CTX_free(verify);
        EVP_MD_free(md);
    }
}

static void encryption_round(struct operation *op, EVP_PKEY *key, unsigned int round, int sm2)
{
    struct instance *inst = op->worker->instance;
    unsigned char plain[32], cipher[1024], decrypted[1024];
    fill(plain, sizeof(plain), op->id * 1103 + round);
    for (int direction = 0; direction < 2; direction++) {
        EVP_PKEY_CTX *enc = EVP_PKEY_CTX_new_from_pkey(inst->ctx, key, direction ? SOFT : properties(op));
        EVP_PKEY_CTX *dec = EVP_PKEY_CTX_new_from_pkey(inst->ctx, key, direction ? properties(op) : SOFT);
        size_t cn = sizeof(cipher), dn = sizeof(decrypted);
        REQUIRE(enc && dec && EVP_PKEY_encrypt_init(enc) > 0 && EVP_PKEY_decrypt_init(dec) > 0);
        check_provider(EVP_PKEY_CTX_get0_provider(enc), direction ? "default" : expected(op));
        check_provider(EVP_PKEY_CTX_get0_provider(dec), direction ? expected(op) : "default");
        if (!sm2) {
            int pad = round & 1 ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
            REQUIRE(EVP_PKEY_CTX_set_rsa_padding(enc, pad) > 0 && EVP_PKEY_CTX_set_rsa_padding(dec, pad) > 0);
        }
        REQUIRE(EVP_PKEY_encrypt(enc, cipher, &cn, plain, sizeof(plain)) > 0);
        REQUIRE(EVP_PKEY_decrypt(dec, decrypted, &dn, cipher, cn) > 0);
        REQUIRE(dn == sizeof(plain) && !CRYPTO_memcmp(plain, decrypted, dn));
        op->checks++;
        EVP_PKEY_CTX_free(enc);
        EVP_PKEY_CTX_free(dec);
    }
}

static EVP_PKEY *dh_key(struct instance *inst, size_t bits, const char *prop)
{
    const unsigned char *bytes = bits == 2048 ? dhtest_2048 : bits == 3072 ? dhtest_3072 : dhtest_4096;
    BIGNUM *p = BN_bin2bn(bytes, (int)bits / 8, NULL), *g = BN_new();
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    EVP_PKEY_CTX *from = EVP_PKEY_CTX_new_from_name(inst->ctx, "DH", prop), *gen;
    EVP_PKEY *parameters = NULL, *key = NULL;
    OSSL_PARAM *params;
    REQUIRE(p && g && bld && from && BN_set_word(g, 2));
    REQUIRE(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p));
    REQUIRE(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g));
    params = OSSL_PARAM_BLD_to_param(bld);
    REQUIRE(params && EVP_PKEY_fromdata_init(from) > 0);
    REQUIRE(EVP_PKEY_fromdata(from, &parameters, EVP_PKEY_KEY_PARAMETERS, params) > 0);
    gen = EVP_PKEY_CTX_new_from_pkey(inst->ctx, parameters, prop);
    REQUIRE(gen && EVP_PKEY_keygen_init(gen) > 0 && EVP_PKEY_generate(gen, &key) > 0);
    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_CTX_free(from);
    EVP_PKEY_free(parameters);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(g);
    return key;
}

static void dh_round(struct operation *op)
{
    struct instance *inst = op->worker->instance;
    size_t bits = (size_t)atoi(op->name + 2);
    EVP_PKEY *a = dh_key(inst, bits, properties(op)), *b = dh_key(inst, bits, SOFT);
    EVP_PKEY_CTX *ac = EVP_PKEY_CTX_new_from_pkey(inst->ctx, a, properties(op));
    EVP_PKEY_CTX *bc = EVP_PKEY_CTX_new_from_pkey(inst->ctx, b, SOFT);
    unsigned char actual[512], reference[512];
    REQUIRE(ac && bc && EVP_PKEY_derive_init(ac) > 0 && EVP_PKEY_derive_init(bc) > 0);
    check_provider(EVP_PKEY_CTX_get0_provider(ac), expected(op));
    REQUIRE(EVP_PKEY_derive_set_peer(ac, b) > 0 && EVP_PKEY_derive_set_peer(bc, a) > 0);
    for (int pad = 0; pad <= 1; pad++) {
        size_t an = sizeof(actual), bn = sizeof(reference);
        REQUIRE(EVP_PKEY_CTX_set_dh_pad(ac, pad) > 0 && EVP_PKEY_CTX_set_dh_pad(bc, pad) > 0);
        REQUIRE(EVP_PKEY_derive(ac, actual, &an) > 0 && EVP_PKEY_derive(bc, reference, &bn) > 0);
        REQUIRE(an == bn && !CRYPTO_memcmp(actual, reference, an));
        op->checks++;
    }
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(reference, sizeof(reference));
    EVP_PKEY_CTX_free(ac);
    EVP_PKEY_CTX_free(bc);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
}

static void rand_round(struct operation *op, unsigned int round)
{
    static const size_t sizes[] = {32, 256, 8192};
    struct instance *inst = op->worker->instance;
    size_t size = sizes[round % 3];
    unsigned char data[8193];
    int private = !strcmp(op->name, "rand-private");
    data[size] = 0x5a;
    REQUIRE((private ? RAND_priv_bytes_ex(inst->ctx, data, size, 0) :
                       RAND_bytes_ex(inst->ctx, data, size, 0)) == 1);
    REQUIRE(data[size] == 0x5a);
    EVP_RAND_CTX *ctx = private ? RAND_get0_private(inst->ctx) : RAND_get0_public(inst->ctx);
    REQUIRE(ctx);
    check_provider(EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(ctx)), "default");
    OPENSSL_cleanse(data, sizeof(data));
    op->checks++;
}

static int perform(void *arg)
{
    struct operation *op = *(struct operation **)arg;
    EVP_PKEY *sm2 = NULL;
    ERR_clear_error();
    if (!strcmp(op->name, "sm2"))
        sm2 = generate_key(op->worker->instance->ctx, "SM2", properties(op), 0);
    for (unsigned int round = 0; round < op->worker->rounds; round++) {
        if (is_cipher(op->name))
            cipher_round(op, round);
        else if (is_digest(op->name))
            digest_round(op, round);
        else if (!strncmp(op->name, "rsa", 3) || sm2) {
            EVP_PKEY *key = sm2 ? sm2 : op->worker->rsa;
            signature_round(op, key, round, sm2 != NULL);
            encryption_round(op, key, round, sm2 != NULL);
        } else if (!strncmp(op->name, "dh", 2))
            dh_round(op);
        else
            rand_round(op, round);
    }
    EVP_PKEY_free(sm2);
    REQUIRE(ERR_peek_error() == 0);
    return 1;
}

static void *run_worker(void *arg)
{
    struct worker *worker = arg;
    OSSL_LIB_CTX *previous = OSSL_LIB_CTX_set0_default(worker->instance->ctx);
    ASYNC_JOB *jobs[MAX_JOBS] = {0};
    ASYNC_WAIT_CTX *wait[MAX_JOBS] = {0};
    struct operation ops[MAX_JOBS] = {0};
    int done[MAX_JOBS] = {0}, ready[MAX_JOBS], results[MAX_JOBS] = {0};
    unsigned int remaining = worker->jobs;
    double deadline = monotime() + 240;
    REQUIRE(ASYNC_init_thread(worker->jobs, worker->jobs));
    for (unsigned int i = 0; i < worker->jobs; i++) {
        ops[i].worker = worker;
        ops[i].id = worker->index * MAX_JOBS + i + 1;
        ops[i].name = strcmp(worker->scope, "mixed") ? worker->scope :
            algorithms[(ops[i].id - 1) % (sizeof(algorithms) / sizeof(algorithms[0]))];
        ready[i] = 1;
        wait[i] = ASYNC_WAIT_CTX_new();
        REQUIRE(wait[i]);
    }
    int rc = pthread_barrier_wait(worker->barrier);
    REQUIRE(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    while (remaining) {
        struct pollfd fds[MAX_JOBS * 8];
        unsigned int owner[MAX_JOBS * 8];
        nfds_t nfds = 0;
        for (unsigned int i = 0; i < worker->jobs; i++) {
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
                    worker->checks += op->checks;
                    continue;
                }
                REQUIRE(status == ASYNC_PAUSE);
                worker->pauses++;
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
            rc = poll(fds, nfds, 1000);
            REQUIRE(rc >= 0 || errno == EINTR);
            if (rc > 0) {
                for (nfds_t j = 0; j < nfds; j++) {
                    REQUIRE(!(fds[j].revents & (POLLERR | POLLHUP | POLLNVAL)));
                    if (fds[j].revents & POLLIN)
                        ready[owner[j]] = 1;
                }
            }
        }
        REQUIRE(monotime() < deadline);
    }
    for (unsigned int i = 0; i < worker->jobs; i++)
        ASYNC_WAIT_CTX_free(wait[i]);
    ASYNC_cleanup_thread();
    OSSL_LIB_CTX_set0_default(previous);
    return NULL;
}

static void selection_check(struct instance *inst, const char *policy)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(inst->ctx, "AES-128-CTR", NULL);
    EVP_MD *md = EVP_MD_fetch(inst->ctx, "SM3", NULL);
    REQUIRE(cipher && md);
    check_provider(EVP_CIPHER_get0_provider(cipher), policy);
    check_provider(EVP_MD_get0_provider(md), policy);
    EVP_CIPHER_free(cipher);
    EVP_MD_free(md);
}

int main(int argc, char **argv)
{
    struct instance instances[MAX_THREADS] = {0};
    struct worker workers[MAX_THREADS] = {0};
    pthread_t threads[MAX_THREADS];
    pthread_barrier_t barrier;
    unsigned long checks = 0, pauses = 0;
    unsigned int count, jobs, rounds, ninstances;
    int global, isolated, partition, prefer;
    if (argc != 7) {
        fprintf(stderr, "Usage: %s ALGORITHM|mixed THREADS JOBS ROUNDS global|shared|isolated explicit|prefer|partition\n", argv[0]);
        return 2;
    }
    count = (unsigned int)atoi(argv[2]);
    jobs = (unsigned int)atoi(argv[3]);
    rounds = (unsigned int)atoi(argv[4]);
    global = !strcmp(argv[5], "global");
    isolated = !strcmp(argv[5], "isolated");
    prefer = !strcmp(argv[6], "prefer");
    partition = !strcmp(argv[6], "partition");
    REQUIRE(count > 0 && count <= MAX_THREADS && jobs > 0 && jobs <= MAX_JOBS && rounds > 0);
    REQUIRE(valid_scope(argv[1]));
    REQUIRE(global || isolated || !strcmp(argv[5], "shared"));
    REQUIRE(prefer || partition || !strcmp(argv[6], "explicit"));
    REQUIRE(!partition || isolated);
    ninstances = isolated ? count : 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (unsigned int i = 0; i < ninstances; i++) {
        struct instance *inst = &instances[i];
        inst->owned = !global;
        inst->ctx = global ? NULL : OSSL_LIB_CTX_new();
        REQUIRE(global || inst->ctx);
        inst->def = OSSL_PROVIDER_load(inst->ctx, "default");
        inst->kae = OSSL_PROVIDER_load(inst->ctx, "kae_provider");
        REQUIRE(inst->def && inst->kae);
        if (prefer || (partition && !(i & 1))) {
            REQUIRE(EVP_set_default_properties(inst->ctx, "?" HARD));
            REQUIRE(RAND_set_DRBG_type(inst->ctx, "CTR-DRBG", SOFT, NULL, NULL));
            inst->properties = NULL;
            inst->expected = "kae_provider";
        } else {
            REQUIRE(EVP_set_default_properties(inst->ctx, SOFT));
            inst->properties = partition ? NULL : HARD;
            inst->expected = partition ? "default" : "kae_provider";
        }
    }
    REQUIRE(pthread_barrier_init(&barrier, NULL, count) == 0);
    for (unsigned int i = 0; i < count; i++) {
        workers[i].instance = &instances[isolated ? i : 0];
        workers[i].barrier = &barrier;
        workers[i].scope = argv[1];
        workers[i].index = i;
        workers[i].jobs = jobs;
        workers[i].rounds = rounds;
        if (!strncmp(argv[1], "rsa", 3) || !strcmp(argv[1], "mixed"))
            workers[i].rsa = generate_key(workers[i].instance->ctx, "RSA", SOFT,
                !strcmp(argv[1], "mixed") ? 2048 : atoi(argv[1] + 3));
    }
    for (unsigned int i = 0; i < count; i++)
        REQUIRE(pthread_create(&threads[i], NULL, run_worker, &workers[i]) == 0);
    for (unsigned int i = 0; i < count; i++) {
        REQUIRE(pthread_join(threads[i], NULL) == 0);
        checks += workers[i].checks;
        pauses += workers[i].pauses;
        EVP_PKEY_free(workers[i].rsa);
    }
    REQUIRE(pthread_barrier_destroy(&barrier) == 0);
    for (unsigned int i = 0; i < ninstances; i++) {
        struct instance *inst = &instances[i];
        const char *policy = prefer || (partition && !(i & 1)) ? "kae_provider" : "default";
        selection_check(inst, getenv("KAE_TEST_NO_SEC") ? "default" : policy);
        OSSL_PROVIDER_unload(inst->kae);
        OSSL_PROVIDER_unload(inst->def);
        if (inst->owned)
            OSSL_LIB_CTX_free(inst->ctx);
    }
    printf("PASS parallel algorithm=%s threads=%u jobs=%u rounds=%u contexts=%s selection=%s checks=%lu pauses=%lu\n",
        argv[1], count, jobs, rounds, argv[5], argv[6], checks, pauses);
    return 0;
}
