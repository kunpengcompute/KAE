/* Copyright 2026 Huawei Technologies Co.,Ltd. SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); \
    ERR_print_errors_fp(stderr); exit(1); } } while (0)

static const char *hw = "provider=kae_provider";
static const char *sw = "provider=default";
static _Thread_local unsigned int cases;

static void selected(EVP_PKEY_CTX *ctx, const char *prop)
{
    const OSSL_PROVIDER *p = EVP_PKEY_CTX_get0_provider(ctx);
    CHECK(p && strcmp(OSSL_PROVIDER_get0_name(p), strchr(prop, '=') + 1) == 0);
}

static EVP_PKEY *keygen(int bits)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", hw);
    CHECK(ctx && EVP_PKEY_keygen_init(ctx) > 0);
    selected(ctx, hw);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0);
    CHECK(EVP_PKEY_generate(ctx, &key) > 0);
    CHECK(EVP_PKEY_get_bits(key) == bits);
    EVP_PKEY_CTX_free(ctx);
    cases++;
    return key;
}

static EVP_PKEY_CTX *sigctx(EVP_PKEY *key, const char *prop, int sign, int pad,
    const EVP_MD *md)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, prop);
    CHECK(ctx);
    CHECK((sign ? EVP_PKEY_sign_init(ctx) : EVP_PKEY_verify_init(ctx)) > 0);
    selected(ctx, prop);
    CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx, pad) > 0);
    CHECK(EVP_PKEY_CTX_set_signature_md(ctx, md) > 0);
    if (pad == RSA_PKCS1_PSS_PADDING) {
        CHECK(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) > 0);
        CHECK(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) > 0);
    }
    return ctx;
}

static void signatures(EVP_PKEY *key, EVP_PKEY *softkey, const EVP_MD *md, int pad)
{
    unsigned char digest[EVP_MAX_MD_SIZE], sig[1024], bad[EVP_MAX_MD_SIZE];
    size_t n;
    unsigned int len;
    CHECK(EVP_Digest("rsa compatibility", 17, digest, &len, md, NULL) > 0);
    for (int direction = 0; direction < 2; direction++) {
        const char *sp = direction ? sw : hw, *vp = direction ? hw : sw;
        EVP_PKEY_CTX *sign = sigctx(direction ? softkey : key, sp, 1, pad, md);
        EVP_PKEY_CTX *verify = sigctx(direction ? key : softkey, vp, 0, pad, md);
        EVP_PKEY_CTX *copy = EVP_PKEY_CTX_dup(sign);
        CHECK(copy);
        if (getenv("KAE_TEST_NEGATIVE")) {
            n = 8;
            CHECK(EVP_PKEY_sign(copy, sig, &n, digest, len) <= 0);
            ERR_clear_error();
            cases++;
        }
        n = sizeof(sig);
        CHECK(EVP_PKEY_sign(copy, sig, &n, digest, len) > 0);
        CHECK(EVP_PKEY_verify(verify, sig, n, digest, len) == 1);
        if (getenv("KAE_TEST_NEGATIVE")) {
            memcpy(bad, digest, len);
            bad[0] ^= 1;
            CHECK(EVP_PKEY_verify(verify, sig, n, bad, len) <= 0);
            ERR_clear_error();
            sig[n - 1] ^= 1;
            CHECK(EVP_PKEY_verify(verify, sig, n, digest, len) <= 0);
            ERR_clear_error();
            cases += 2;
        }
        EVP_PKEY_CTX_free(copy);
        EVP_PKEY_CTX_free(sign);
        EVP_PKEY_CTX_free(verify);
        cases++;
    }
}

static EVP_PKEY_CTX *cryptctx(EVP_PKEY *key, const char *prop, int enc, int pad,
    const EVP_MD *md, int label)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, prop);
    CHECK(ctx && (enc ? EVP_PKEY_encrypt_init(ctx) : EVP_PKEY_decrypt_init(ctx)) > 0);
    selected(ctx, prop);
    CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx, pad) > 0);
    if (pad == RSA_PKCS1_OAEP_PADDING) {
        CHECK(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) > 0);
        CHECK(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) > 0);
        if (label) {
            unsigned char *data = OPENSSL_memdup("label", 5);
            CHECK(data && EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, data, 5) > 0);
        }
    }
    return ctx;
}

static void encryption(EVP_PKEY *key, EVP_PKEY *softkey, int pad,
    const EVP_MD *md, int label)
{
    unsigned char plain[1024] = {0}, cipher[1024], out[1024];
    size_t len = pad == RSA_NO_PADDING ? (size_t)EVP_PKEY_get_size(key) : 32;
    size_t cn, on;
    memset(plain + 1, 0x24, len - 1);
    for (int direction = 0; direction < 2; direction++) {
        const char *ep = direction ? sw : hw, *dp = direction ? hw : sw;
        EVP_PKEY_CTX *enc = cryptctx(direction ? softkey : key, ep, 1, pad, md, label);
        EVP_PKEY_CTX *dec = cryptctx(direction ? key : softkey, dp, 0, pad, md, label);
        /* Exercise KAE duplication; 3.0.16 default-provider OAEP label copies
         * alias their allocation, so use its original context as the oracle. */
        EVP_PKEY_CTX *copy = direction ? EVP_PKEY_CTX_dup(dec) : dec;
        CHECK(copy);
        if (getenv("KAE_TEST_NEGATIVE") && !direction) {
            cn = 8;
            CHECK(EVP_PKEY_encrypt(enc, cipher, &cn, plain, len) <= 0);
            ERR_clear_error();
            cases++;
        }
        cn = sizeof(cipher);
        CHECK(EVP_PKEY_encrypt(enc, cipher, &cn, plain, len) > 0);
        on = sizeof(out);
        CHECK(EVP_PKEY_decrypt(copy, out, &on, cipher, cn) > 0);
        CHECK(on == len && memcmp(out, plain, len) == 0);
        if (pad == RSA_PKCS1_OAEP_PADDING && getenv("KAE_TEST_NEGATIVE")) {
            cipher[cn - 1] ^= 1;
            on = sizeof(out);
            CHECK(EVP_PKEY_decrypt(copy, out, &on, cipher, cn) <= 0);
            ERR_clear_error();
            cases++;
        }
        if (copy != dec)
            EVP_PKEY_CTX_free(copy);
        EVP_PKEY_CTX_free(enc);
        EVP_PKEY_CTX_free(dec);
        cases++;
    }
}

static void streaming(EVP_PKEY *key, EVP_PKEY *softkey)
{
    EVP_MD_CTX *sign = EVP_MD_CTX_new(), *copy = EVP_MD_CTX_new();
    EVP_MD_CTX *verify = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char sig[1024];
    size_t n = sizeof(sig);
    CHECK(sign && copy && verify);
    CHECK(EVP_DigestSignInit_ex(sign, &pctx, "SHA256", NULL, hw, key, NULL) > 0);
    selected(pctx, hw);
    CHECK(EVP_DigestSignUpdate(sign, "part1", 5) > 0);
    CHECK(EVP_MD_CTX_copy_ex(copy, sign) > 0);
    CHECK(EVP_DigestSignUpdate(copy, "part2", 5) > 0);
    CHECK(EVP_DigestSignFinal(copy, NULL, &n) > 0);
    CHECK(n <= sizeof(sig));
    CHECK(EVP_DigestSignFinal(copy, sig, &n) > 0);
    CHECK(EVP_DigestVerifyInit_ex(verify, &pctx, "SHA256", NULL, sw, softkey, NULL) > 0);
    selected(pctx, sw);
    CHECK(EVP_DigestVerifyUpdate(verify, "part1part2", 10) > 0);
    CHECK(EVP_DigestVerifyFinal(verify, sig, n) == 1);
    CHECK(EVP_MD_CTX_reset(verify));
    CHECK(EVP_DigestVerifyInit_ex(verify, &pctx, "SHA256", NULL, hw, key, NULL) > 0);
    selected(pctx, hw);
    CHECK(EVP_DigestVerifyUpdate(verify, "part1part2", 10) > 0);
    CHECK(EVP_DigestVerifyFinal(verify, sig, n) == 1);
    EVP_MD_CTX_free(sign);
    EVP_MD_CTX_free(copy);
    EVP_MD_CTX_free(verify);
    cases += 3;
}

typedef struct { EVP_PKEY *key; EVP_PKEY *softkey; } KEYS;

static int matrix(void *arg)
{
    KEYS *keys = arg;
    const EVP_MD *mds[] = {EVP_sha256(), EVP_sha384(), EVP_sha512()};
    for (size_t i = 0; i < sizeof(mds) / sizeof(mds[0]); i++) {
        signatures(keys->key, keys->softkey, mds[i], RSA_PKCS1_PADDING);
        /* 1024-bit RSA cannot fit SHA512 with a digest-length PSS salt. */
        if (EVP_PKEY_get_bits(keys->key) > 1024 || i < 2)
            signatures(keys->key, keys->softkey, mds[i], RSA_PKCS1_PSS_PADDING);
    }
    encryption(keys->key, keys->softkey, RSA_PKCS1_PADDING, NULL, 0);
    encryption(keys->key, keys->softkey, RSA_NO_PADDING, NULL, 0);
    encryption(keys->key, keys->softkey, RSA_PKCS1_OAEP_PADDING, EVP_sha1(), 0);
    encryption(keys->key, keys->softkey, RSA_PKCS1_OAEP_PADDING, EVP_sha256(), 1);
    streaming(keys->key, keys->softkey);
    return 1;
}

static void *thread_matrix(void *arg)
{
    CHECK(matrix(arg) == 1);
    return NULL;
}

int main(int argc, char **argv)
{
    int bits = argc > 1 ? atoi(argv[1]) : 2048;
    int async = argc > 2 ? atoi(argv[2]) : 0;
    int result = 0, pauses = 0;
    if (argc > 3)
        hw = argv[3];
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    KEYS keys = {0};
    BIO *pem;
    EVP_PKEY_CTX *check;
    CHECK(def && kae);
    keys.key = keygen(bits);
    pem = BIO_new(BIO_s_mem());
    CHECK(pem && PEM_write_bio_PrivateKey(pem, keys.key, NULL, NULL, 0, NULL, NULL));
    keys.softkey = PEM_read_bio_PrivateKey_ex(pem, NULL, NULL, NULL, NULL, sw);
    CHECK(keys.softkey);
    check = EVP_PKEY_CTX_new_from_pkey(NULL, keys.softkey, sw);
    CHECK(check && EVP_PKEY_pairwise_check(check) > 0);
    EVP_PKEY_CTX_free(check);
    BIO_free(pem);
    cases += 2;
    if (async == 2) {
        pthread_t threads[4];
        for (size_t i = 0; i < 4; i++)
            CHECK(pthread_create(&threads[i], NULL, thread_matrix, &keys) == 0);
        for (size_t i = 0; i < 4; i++)
            CHECK(pthread_join(threads[i], NULL) == 0);
        result = 1;
        printf("PASS 4 concurrent RSA matrices\n");
    } else if (async) {
        ASYNC_JOB *job = NULL;
        ASYNC_WAIT_CTX *wait = ASYNC_WAIT_CTX_new();
        CHECK(wait && ASYNC_init_thread(1, 1) > 0);
        for (;;) {
            OSSL_ASYNC_FD fds[16];
            struct pollfd pollfds[16];
            size_t count = 0;
            int status = ASYNC_start_job(&job, wait, &result, matrix, &keys, sizeof(keys));
            if (status == ASYNC_FINISH)
                break;
            CHECK(status == ASYNC_PAUSE);
            pauses++;
            CHECK(ASYNC_WAIT_CTX_get_all_fds(wait, NULL, &count) && count <= 16);
            CHECK(ASYNC_WAIT_CTX_get_all_fds(wait, fds, &count));
            for (size_t i = 0; i < count; i++)
                pollfds[i] = (struct pollfd){fds[i], POLLIN, 0};
            CHECK(count && poll(pollfds, count, 10000) > 0);
        }
        ASYNC_WAIT_CTX_free(wait);
        ASYNC_cleanup_thread();
    } else {
        result = matrix(&keys);
    }
    CHECK(result == 1);
    printf("PASS RSA bits=%d async=%d checks=%u pauses=%d provider=kae_provider\n",
        bits, async, cases, pauses);
    EVP_PKEY_free(keys.key);
    EVP_PKEY_free(keys.softkey);
    OSSL_PROVIDER_unload(kae);
    OSSL_PROVIDER_unload(def);
    return 0;
}
