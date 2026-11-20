/* Copyright 2026 Huawei Technologies Co.,Ltd. SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); \
    ERR_print_errors_fp(stderr); exit(1); } } while (0)

typedef struct {
    EVP_MD *md;
    EVP_MD *soft;
    unsigned char *data;
    const char *name;
    unsigned int cases;
} TEST;

static void finish(EVP_MD_CTX *ctx, TEST *t, size_t n)
{
    unsigned char got[EVP_MAX_MD_SIZE], expected[EVP_MAX_MD_SIZE];
    unsigned int gn = 0, en = 0;
    CHECK(EVP_Digest(t->data, n, expected, &en, t->soft, NULL) == 1);
    CHECK(EVP_DigestFinal_ex(ctx, got, &gn) == 1);
    CHECK(gn == en && memcmp(got, expected, en) == 0);
    t->cases++;
}

static int matrix(void *arg)
{
    TEST *t = *(TEST **)arg;
    static const size_t lengths[] = {0, 1, 16, 64, 256, 511, 512, 513,
        8191, 8192, 8193, 16384, 524288, 524289, 1048593};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(), *copy = EVP_MD_CTX_new();
    CHECK(ctx && copy);
    for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
        size_t n = lengths[i];
        unsigned char got[EVP_MAX_MD_SIZE], expected[EVP_MAX_MD_SIZE];
        unsigned int gn, en;
        CHECK(EVP_Digest(t->data, n, got, &gn, t->md, NULL) == 1);
        CHECK(EVP_Digest(t->data, n, expected, &en, t->soft, NULL) == 1);
        CHECK(gn == en && memcmp(got, expected, en) == 0);
        t->cases++;
        CHECK(EVP_DigestInit_ex(ctx, t->md, NULL) == 1);
        for (size_t offset = 0; offset < n;) {
            size_t chunk = n - offset < 113 ? n - offset : 113;
            CHECK(EVP_DigestUpdate(ctx, t->data + offset, chunk) == 1);
            offset += chunk;
        }
        finish(ctx, t, n);
        /* Re-init the same object and fork a partially updated digest. */
        CHECK(EVP_DigestInit_ex(ctx, t->md, NULL) == 1);
        CHECK(EVP_DigestUpdate(ctx, t->data, n / 2) == 1);
        CHECK(EVP_MD_CTX_copy_ex(copy, ctx) == 1);
        CHECK(EVP_DigestUpdate(copy, t->data + n / 2, n - n / 2) == 1);
        finish(copy, t, n);
        finish(ctx, t, n / 2);
        CHECK(EVP_MD_CTX_reset(copy) == 1);
    }
    EVP_MD_CTX_free(copy);
    EVP_MD_CTX_free(ctx);
    return 1;
}

int main(int argc, char **argv)
{
    int async = argc > 2 && strcmp(argv[2], "async") == 0;
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    TEST t = {0}, *tp = &t;
    t.name = argc > 1 ? argv[1] : "SM3";
    t.md = EVP_MD_fetch(NULL, t.name, "provider=kae_provider");
    t.soft = EVP_MD_fetch(NULL, t.name, "provider=default");
    t.data = OPENSSL_malloc(1048593);
    CHECK(def && kae && t.md && t.soft && t.data);
    CHECK(strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(t.md)), "kae_provider") == 0);
    for (size_t i = 0; i < 1048593; i++)
        t.data[i] = (unsigned char)(i * 37 + 11);
    int result = 0, pauses = 0;
    if (async) {
        ASYNC_JOB *job = NULL;
        ASYNC_WAIT_CTX *wait = ASYNC_WAIT_CTX_new();
        CHECK(wait && ASYNC_init_thread(1, 1));
        for (;;) {
            OSSL_ASYNC_FD fd[16];
            struct pollfd polls[16];
            size_t count = 0;
            int status = ASYNC_start_job(&job, wait, &result, matrix, &tp, sizeof(tp));
            if (status == ASYNC_FINISH)
                break;
            CHECK(status == ASYNC_PAUSE);
            pauses++;
            CHECK(ASYNC_WAIT_CTX_get_all_fds(wait, NULL, &count) && count <= 16);
            CHECK(ASYNC_WAIT_CTX_get_all_fds(wait, fd, &count));
            for (size_t i = 0; i < count; i++)
                polls[i] = (struct pollfd){fd[i], POLLIN, 0};
            CHECK(count && poll(polls, count, 10000) > 0);
        }
        ASYNC_WAIT_CTX_free(wait);
        ASYNC_cleanup_thread();
    } else {
        result = matrix(&tp);
    }
    CHECK(result == 1);
    printf("PASS digest=%s checks=%u async=%d pauses=%d\n", t.name, t.cases, async, pauses);
    OPENSSL_free(t.data);
    EVP_MD_free(t.md);
    EVP_MD_free(t.soft);
    OSSL_PROVIDER_unload(kae);
    OSSL_PROVIDER_unload(def);
    return 0;
}
