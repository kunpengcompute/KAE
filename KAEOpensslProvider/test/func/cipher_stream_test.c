/* SPDX-License-Identifier: Apache-2.0 */
#include <openssl/async.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CAPACITY (2 * 1024 * 1024)

struct test_case {
    const char *algorithm;
    const char *pattern;
    const size_t *chunks;
    size_t nchunks;
    int padding;
    int inplace;
    int counter_wrap;
    int raw;
    int inspect;
};

static int get_iv(EVP_CIPHER_CTX *ctx, const char *name, unsigned char *out, size_t len)
{
    void *iv = NULL;
    OSSL_PARAM params[] = {OSSL_PARAM_octet_ptr(name, &iv, len), OSSL_PARAM_END};
    if (!EVP_CIPHER_CTX_get_params(ctx, params) || !iv)
        return 0;
    memcpy(out, iv, len);
    return 1;
}

static int check_state(EVP_CIPHER_CTX *actual, EVP_CIPHER_CTX *reference)
{
    unsigned char a[16], b[16];
    int ivlen = EVP_CIPHER_CTX_get_iv_length(reference);
    if (EVP_CIPHER_CTX_get_num(actual) != EVP_CIPHER_CTX_get_num(reference)) {
        fprintf(stderr, "NUM mismatch: actual=%d reference=%d\n",
            EVP_CIPHER_CTX_get_num(actual), EVP_CIPHER_CTX_get_num(reference));
        return 0;
    }
    if (ivlen && (!EVP_CIPHER_CTX_get_updated_iv(actual, a, ivlen) ||
        !get_iv(reference, OSSL_CIPHER_PARAM_UPDATED_IV, b, ivlen) || memcmp(a, b, ivlen))) {
        fprintf(stderr, "updated IV mismatch\n");
        return 0;
    }
    if (ivlen && (!EVP_CIPHER_CTX_get_original_iv(actual, a, ivlen) ||
        !get_iv(reference, OSSL_CIPHER_PARAM_IV, b, ivlen) || memcmp(a, b, ivlen))) {
        fprintf(stderr, "original IV mismatch\n");
        return 0;
    }
    return 1;
}

static int transform(EVP_CIPHER_CTX *actual, EVP_CIPHER_CTX *reference,
    const struct test_case *test, const unsigned char *input, size_t size,
    unsigned char *output, size_t *output_size)
{
    unsigned char *a = OPENSSL_malloc(CAPACITY + 32);
    unsigned char *b = OPENSSL_malloc(CAPACITY + 32);
    size_t offset = 0, used = 0, chunk = 0;
    int ok = 0, alen, blen;
    if (!a || !b)
        goto end;
    while (offset < size) {
        size_t n = test->chunks[chunk++ % test->nchunks];
        if (n == 0 || n > size - offset)
            n = size - offset;
        if (test->inplace) {
            memcpy(a, input + offset, n);
            memcpy(b, input + offset, n);
        }
        const unsigned char *ain = test->inplace ? a : input + offset;
        const unsigned char *bin = input + offset;
        if (test->raw) {
            if (!EVP_Cipher(actual, a, ain, n) || !EVP_Cipher(reference, b, bin, n))
                goto end;
            alen = blen = n;
        } else if (!EVP_CipherUpdate(actual, a, &alen, ain, n) ||
            !EVP_CipherUpdate(reference, b, &blen, bin, n)) {
            goto end;
        }
        if (alen != blen || memcmp(a, b, blen) ||
            (test->inspect && !check_state(actual, reference))) {
            fprintf(stderr, "update mismatch at offset=%zu size=%zu actual=%d reference=%d\n",
                offset, n, alen, blen);
            goto end;
        }
        memcpy(output + used, a, alen);
        used += alen;
        offset += n;
    }
    if (!test->raw) {
        if (!EVP_CipherFinal_ex(actual, a, &alen) || !EVP_CipherFinal_ex(reference, b, &blen) ||
            alen != blen || memcmp(a, b, blen) ||
            (test->inspect && !check_state(actual, reference))) {
            fprintf(stderr, "final mismatch\n");
            goto end;
        }
        memcpy(output + used, a, alen);
        used += alen;
    }
    *output_size = used;
    ok = 1;
end:
    OPENSSL_free(a);
    OPENSSL_free(b);
    return ok;
}

static int run_case(void *argument)
{
    struct test_case current = **(const struct test_case **)argument;
    struct test_case *test = &current;
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, test->algorithm, "provider=kae_provider");
    EVP_CIPHER *reference = EVP_CIPHER_fetch(NULL, test->algorithm, "provider=default");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *ref = EVP_CIPHER_CTX_new();
    unsigned char key[64], iv[16], *plain = NULL, *encrypted = NULL, *decrypted = NULL;
    size_t len = 0, encrypted_len, decrypted_len;
    int ok = 0;
    unsigned int padding = test->padding;
    OSSL_PARAM params[] = { OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &padding), OSSL_PARAM_END };
    for (size_t i = 0; i < test->nchunks; i++)
        len += test->chunks[i];
    if (len > CAPACITY || !cipher || !reference || !ctx || !ref)
        goto end;
    plain = OPENSSL_malloc(len + 32);
    encrypted = OPENSSL_malloc(len + 32);
    decrypted = OPENSSL_malloc(len + 32);
    if (!plain || !encrypted || !decrypted)
        goto end;
    for (size_t i = 0; i < len; i++)
        plain[i] = (unsigned char)(17 * i + 3);
    for (int round = 0; round < 3; round++) {
        test->inspect = round == 1;
        for (size_t i = 0; i < sizeof(key); i++)
            key[i] = (unsigned char)(i * 3 + 7 + round);
        memset(iv, 0x53 + round, sizeof(iv));
        if (test->counter_wrap) {
            memset(iv + 12, 0xff, 4);
            iv[15] = 0xe0;
        }
        /* Reuse the same contexts across keys, IVs and encrypt/decrypt directions. */
        if (!EVP_CipherInit_ex2(ctx, round ? NULL : cipher, key, iv, 1, params) ||
            !EVP_CipherInit_ex2(ref, round ? NULL : reference, key, iv, 1, params) ||
            !transform(ctx, ref, test, plain, len, encrypted, &encrypted_len)) {
            fprintf(stderr, "encrypt failed round=%d\n", round);
            goto end;
        }
        if (!EVP_CipherInit_ex2(ctx, NULL, NULL, iv, 1, NULL) ||
            !EVP_CipherInit_ex2(ref, NULL, NULL, iv, 1, NULL) ||
            !transform(ctx, ref, test, plain, len, encrypted, &encrypted_len)) {
            fprintf(stderr, "retained key/new IV failed round=%d\n", round);
            goto end;
        }
        if (!EVP_CipherInit_ex2(ctx, NULL, key, iv, 0, NULL) ||
            !EVP_CipherInit_ex2(ref, NULL, key, iv, 0, NULL) ||
            !EVP_CIPHER_CTX_set_padding(ctx, padding) ||
            !EVP_CIPHER_CTX_set_padding(ref, padding) ||
            !transform(ctx, ref, test, encrypted, encrypted_len, decrypted, &decrypted_len) ||
            decrypted_len != len || memcmp(plain, decrypted, len)) {
            fprintf(stderr, "decrypt failed round=%d\n", round);
            goto end;
        }
        if (EVP_CIPHER_get_mode(cipher) != EVP_CIPH_XTS_MODE &&
            (!EVP_CipherInit_ex2(ctx, NULL, key, NULL, 1, NULL) ||
             !EVP_CipherInit_ex2(ref, NULL, key, NULL, 1, NULL) ||
             !transform(ctx, ref, test, plain, len, encrypted, &encrypted_len))) {
            fprintf(stderr, "retained key/IV reinit failed round=%d\n", round);
            goto end;
        }
    }
    if (ERR_peek_error()) {
        fprintf(stderr, "unexpected OpenSSL error queue\n");
        goto end;
    }
    ok = 1;
end:
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(ref);
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_free(reference);
    OPENSSL_free(plain);
    OPENSSL_free(encrypted);
    OPENSSL_free(decrypted);
    return ok;
}

static int execute(const struct test_case *test, int async, unsigned int *pauses)
{
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *waitctx = NULL;
    int result = 0;
    if (!async)
        return run_case(&test);
    if (!ASYNC_init_thread(1, 1) || !(waitctx = ASYNC_WAIT_CTX_new()))
        return 0;
    for (;;) {
        int status = ASYNC_start_job(&job, waitctx, &result, run_case, &test, sizeof(test));
        if (status == ASYNC_FINISH)
            break;
        if (status != ASYNC_PAUSE) {
            result = 0;
            break;
        }
        (*pauses)++;
        OSSL_ASYNC_FD fds[32];
        struct pollfd pollfds[32];
        size_t n = 0;
        if (!ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &n) || n > 32 ||
            !ASYNC_WAIT_CTX_get_all_fds(waitctx, fds, &n))
            exit(2);
        for (size_t i = 0; i < n; i++) {
            pollfds[i].fd = fds[i];
            pollfds[i].events = POLLIN;
            pollfds[i].revents = 0;
        }
        if (n && poll(pollfds, n, 10000) <= 0)
            exit(2);
    }
    ASYNC_WAIT_CTX_free(waitctx);
    ASYNC_cleanup_thread();
    return result;
}

int main(int argc, char **argv)
{
    static const char *algorithms[] = {
        "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "SM4-CBC",
        "AES-128-ECB", "AES-192-ECB", "AES-256-ECB", "SM4-ECB",
        "AES-128-CTR", "AES-192-CTR", "AES-256-CTR", "SM4-CTR",
        "AES-128-CFB", "AES-192-CFB", "AES-256-CFB", "SM4-CFB",
        "AES-128-OFB", "AES-192-OFB", "AES-256-OFB", "SM4-OFB",
        "AES-128-XTS", "AES-256-XTS"
    };
    static const size_t small[] = {16, 64, 16, 64};
    static const size_t mixed[] = {16, 256, 64, 1024, 8192, 16384};
    static const size_t split[] = {1, 15, 17, 239, 3, 13, 256, 16};
    static const size_t large[] = {262160, 16};
    static const size_t wrap[] = {17, 256, 1024, 64, 256};
    static const size_t padded[] = {1, 15, 17, 239, 3};
    static const size_t xts_partial[] = {17, 31, 257};
    static const size_t empty[] = {0};
    static const size_t xts_large_partial[] = {262145, 17};
    static const size_t xts_chunks[] = {262143, 262144, 262160, 524305, 256, 1024};
    struct { const char *name; const size_t *sizes; size_t count; int pad; int wrap; } patterns[] = {
        {"small", small, 4, 0, 0}, {"mixed", mixed, 6, 0, 0},
        {"split", split, 8, 0, 0}, {"large", large, 2, 0, 0},
        {"counter-wrap", wrap, 5, 0, 1}, {"padding", padded, 5, 1, 0},
        {"xts-partial", xts_partial, 3, 0, 0},
        {"empty-padding", empty, 1, 1, 0}, {"aligned-padding", small, 4, 1, 0},
        {"xts-large-partial", xts_large_partial, 2, 0, 0},
        {"xts-chunks", xts_chunks, 6, 0, 0}
    };
    int async = argc > 1 && !strcmp(argv[1], "async");
    unsigned int passed = 0, failed = 0, pauses = 0;
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!def || !kae)
        return 2;
    for (size_t a = 0; a < sizeof(algorithms) / sizeof(algorithms[0]); a++) {
        if (argc > 2 && strcmp(argv[2], algorithms[a]))
            continue;
        int xts = strstr(algorithms[a], "XTS") != NULL;
        for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]); p++) {
            if ((patterns[p].wrap && !strstr(algorithms[a], "CTR")) ||
                (patterns[p].pad && !(strstr(algorithms[a], "CBC") || strstr(algorithms[a], "ECB"))) ||
                (xts && (p == 2 || patterns[p].pad || patterns[p].wrap)) ||
                ((p == 6 || p == 9 || p == 10) && !xts))
                continue;
            for (int inplace = 0; inplace <= 1; inplace++) {
                for (int raw = 0; raw <= (p == 0 || p == 1); raw++) {
                    struct test_case test = {algorithms[a], patterns[p].name, patterns[p].sizes,
                        patterns[p].count, patterns[p].pad, inplace, patterns[p].wrap, raw, 0};
                    ERR_clear_error();
                    int ok = execute(&test, async, &pauses);
                    printf("%s %s %s inplace=%d raw=%d mode=%s\n", ok ? "PASS" : "FAIL",
                        algorithms[a], patterns[p].name, inplace, raw, async ? "async" : "sync");
                    if (ok) passed++; else failed++;
                }
            }
        }
    }
    OSSL_PROVIDER_unload(kae);
    OSSL_PROVIDER_unload(def);
    printf("SUMMARY passed=%u failed=%u async_pauses=%u\n", passed, failed, pauses);
    return failed != 0;
}
