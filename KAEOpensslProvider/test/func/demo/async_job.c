#include <openssl/evp.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_SIZE (16 * 1024)

// 改进的任务上下文结构体
typedef struct SM3_JOB_CTX {
    unsigned char *data;
    size_t data_len;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_MD_CTX *md_ctx;
    EVP_MD *md_type;
    struct SM3_JOB_CTX *orig_ctx;
} SM3_JOB_CTX;

// 初始化OpenSSL provider
static int load_providers(OSSL_PROVIDER **prov_kae, OSSL_PROVIDER **prov_def)
{
    *prov_kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    if (!*prov_kae) {
        fprintf(stderr, "Warning: kae_provider not available, fallback.\n");
        return 0;
    }
    *prov_def = OSSL_PROVIDER_load(NULL, "default");
    if (!*prov_def) {
        fprintf(stderr, "Error: default provider not available!\n");
        OSSL_PROVIDER_unload(*prov_kae);
        return -1;
    }
    return 1;
}

// 创建随机数据
static unsigned char *generate_random_data(size_t size)
{
    unsigned char *data = OPENSSL_malloc(size);
    if (!data) return NULL;
    if (RAND_bytes(data, size) != 1) {
        OPENSSL_free(data);
        return NULL;
    }
    return data;
}

// 异步任务函数
static int sm3_async_job(void *args)
{
    SM3_JOB_CTX *job_ctx = (SM3_JOB_CTX *)args;

    if (!job_ctx->md_ctx) job_ctx->md_ctx = EVP_MD_CTX_new();
    if (!job_ctx->md_ctx) return 0;

    if (EVP_DigestInit_ex(job_ctx->md_ctx, job_ctx->md_type, NULL) <= 0) goto fail;
        if (EVP_DigestUpdate(job_ctx->md_ctx, job_ctx->data, job_ctx->data_len) <= 0) goto fail;

        printf("[Job] DigestUpdate done, about to pause...\n");
        if (ASYNC_pause_job() == 0) goto fail;

        printf("[Job] Resumed after pause\n");
        if (EVP_DigestFinal_ex(job_ctx->md_ctx, job_ctx->md, &job_ctx->md_len) <= 0) goto fail;

        memcpy(job_ctx->orig_ctx->md, job_ctx->md, job_ctx->md_len);
        job_ctx->orig_ctx->md_len = job_ctx->md_len;

        EVP_MD_CTX_free(job_ctx->md_ctx);
        job_ctx->md_ctx = NULL;
        return 1;

fail:
    EVP_MD_CTX_free(job_ctx->md_ctx);
    job_ctx->md_ctx = NULL;
    return 0;
}

// 异步计算SM3
static int async_sm3(unsigned char *data, size_t data_len)
{
    ASYNC_WAIT_CTX *wait_ctx = NULL;
    ASYNC_JOB *job = NULL;
    SM3_JOB_CTX *job_ctx;
    int job_ret = 0;

    if (!ASYNC_is_capable() || ASYNC_init_thread(1, 1) != 1) {
        fprintf(stderr, "Async not supported or init failed\n");
        return 0;
    }

    wait_ctx = ASYNC_WAIT_CTX_new();
    if (!wait_ctx) return 0;

    job_ctx = OPENSSL_malloc(sizeof(SM3_JOB_CTX));
    if (!job_ctx) goto cleanup;
    memset(job_ctx, 0, sizeof(SM3_JOB_CTX));
    job_ctx->data = data;
    job_ctx->data_len = data_len;
    job_ctx->orig_ctx = job_ctx;
    job_ctx->md_type = EVP_MD_fetch(NULL, "SM3", "provider=kae_provider");

    printf("Starting async SM3 job...\n");

    while (1) {
    int ret = ASYNC_start_job(&job, wait_ctx, &job_ret, sm3_async_job, job_ctx, sizeof(SM3_JOB_CTX));
    switch (ret) {
        case ASYNC_ERR:
            fprintf(stderr, "Async job error\n");
            goto cleanup;
        case ASYNC_NO_JOBS:
            fprintf(stderr, "No async jobs\n");
            goto cleanup;
        case ASYNC_PAUSE:
            printf("Job paused, doing other work...\n");
            break;
        case ASYNC_FINISH:
            if (job_ret == 1) {
                printf("\nKAE Async job finished successfully\nHash length: %u\nHash: ", job_ctx->md_len);
                for (unsigned int i = 0; i < job_ctx->md_len; i++)
                    printf("%02x", job_ctx->md[i]);
                printf("\n");
                goto cleanup;
            } else {
                fprintf(stderr, "Async job failed\n");
                goto cleanup;
            }
                                                                                        }
                                                                    }

cleanup:
    if (job_ctx) {
        EVP_MD_free(job_ctx->md_type);
        OPENSSL_free(job_ctx);
    }
    if (wait_ctx) ASYNC_WAIT_CTX_free(wait_ctx);
        ASYNC_cleanup_thread();
    return 1;
}

// 同步计算SM3
static int sync_sm3(unsigned char *data, size_t data_len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *md_type = EVP_MD_fetch(NULL, "SM3", "provider=default");

    if (!ctx || !md_type) return 0;
    if (EVP_DigestInit_ex(ctx, md_type, NULL) <= 0 ||
            EVP_DigestUpdate(ctx, data, data_len) <= 0 ||
            EVP_DigestFinal_ex(ctx, md, &md_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md_type);
        return 0;
    }
    EVP_MD_CTX_free(ctx);

    printf("\nSoft SM3 hash completed synchronously\nHash length: %u\nHash: ", md_len);
    for (unsigned int i = 0; i < md_len; i++)
        printf("%02x", md[i]);
    printf("\n");

    EVP_MD_free(md_type);
    return 1;
}

int main()
{
    OSSL_PROVIDER *prov_kae = NULL, *prov_def = NULL;
    unsigned char *data = NULL;

    int ret = load_providers(&prov_kae, &prov_def);
    if (ret < 0) return -1;

    data = generate_random_data(DATA_SIZE);
    if (!data) {
        fprintf(stderr, "Failed to generate random data\n");
        goto unload;
    }

    if (!async_sm3(data, DATA_SIZE)) {
        printf("Falling back to synchronous SM3\n");
    }
    sync_sm3(data, DATA_SIZE);
    OPENSSL_free(data);

    unload:
    if (prov_kae) OSSL_PROVIDER_unload(prov_kae);
    if (prov_def) OSSL_PROVIDER_unload(prov_def);

    return 0;
}
