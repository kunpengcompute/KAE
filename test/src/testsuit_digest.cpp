
#include "testsuit_common.h"

#define OUTPUTLEN  32

using namespace std;

struct DigestParam
{
    const char *evp_;
    int len_;
public:
    DigestParam(const char *evp, int len) : 
        evp_(evp), len_(len)
    {
    }
};

struct digest_ctx_t {
    const EVP_MD* md;
    ENGINE *e;
    uint8_t* buf_in;
    uint8_t  buf_out[OUTPUTLEN];
    int inl;
    int outl;
    void set_engine(ENGINE *engine) 
    {
        this->e = engine;
    }
};

static digest_ctx_t *init_digest_ctx(const char* name, int datalen);
static digest_ctx_t *dup_digest_ctx(digest_ctx_t *src);
static const EVP_MD * get_evp_digest(const char* evp);

class DigestAsyncTest : public testing::TestWithParam<DigestParam>
{
public:
    static ENGINE *engine_;
public:
    digest_ctx_t* GetDigestCtx(DigestParam &param)
    {
        return init_digest_ctx(param.evp_, param.len_);
    }

    ENGINE* GetEngine()
    {
        return engine_;
    }

    static vector<DigestParam> GenerateData()
    {
        vector<DigestParam> ret;
        ret.push_back(DigestParam("sm3",  1024));
        ret.push_back(DigestParam("sm3",  2048));
        ret.push_back(DigestParam("sm3",  512*1024));
        ret.push_back(DigestParam("sm3",  513*1024));
        ret.push_back(DigestParam("sm3",  513));

        ret.push_back(DigestParam("md5",  1024));
        ret.push_back(DigestParam("md5",  2048));
        ret.push_back(DigestParam("md5",  512*1024));
        ret.push_back(DigestParam("md5",  513*1024));
        ret.push_back(DigestParam("md5",  513));
        ret.push_back(DigestParam("md5",  192));

        return ret;
    }

    virtual void SetUp()
    {
        init_openssl();
        engine_ = ENGINE_by_id("kae");
        if (engine_ == NULL) {
            printf("Fail to get enigne kae\n");
            abort();
        }
    }
    virtual void TearDown()
    {
        ENGINE_free(engine_);
        engine_ = NULL;
    }
};

ENGINE* DigestAsyncTest::engine_ = NULL;

INSTANTIATE_TEST_CASE_P(InitDigestAsyncTestData, 
    DigestAsyncTest, ::testing::ValuesIn(DigestAsyncTest::GenerateData()));

static digest_ctx_t *init_digest_ctx(const char* name, int datalen)
{
    digest_ctx_t *digest_ctx = (digest_ctx_t *)malloc(sizeof(digest_ctx_t));

    digest_ctx->md = get_evp_digest(name);
    if (digest_ctx->md == NULL) {
        return NULL;
    }

    digest_ctx->buf_in = (uint8_t *)malloc(datalen);
    (void)rand_buffer(digest_ctx->buf_in, datalen);
    digest_ctx->inl = datalen;

    memset(digest_ctx->buf_out, 0, OUTPUTLEN);
    digest_ctx->outl = OUTPUTLEN;

    digest_ctx->e = NULL;

    return digest_ctx;
}

static void digest_ctx_cleanup(digest_ctx_t *other_ctx)
{
    if (other_ctx) {            
        free(other_ctx->buf_in);
        free(other_ctx);
        other_ctx = NULL;
    }
}

static digest_ctx_t *dup_digest_ctx(digest_ctx_t *src)
{
    digest_ctx_t *dst = (digest_ctx_t *)malloc(sizeof(digest_ctx_t));

    dst->buf_in = (uint8_t *)malloc(src->inl);
    memcpy(dst->buf_in, src->buf_in, src->inl);
    dst->inl = src->inl;

    memset(dst->buf_out, 0, OUTPUTLEN);
    dst->outl = 0;

    dst->md = src->md;
    dst->e = src->e;

    return dst;
}

static const EVP_MD * get_evp_digest(const char* evp)
{
    const EVP_MD*   digest = NULL;

    if (strcmp(evp, "sm3") == 0) {
        digest = EVP_sm3();
    } else if (strcmp(evp, "md5") == 0) {
        digest = EVP_md5();
    } else {
        printf("unknow evp method, default method(sm3) used");
        digest = EVP_sm3();
    }
    
    return digest;
}

static int do_evp_digest_job(void *args)
{
    int ret = -1;
    digest_ctx_t  *digest_ctx = *(digest_ctx_t **)args;
    
    const EVP_MD *md        = digest_ctx->md;
    uint8_t *buf_in         = digest_ctx->buf_in;
    uint8_t *buf_out        = digest_ctx->buf_out;
    int inl                 = digest_ctx->inl;
    uint32_t outl           = digest_ctx->outl;
    ENGINE *e               = digest_ctx->e;
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    ret = EVP_DigestInit_ex(md_ctx, md, e);
    if (ret == 0) {
        printf("EVP_DigestInit_ex error \n");
        return 0;
    }

    ret = EVP_DigestUpdate(md_ctx, buf_in, inl);
    if (ret == 0) {
        printf("EVP_DigestUpdate error \n");
        goto end;
    }

    ret = EVP_DigestFinal_ex(md_ctx, buf_out, &outl);
    if (ret == 0) {
        printf("EVP_EncryptFinal_ex error \n");
        goto end;
    }
    
    digest_ctx->outl = outl;

end:
    EVP_MD_CTX_free(md_ctx);
    
    return ret;
}

static void print_digest_stdout(digest_ctx_t *digest_ctx, digest_ctx_t *other_ctx)
{
    int i = 0;
    printf("hardware digest outlen = %d\n", digest_ctx->outl);
    for (i = 0; i < digest_ctx->outl; i++) {
        printf("%02x", digest_ctx->buf_out[i]);
    }
    printf("\n");

    printf("software digest outlen = %d\n", other_ctx->outl);
    for (i = 0; i < other_ctx->outl; i++) {
        printf("%02x", other_ctx->buf_out[i]);
    }
    printf("\n");
}

int start_async_job(int (*async_function) (void *), digest_ctx_t* digest_ctx)
{
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *ctx = NULL;
    int ret;
    OSSL_ASYNC_FD waitfd;
    fd_set waitfdset;
    size_t numfds;

    //printf("Starting...\n");

    ctx = ASYNC_WAIT_CTX_new();
    if (ctx == NULL) {
        printf("Failed to create ASYNC_WAIT_CTX\n");
        abort();
    }

    for (;;) {
        switch(ASYNC_start_job(&job, ctx, &ret, async_function, &digest_ctx, sizeof(digest_ctx_t*))) {
        case ASYNC_ERR:
        case ASYNC_NO_JOBS:
                //printf("An error occurred\n");
                goto end;
        case ASYNC_PAUSE:
                //printf("Job was paused\n");
                break;
        case ASYNC_FINISH:
                //printf("Job finished with return value %d\n", ret);
                goto end;
        }

        /* Wait for the job to be woken */
        //printf("Waiting for the job to be woken up\n");

        if (!ASYNC_WAIT_CTX_get_all_fds(ctx, NULL, &numfds)
                || numfds > 1) {
            printf("Unexpected number of fds\n");
            abort();
        }

        ASYNC_WAIT_CTX_get_all_fds(ctx, &waitfd, &numfds);
        FD_ZERO(&waitfdset);
        FD_SET(waitfd, &waitfdset);
        select(waitfd + 1, &waitfdset, NULL, NULL, NULL);
    }

end:
    ASYNC_WAIT_CTX_free(ctx);
    //printf("Finishing\n");

    return 0;
}

int sync_dgest_routine(void *args) 
{
    DigestParam digest_param = *(DigestParam*) args;

    digest_ctx_t* digest_ctx = init_digest_ctx(digest_param.evp_, digest_param.len_);
    digest_ctx->set_engine(DigestAsyncTest::engine_);

    digest_ctx_t *other_ctx = dup_digest_ctx(digest_ctx);
    other_ctx->set_engine(NULL);
    int ret = do_evp_digest_job(&other_ctx);
    if (ret == 0) {
        printf("do_evp_digest_job(&other_ctx) failed\n");
        return -1;
    }

    for (int i = 0; i < 500; i++) {
        ret = do_evp_digest_job(&digest_ctx);
        if (ret == 0) {
            printf("do_evp_digest_job(&digest_ctx) failed\n");
            return -1;
        }

        ret = memcmp(digest_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
        if (ret != 0) {
            printf("memcmp failed, other_ctx->inl %d  digest_ctx->inl %d, digest_param.len_ %d, i %d\n",
                other_ctx->inl, digest_ctx->inl, digest_param.len_, i);
            print_digest_stdout(digest_ctx, other_ctx);
            goto end;
        }
    }

end:
    digest_ctx_cleanup(digest_ctx);
    digest_ctx_cleanup(other_ctx);
    return ret;
}

//验证否软硬一致
TEST_P(DigestAsyncTest, sync_digest_test)
{
    DigestParam digest_param = GetParam();
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);
    sync_dgest_routine((void*)&digest_param);
}

//验证不同包长下摘要是否软硬一致
TEST_P(DigestAsyncTest, sync_dgest_multi_thread_a_test)
{
    DigestParam digest_param = GetParam();

    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    int ret = 0;
    digest_param.len_ += 1;
    ret = sync_dgest_routine((void*)&digest_param);
    ASSERT_TRUE(ret == 0);

    digest_param.len_ -= 2;
    ret = sync_dgest_routine((void*)&digest_param);
    ASSERT_TRUE(ret == 0);
}

//验证多线程是否软硬一致
TEST_P(DigestAsyncTest, sync_dgest_multi_thread_test)
{
    DigestParam digest_param = GetParam();

    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    int thds = 10;
    pthread_t *tids = new pthread_t[thds];
    for (int i = 0; i < thds; ++i) {
        pthread_create(&tids[i], NULL, (void* (*)(void*))sync_dgest_routine, (void*)&digest_param);
    }

    for (int i = 0; i < thds; ++i) {
        pthread_join(tids[i], NULL);
    }

    delete[] tids;
}

//验证同步异步加密解密是否一致
TEST_P(DigestAsyncTest, sync_and_async_digest_test)
{
    DigestParam digest_param = GetParam();
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    digest_ctx_t* digest_ctx = GetDigestCtx(digest_param);
    ASSERT_TRUE(digest_ctx != NULL);

    int ret = do_evp_digest_job(&digest_ctx);
    ASSERT_TRUE(ret != 0);

    //做硬算同步摘要，对比结果
    digest_ctx_t *other_ctx = dup_digest_ctx(digest_ctx);
    ASSERT_TRUE(other_ctx != NULL);

    other_ctx->set_engine(e);
    start_async_job(do_evp_digest_job, other_ctx);

    ret = memcmp(digest_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //print_digest_stdout(digest_ctx, other_ctx);

    digest_ctx_cleanup(other_ctx);
}

//验证两次异步加密解密是否一致
TEST_P(DigestAsyncTest, async_digest_test)
{
    DigestParam digest_param = GetParam();
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    digest_ctx_t* digest_ctx = GetDigestCtx(digest_param);
    ASSERT_TRUE(digest_ctx != NULL);

    start_async_job(do_evp_digest_job, digest_ctx);

    //做硬算异步摘要，对比结果
    digest_ctx_t *other_ctx = dup_digest_ctx(digest_ctx);
    ASSERT_TRUE(other_ctx != NULL);

    other_ctx->set_engine(e);
    start_async_job(do_evp_digest_job, other_ctx);

    int ret = memcmp(digest_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //print_digest_stdout(digest_ctx, other_ctx);

    digest_ctx_cleanup(other_ctx);
	digest_ctx_cleanup(digest_ctx);
}

//验证关闭异步功能，同步异步加密是否一致
TEST_P(DigestAsyncTest, enable_async_digest_test)
{
    DigestParam digest_param = GetParam();
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    digest_ctx_t* digest_ctx = GetDigestCtx(digest_param);
    ASSERT_TRUE(digest_ctx != NULL);

    start_async_job(do_evp_digest_job, digest_ctx);

    //做硬算异步摘要，对比结果
    digest_ctx_t *other_ctx = dup_digest_ctx(digest_ctx);
    ASSERT_TRUE(other_ctx != NULL);

    other_ctx->set_engine(e);
    ENGINE_ctrl_cmd_string(other_ctx->e, "KAE_CMD_ENABLE_ASYNC", "0", 0); 
    start_async_job(do_evp_digest_job, other_ctx);
    int ret = memcmp(digest_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    ENGINE_ctrl_cmd_string(other_ctx->e, "KAE_CMD_ENABLE_ASYNC", "1", 0); 
    start_async_job(do_evp_digest_job, other_ctx);
    ret = memcmp(digest_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //print_digest_stdout(digest_ctx, other_ctx);

    digest_ctx_cleanup(other_ctx);
}

