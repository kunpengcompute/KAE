#include "testsuit_common.h"

using namespace std;

struct CipherParam
{
    const char *evp_;
    int len_;
public:
    CipherParam(const char *evp, int len) : 
        evp_(evp), len_(len)
    {
    }
};

struct cipher_ctx_t {
    EVP_CIPHER_CTX*     ctx;
    const EVP_CIPHER*   cipher;
    ENGINE *            e;
    int                 decrypt;
    uint8_t*            buf_in;
    uint8_t*            buf_out;
    int                 buf_len;
    int                 inl;
    int                 outl;
    uint8_t             key[64];
    uint8_t             iv[16];
    void set_engine(ENGINE *engine) 
    {
        this->e = engine;
    }
};

class CipherAsyncTest : public testing::TestWithParam<CipherParam>
{
    cipher_ctx_t* cipher_ctx_;
    static ENGINE *engine_;
public:
    cipher_ctx_t* GetCipherCtx(CipherParam &param)
    {
        return init_cipher_ctx(param.evp_, param.len_);
    }

    ENGINE* GetEngine()
    {
        return engine_;
    }

    static vector<CipherParam> GenerateData()
    {
        vector<CipherParam> ret;
        ret.push_back(CipherParam("sm4-cbc",  191));        //0
        ret.push_back(CipherParam("sm4-cbc",  256));
        ret.push_back(CipherParam("sm4-cbc",  512));
        ret.push_back(CipherParam("sm4-cbc",  1024));
        ret.push_back(CipherParam("sm4-cbc",  512*1024));
        ret.push_back(CipherParam("sm4-cbc",  513*1024));
        ret.push_back(CipherParam("sm4-ctr",  191));        //6
        ret.push_back(CipherParam("sm4-ctr",  256));
        ret.push_back(CipherParam("sm4-ctr",  512));
        ret.push_back(CipherParam("sm4-ctr",  1024));
        ret.push_back(CipherParam("sm4-ctr",  512*1024));
        ret.push_back(CipherParam("sm4-ctr",  513*1024));
        ret.push_back(CipherParam("sm4-ecb",  191));        //12
        ret.push_back(CipherParam("sm4-ecb",  256));
        ret.push_back(CipherParam("sm4-ecb",  512));
        ret.push_back(CipherParam("sm4-ecb",  1024));
        ret.push_back(CipherParam("sm4-ecb",  512*1024));
        ret.push_back(CipherParam("sm4-ecb",  513*1024));
        ret.push_back(CipherParam("sm4-ofb",  191));        //18
        ret.push_back(CipherParam("sm4-ofb",  256));
        ret.push_back(CipherParam("sm4-ofb",  512));
        ret.push_back(CipherParam("sm4-ofb",  1024));
        ret.push_back(CipherParam("sm4-ofb",  512*1024));
        ret.push_back(CipherParam("sm4-ofb",  513*1024));

        ret.push_back(CipherParam("aes-128-cbc",  1024));
        ret.push_back(CipherParam("aes-192-cbc",  1024));
        ret.push_back(CipherParam("aes-256-cbc",  1024));
        ret.push_back(CipherParam("aes-128-ctr",  1024));
        ret.push_back(CipherParam("aes-192-ctr",  1024));
        ret.push_back(CipherParam("aes-256-ctr",  1024));
        ret.push_back(CipherParam("aes-128-ecb",  1024));
        ret.push_back(CipherParam("aes-192-ecb",  1024));
        ret.push_back(CipherParam("aes-256-ecb",  1024));
        ret.push_back(CipherParam("aes-128-xts",  1024));
        ret.push_back(CipherParam("aes-192-xts",  1024));

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

    cipher_ctx_t *init_cipher_ctx(const char* evp, int datalen)
    {
        cipher_ctx_t *cipher_ctx = (cipher_ctx_t *)malloc(sizeof(cipher_ctx_t));
    
        cipher_ctx->ctx = EVP_CIPHER_CTX_new();
        if (cipher_ctx->ctx == NULL) {
            return NULL;
        }
        (void)rand_buffer(cipher_ctx->key, 64);
        (void)rand_buffer(cipher_ctx->iv, 16);
    
        int buf_len = datalen + ((datalen / 4096 + 1) * 16); // 确保足够的缓存区
        cipher_ctx->buf_in = (uint8_t *)malloc(buf_len);
        (void)rand_buffer(cipher_ctx->buf_in, buf_len);
        cipher_ctx->inl = datalen;
        
        cipher_ctx->buf_out = (uint8_t *)malloc(buf_len);
        memset(cipher_ctx->buf_out, 0, buf_len);
    
        cipher_ctx->buf_len = buf_len;
        cipher_ctx->cipher = get_evp_cipher(evp);
        cipher_ctx->e = NULL;

        return cipher_ctx;
    }

    static void swap_dup_cipher_ctx_inout(cipher_ctx_t *other_ctx)
    {
        memcpy(other_ctx->buf_in, other_ctx->buf_out, other_ctx->outl);
        other_ctx->inl = other_ctx->outl;
        memset(other_ctx->buf_out, 0, other_ctx->outl);
        other_ctx->outl = 0;
    }

    static void cipher_ctx_cleanup(cipher_ctx_t *other_ctx)
    {
        if (other_ctx) {
            if (other_ctx->ctx != NULL) {
                EVP_CIPHER_CTX_free(other_ctx->ctx);
                other_ctx->ctx = NULL;
            }
            free(other_ctx->buf_in);
            free(other_ctx->buf_out);
            free(other_ctx);
        }
    }

    static cipher_ctx_t *dup_cipher_ctx(cipher_ctx_t *src)
    {
        cipher_ctx_t *dst = (cipher_ctx_t *)malloc(sizeof(cipher_ctx_t));
        
        dst->ctx = EVP_CIPHER_CTX_new();
        memcpy(dst->key, src->key, 64);
        memcpy(dst->iv, src->iv, 16);

        dst->buf_in = (uint8_t *)malloc(src->buf_len);
        memcpy(dst->buf_in, src->buf_in, src->buf_len);
        dst->inl = src->inl;

        dst->buf_out = (uint8_t *)malloc(src->buf_len);
        memset(dst->buf_out, 0, src->buf_len);
        dst->outl = 0;

        dst->buf_len = src->buf_len;
        
        dst->cipher = src->cipher;
        dst->e = src->e;

        //EVP_CIPHER_CTX_copy(dst->ctx, src->ctx);

        return dst;
    }

    const EVP_CIPHER* get_evp_cipher(const char* evp)
    {
        const EVP_CIPHER*   cipher = NULL;
    
        if (strcmp(evp, "sm4-cbc") == 0) {
            cipher = EVP_sm4_cbc();
        } else if (strcmp(evp, "sm4-ctr") == 0) {
            cipher = EVP_sm4_ctr();
        } else if (strcmp(evp, "sm4-ecb") == 0) {
            cipher = EVP_sm4_ecb();
        } else if (strcmp(evp, "sm4-ofb") == 0) {
            cipher = EVP_sm4_ofb();
        } else if (strcmp(evp, "aes-128-cbc") == 0) {
            cipher = EVP_aes_128_cbc();
        } else if (strcmp(evp, "aes-128-ctr") == 0) {
            cipher = EVP_aes_128_ctr();
        } else if (strcmp(evp, "aes-128-ecb") == 0) {
            cipher = EVP_aes_128_ecb();
        } else if (strcmp(evp, "aes-128-xts") == 0) {
            cipher = EVP_aes_128_xts();
        } else if (strcmp(evp, "aes-192-cbc") == 0) {
            cipher = EVP_aes_192_cbc();
        } else if (strcmp(evp, "aes-192-ctr") == 0) {
            cipher = EVP_aes_192_ctr();
        } else if (strcmp(evp, "aes-192-ecb") == 0) {
            cipher = EVP_aes_192_ecb();
        } else if (strcmp(evp, "aes-256-cbc") == 0) {
            cipher = EVP_aes_256_cbc();
        } else if (strcmp(evp, "aes-256-ctr") == 0) {
            cipher = EVP_aes_256_ctr();
        } else if (strcmp(evp, "aes-256-ecb") == 0) {
            cipher = EVP_aes_256_ecb();
        } else if (strcmp(evp, "aes-256-xts") == 0) {
            cipher = EVP_aes_256_xts();
        } else {
            //printf("unknow evp method, default method(sm4-cbc) used");
            cipher = EVP_sm4_cbc();
        }
        
        return cipher;
    }
};

ENGINE* CipherAsyncTest::engine_ = NULL;

INSTANTIATE_TEST_CASE_P(InitCipherAsyncTestData, 
    CipherAsyncTest, ::testing::ValuesIn(CipherAsyncTest::GenerateData()));


int do_evp_cihper_encrypt_job(void *args)
{
    int ret = -1;
    cipher_ctx_t  *cipher_ctx = *(cipher_ctx_t **)args;

    EVP_CIPHER_CTX *ctx     = cipher_ctx->ctx;
    uint8_t *key            = cipher_ctx->key;
    uint8_t *iv             = cipher_ctx->iv;
    uint8_t *buf_in         = cipher_ctx->buf_in;
    uint8_t *buf_out        = cipher_ctx->buf_out;
    int inl                 = cipher_ctx->inl;
    int outl                = cipher_ctx->outl;
    const EVP_CIPHER *cipher = cipher_ctx->cipher;
    ENGINE *e               = cipher_ctx->e;

    ret = EVP_EncryptInit_ex(ctx, cipher, e, key, iv);
    if (ret == 0) {
        printf("EVP_EncryptInit_ex error \n");
        return 0;
    }

    ret = EVP_EncryptUpdate(ctx, buf_out, &outl, buf_in, inl);
    if (ret == 0) {
        printf("EVP_EncryptUpdate error \n");
        return 0;
    }

    int tmplen = 0;
    ret = EVP_EncryptFinal(ctx, buf_out + outl, &tmplen);
    if (ret == 0) {
        printf("EVP_EncryptFinal error \n");
        return 0;
    }

    outl += tmplen;
    cipher_ctx->outl = outl;

    return ret;
}

int do_evp_cihper_decrypt_job(void *args)
{
    int ret = -1;
    cipher_ctx_t  *cipher_ctx = *(cipher_ctx_t **)args;

    EVP_CIPHER_CTX *ctx     = cipher_ctx->ctx;
    uint8_t *key            = cipher_ctx->key;
    uint8_t *iv             = cipher_ctx->iv;
    uint8_t *buf_in         = cipher_ctx->buf_in;
    uint8_t *buf_out        = cipher_ctx->buf_out;
    int inl                 = cipher_ctx->inl;
    int outl                = cipher_ctx->outl;
    const EVP_CIPHER *cipher = cipher_ctx->cipher;
    ENGINE *e               = cipher_ctx->e;

    ret = EVP_DecryptInit_ex(ctx, cipher, e, key, iv);
    if (ret == 0) {
        printf("EVP_DecryptInit_ex error \n");
        return 0;
    }

    ret = EVP_DecryptUpdate(ctx, buf_out, &outl, buf_in, inl);
    if (ret == 0) {
        printf("EVP_DecryptUpdate error \n");
        return 0;
    }

    int tmplen = 0;
    ret = EVP_DecryptFinal_ex(ctx, buf_out + outl, &tmplen);
    if (ret == 0) {
        printf("EVP_DecryptFinal error \n");
        return 0;
    }

    outl += tmplen;
    cipher_ctx->outl = outl;

    return ret;
}

int start_async_job(int (*async_function) (void *), cipher_ctx_t* cipher_ctx)
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
        switch(ASYNC_start_job(&job, ctx, &ret, async_function, &cipher_ctx, sizeof(cipher_ctx_t*))) {
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

//验证两次同步加密解密是否一致
TEST_P(CipherAsyncTest, sync_cipher_test)
{
    int ret = -1;

    CipherParam cipher_param = GetParam();
    //printf("test input cipher param %s  %d\n  ", cipher_param.evp_, cipher_param.len_);
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    cipher_ctx_t* cipher_ctx = GetCipherCtx(cipher_param);
    ASSERT_TRUE(cipher_ctx != NULL);

    //做软算同步加密
    ret = do_evp_cihper_encrypt_job(&cipher_ctx);
    ASSERT_TRUE(ret != 0);

    for (int i = 0; i < 500; i++) {
        //做硬算同步加密，对比结果
        cipher_ctx_t *other_ctx = dup_cipher_ctx(cipher_ctx);
        ASSERT_TRUE(other_ctx != NULL);

        other_ctx->set_engine(e);
        ret = do_evp_cihper_encrypt_job(&other_ctx);
        ASSERT_TRUE(ret != 0);

        ret = memcmp(cipher_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
        ASSERT_TRUE(ret == 0);

        //做硬算同步加密，和输入对比结果
        swap_dup_cipher_ctx_inout(other_ctx);
        ret = do_evp_cihper_decrypt_job(&other_ctx);
        ASSERT_TRUE(ret != 0);

        ret = memcmp(other_ctx->buf_out, cipher_ctx->buf_in, cipher_ctx->inl);
        ASSERT_TRUE(ret == 0);

        cipher_ctx_cleanup(other_ctx);
    }
    cipher_ctx_cleanup(cipher_ctx);
}

//验证硬件同步加密，硬算异步解密是否一致
TEST_P(CipherAsyncTest, async_cipher_test1)
{
    int ret = -1;

    CipherParam cipher_param = GetParam();
    //printf("test input cipher param %s  %d\n  ", cipher_param.evp_, cipher_param.len_);
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    cipher_ctx_t* cipher_ctx = GetCipherCtx(cipher_param);
    ASSERT_TRUE(cipher_ctx != NULL);

    //做软算同步加密
    ret = do_evp_cihper_encrypt_job(&cipher_ctx);
    ASSERT_TRUE(ret != 0);

    //做硬算同步加密，对比结果
    cipher_ctx_t *other_ctx = dup_cipher_ctx(cipher_ctx);
    ASSERT_TRUE(other_ctx != NULL);

    other_ctx->set_engine(e);
    ret = do_evp_cihper_encrypt_job(&other_ctx);
    ASSERT_TRUE(ret != 0);

    ret = memcmp(cipher_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //做硬算异步解密，和输入对比结果
    swap_dup_cipher_ctx_inout(other_ctx);
    start_async_job(do_evp_cihper_decrypt_job, other_ctx);

    ret = memcmp(other_ctx->buf_out, cipher_ctx->buf_in, cipher_ctx->inl);
    ASSERT_TRUE(ret == 0);

    cipher_ctx_cleanup(other_ctx);
    cipher_ctx_cleanup(cipher_ctx);
}

//验证硬件异步加密，硬算同步解密是否一致
TEST_P(CipherAsyncTest, async_cipher_test2)
{
    int ret = -1;

    CipherParam cipher_param = GetParam();
    //printf("test input cipher param %s  %d\n  ", cipher_param.evp_, cipher_param.len_);
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    cipher_ctx_t* cipher_ctx = GetCipherCtx(cipher_param);
    ASSERT_TRUE(cipher_ctx != NULL);

    //做软算同步加密
    ret = do_evp_cihper_encrypt_job(&cipher_ctx);
    ASSERT_TRUE(ret != 0);

    //做硬算同步加密，对比结果
    cipher_ctx_t *other_ctx = dup_cipher_ctx(cipher_ctx);
    ASSERT_TRUE(other_ctx != NULL);

    other_ctx->set_engine(e);
    start_async_job(do_evp_cihper_encrypt_job, other_ctx);

    ret = memcmp(cipher_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //做硬算同步解密，和输入对比结果
    swap_dup_cipher_ctx_inout(other_ctx);
    ret = do_evp_cihper_decrypt_job(&other_ctx);
    ASSERT_TRUE(ret != 0);

    ret = memcmp(other_ctx->buf_out, cipher_ctx->buf_in, cipher_ctx->inl);
    ASSERT_TRUE(ret == 0);

    cipher_ctx_cleanup(other_ctx);
    cipher_ctx_cleanup(cipher_ctx);
}

//验证硬算异步加密，硬算异步解密是否一致
TEST_P(CipherAsyncTest, async_cipher_test3)
{
    int ret = -1;

    CipherParam cipher_param = GetParam();
    printf("test input cipher param %s  %d\n  ", cipher_param.evp_, cipher_param.len_);
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    cipher_ctx_t* cipher_ctx = GetCipherCtx(cipher_param);
    ASSERT_TRUE(cipher_ctx != NULL);

    //做软算同步加密
    ret = do_evp_cihper_encrypt_job(&cipher_ctx);
    ASSERT_TRUE(ret != 0);

    //做硬算异步加密，对比结果
    cipher_ctx_t *other_ctx = dup_cipher_ctx(cipher_ctx);
    ASSERT_TRUE(other_ctx != NULL);

    other_ctx->set_engine(e);
    start_async_job(do_evp_cihper_encrypt_job, other_ctx);

    ret = memcmp(cipher_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //做硬算异步解密，和输入对比结果
    swap_dup_cipher_ctx_inout(other_ctx);
    start_async_job(do_evp_cihper_decrypt_job, other_ctx);

    ret = memcmp(other_ctx->buf_out, cipher_ctx->buf_in, cipher_ctx->inl);
    ASSERT_TRUE(ret == 0);

    cipher_ctx_cleanup(other_ctx);
    cipher_ctx_cleanup(cipher_ctx);
}

//验证软算异步加密，硬算异步解密是否一致
TEST_P(CipherAsyncTest, async_cipher_test4)
{
    int ret = -1;

    CipherParam cipher_param = GetParam();
    printf("test input cipher param %s  %d\n  ", cipher_param.evp_, cipher_param.len_);
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    cipher_ctx_t* cipher_ctx = GetCipherCtx(cipher_param);
    ASSERT_TRUE(cipher_ctx != NULL);

    //做软算同步加密
    ret = do_evp_cihper_encrypt_job(&cipher_ctx);
    ASSERT_TRUE(ret != 0);

    //做软算异步加密，对比结果
    cipher_ctx_t *other_ctx = dup_cipher_ctx(cipher_ctx);
    ASSERT_TRUE(other_ctx != NULL);

    start_async_job(do_evp_cihper_encrypt_job, other_ctx);

    ret = memcmp(cipher_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //做硬算异步解密，和输入对比结果
    swap_dup_cipher_ctx_inout(other_ctx);
    other_ctx->set_engine(e);
    start_async_job(do_evp_cihper_decrypt_job, other_ctx);

    ret = memcmp(other_ctx->buf_out, cipher_ctx->buf_in, cipher_ctx->inl);
    ASSERT_TRUE(ret == 0);

    cipher_ctx_cleanup(other_ctx);
}

//验证异步硬算对文件加密，异步软算解密是否一致
TEST_P(CipherAsyncTest, async_cipher_test5)
{
    int ret = -1;

    CipherParam cipher_param = GetParam();
    printf("test input cipher param %s  %d\n  ", cipher_param.evp_, cipher_param.len_);
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    cipher_ctx_t* cipher_ctx = GetCipherCtx(cipher_param);
    ASSERT_TRUE(cipher_ctx != NULL);

    //做软算同步加密
    ret = do_evp_cihper_encrypt_job(&cipher_ctx);
    ASSERT_TRUE(ret != 0);

    //做硬算异步加密，对比结果
    cipher_ctx_t *other_ctx = dup_cipher_ctx(cipher_ctx);
    ASSERT_TRUE(other_ctx != NULL);
    other_ctx->set_engine(e);
    start_async_job(do_evp_cihper_encrypt_job, other_ctx);

    ret = memcmp(cipher_ctx->buf_out, other_ctx->buf_out, other_ctx->outl);
    ASSERT_TRUE(ret == 0);

    //做软算异步解密，和输入对比结果
    swap_dup_cipher_ctx_inout(other_ctx);
    other_ctx->set_engine(NULL);
    start_async_job(do_evp_cihper_decrypt_job, other_ctx);

    ret = memcmp(other_ctx->buf_out, cipher_ctx->buf_in, cipher_ctx->inl);
    ASSERT_TRUE(ret == 0);

    cipher_ctx_cleanup(other_ctx);
}

void* sync_ciphers_routine(void *args) 
{
    cipher_ctx_t* cipher_ctx  = (cipher_ctx_t*)args;
    if (cipher_ctx == NULL) {
        printf("memcmp failed\n");
        return NULL;
    }

    for (int i = 0; i < 1000; i++) {   
        //做硬算同步加密
        cipher_ctx_t *other_ctx = CipherAsyncTest::dup_cipher_ctx(cipher_ctx);
        if (other_ctx == NULL) {
            printf("dup_cipher_ctx failed\n");
            return NULL;
        }

        int ret = do_evp_cihper_encrypt_job(&other_ctx);
        if (ret == 0) {
            printf("do_evp_cihper_encrypt_job failed\n");
            return NULL;
        }

        //做硬算同步加密，和输入对比结果
        CipherAsyncTest::swap_dup_cipher_ctx_inout(other_ctx);
        ret = do_evp_cihper_decrypt_job(&other_ctx);
        if (ret == 0) {
            printf("do_evp_cihper_decrypt_job failed\n");
            return NULL;
        }
        ret = memcmp(other_ctx->buf_out, cipher_ctx->buf_in, cipher_ctx->inl);
        if (ret != 0) {
            printf("memcmp failed\n");
            return NULL;
        }

        CipherAsyncTest::cipher_ctx_cleanup(other_ctx);
    }

    return NULL;
}
//验证多线程
TEST_P(CipherAsyncTest, sync_cipher_multi_thread_test)
{
    ENGINE* e = GetEngine();
    ASSERT_TRUE(e != NULL);

    CipherParam cipher_param = GetParam();
    //printf("test input cipher param %s  %d\n  ", cipher_param.evp_, cipher_param.len_);

    int thds = 10;
    cipher_ctx_t* cipher_ctx[thds];

    for (int i = 0; i < thds; ++i) {
        cipher_ctx[i] = GetCipherCtx(cipher_param);
        ASSERT_TRUE(cipher_ctx[i] != NULL);
        cipher_ctx[i]->set_engine(e);
    }

    pthread_t *tids = new pthread_t[thds];
    for (int i = 0; i < thds; ++i) {
        pthread_create(&tids[i], NULL, sync_ciphers_routine, (void*)cipher_ctx[i]);
    }

    for (int i = 0; i < thds; ++i) {
        pthread_join(tids[i], NULL);
    }

    delete[] tids;
}
