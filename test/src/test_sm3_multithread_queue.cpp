#include "testsuit_common.h"

#define NUM_THREADS 10   //线程个数
class Sm3MultithreadQueueTestGroup:public testing::Test
{
protected:
    virtual void SetUp()
    {
        init_openssl();
    }
    virtual void TearDown()
    {
    }
};

void* sm3_digest(void *arg)
{
    ENGINE *engine;
    engine = (ENGINE *)arg;
    const EVP_MD *md_sm3 = EVP_sm3();
    sec2_loop_digest(engine, md_sm3, SM3_ENGINE_PACKAGE_SIZE, 1);
    return NULL;
}

TEST_F(Sm3MultithreadQueueTestGroup, sm3_multithread_queuedigest_multiplexing)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
    
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret = pthread_create(&tids[i], NULL, sm3_digest, (void *)engine);
        if (ret == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    sleep(3);
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret1 = pthread_create(&tids1[i], NULL, sm3_digest, (void *)engine);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(engine);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}

TEST_F(Sm3MultithreadQueueTestGroup, sm3_multithread_queuedigest_unmultiplexing)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
    
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret = pthread_create(&tids[i], NULL, sm3_digest, (void *)engine);
        if (ret == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    sleep(8);
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret1 = pthread_create(&tids1[i], NULL, sm3_digest, (void *)engine);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(engine);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}