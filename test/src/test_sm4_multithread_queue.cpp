#include "testsuit_common.h"

#define NUM_THREADS 10   //Number of threads

class Sm4MultithreadQueueTestGroup:public testing::Test
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

void* sm4_ctr_cipher(void *arg)
{
    ENGINE *e;
    e = (ENGINE *)arg;
    sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
    return NULL;
}

void* sm4_cbc_cipher(void *arg)
{
    ENGINE *e;
    e = (ENGINE *)arg;
    sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
    return NULL;
}

TEST_F(Sm4MultithreadQueueTestGroup, sm4_ctr_cipher_multithread_queue_multiplexing)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    ENGINE *e;
    e = ENGINE_by_id("kae");
    
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret = pthread_create(&tids[i], NULL, sm4_ctr_cipher, (void *)e);
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
        ret1 = pthread_create(&tids1[i], NULL, sm4_ctr_cipher, (void *)e);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(e);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}

TEST_F(Sm4MultithreadQueueTestGroup, sm4_ctr_cipher_multithread_queue_unmultiplexing)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    ENGINE *e;
    e = ENGINE_by_id("kae");
    
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret = pthread_create(&tids[i], NULL, sm4_ctr_cipher, (void *)e);
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
        ret1 = pthread_create(&tids1[i], NULL, sm4_ctr_cipher, (void *)e);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(e);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}

TEST_F(Sm4MultithreadQueueTestGroup, sm4_cbc_cipher_multithread_queue_multiplexing)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    ENGINE *e;
    e = ENGINE_by_id("kae");
    
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret = pthread_create(&tids[i], NULL, sm4_cbc_cipher, (void *)e);
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
        ret1 = pthread_create(&tids1[i], NULL, sm4_cbc_cipher, (void *)e);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(e);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}

TEST_F(Sm4MultithreadQueueTestGroup, sm4_cbc_cipher_multithread_queue_unmultiplexing)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    ENGINE *e;
    e = ENGINE_by_id("kae");
    
    for (int i = 0; i < NUM_THREADS; ++i) 
    {
        ret = pthread_create(&tids[i], NULL, sm4_cbc_cipher, (void *)e);
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
        ret1 = pthread_create(&tids1[i], NULL, sm4_cbc_cipher, (void *)e);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(e);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}
