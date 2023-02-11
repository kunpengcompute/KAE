#include "testsuit_common.h"

class Sm3QueueTestGroup:public testing::Test
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

int sm3_digest_queue_multiplexing(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *md_sm3 = EVP_sm3();
    int result=0;
    
    for (int i = 0; i <= 9; i++) {
        int ret = sec2_loop_digest(e, md_sm3, SM3_ENGINE_PACKAGE_SIZE, 1);
        if (ret == 0)
            result++;
        sleep(2);
    }
    ENGINE_free(e);

    return (result == 10 ? 0 : -1);
}

TEST_F(Sm3QueueTestGroup, sm3_digest_queue_multiplexing)
{
    EXPECT_EQ(sm3_digest_queue_multiplexing(),0);
}

int sm3_digest_queue_unmultiplexing(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *md_sm3 = EVP_sm3();
    int result=0;
    
    for (int i = 0; i <= 9; i++) {
        int ret = sec2_loop_digest(e, md_sm3, SM3_ENGINE_PACKAGE_SIZE, 1);
        if (ret == 0)
            result++;
        sleep(8);
    }
    ENGINE_free(e);

    return (result == 10 ? 0 : -1);
}

TEST_F(Sm3QueueTestGroup, sm3_digest_queue_unmultiplexing)
{
    EXPECT_EQ(sm3_digest_queue_unmultiplexing(),0);
}