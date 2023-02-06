#include "testsuit_common.h"

class Sm4QueueTestGroup:public testing::Test
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

int sm4_ctr_cipher_queue_multiplexing(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    for (int i = 0; i <= 9; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
        sleep(2);
        if(ret == 0)
            result++;
    }
    ENGINE_free(e);

    return (result == 10 ? 0 : -1);
}

TEST_F(Sm4QueueTestGroup, sm4_ctr_cipher_queue_multiplexing)
{
    EXPECT_EQ(sm4_ctr_cipher_queue_multiplexing(),0);
}

int sm4_ctr_cipher_queue_unmultiplexing(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    for (int i = 0; i <= 9; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
        sleep(8);
        if(ret == 0)
            result++;
    }
    ENGINE_free(e);

    return (result == 10 ? 0 : -1);
}

TEST_F(Sm4QueueTestGroup, sm4_ctr_cipher_queue_unmultiplexing)
{
    EXPECT_EQ(sm4_ctr_cipher_queue_unmultiplexing(),0);
}

int sm4_cbc_cipher_queue_multiplexing(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    for (int i = 0; i <= 9; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
        sleep(2);
        if(ret == 0)
            result++;
    }
    ENGINE_free(e);

    return (result == 10 ? 0 : -1);
}

TEST_F(Sm4QueueTestGroup, sm4_cbc_cipher_queue_multiplexing)
{
    EXPECT_EQ(sm4_cbc_cipher_queue_multiplexing(),0);
}

int sm4_cbc_cipher_queue_unmultiplexing(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    for (int i = 0; i <= 9; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
        sleep(8);
        if(ret == 0)
            result++;
    }
    ENGINE_free(e);

    return (result == 10 ? 0 : -1);
}

TEST_F(Sm4QueueTestGroup, sm4_cbc_cipher_queue_unmultiplexing)
{
    EXPECT_EQ(sm4_cbc_cipher_queue_unmultiplexing(),0);
}
