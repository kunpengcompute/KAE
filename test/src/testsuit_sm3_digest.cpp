#include "testsuit_common.h"

class DigestTestGroup:public testing::Test
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

//sm3软算提取摘要
int sm3_soft_digest_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *sm3 = EVP_sm3();
    int ret = sec2_loop_digest(e, sm3, SM3_SOFT_PACKAGE_SIZE, 1);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, sm3_soft_digest_mode1)
{
    EXPECT_EQ(sm3_soft_digest_mode1(),0);
}

int sm3_soft_digest_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *sm3 = EVP_sm3();
    int ret = sec2_loop_digest(e, sm3, SM3_SOFT_PACKAGE_SIZE/2, 2);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, sm3_soft_digest_mode2)
{
    EXPECT_EQ(sm3_soft_digest_mode2(),0);
}

//sm3硬算提取摘要
int sm3_engine_digest_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *sm3 = EVP_sm3();
    int ret = sec2_loop_digest(e, sm3, SM3_ENGINE_PACKAGE_SIZE, 1);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, sm3_engine_digest_mode1)
{
    EXPECT_EQ(sm3_engine_digest_mode1(),0);
}

int sm3_engine_digest_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *sm3 = EVP_sm3();
    int ret = sec2_loop_digest(e, sm3, SM3_ENGINE_PACKAGE_SIZE/2, 2);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, sm3_engine_digest_mode2)
{
    EXPECT_EQ(sm3_engine_digest_mode2(),0);
}

//md5软算提取摘要
int md5_soft_digest_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *md5 = EVP_md5();
    int ret = sec2_loop_digest(e, md5, SM3_SOFT_PACKAGE_SIZE, 1);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, md5_soft_digest_mode1)
{
    EXPECT_EQ(md5_soft_digest_mode1(),0);
}

int md5_soft_digest_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *md5 = EVP_md5();
    int ret = sec2_loop_digest(e, md5, SM3_SOFT_PACKAGE_SIZE/2, 2);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, md5_soft_digest_mode2)
{
    EXPECT_EQ(md5_soft_digest_mode2(),0);
}

//md5硬算提取摘要
int md5_engine_digest_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *md5 = EVP_md5();
    int ret = sec2_loop_digest(e, md5, SM3_ENGINE_PACKAGE_SIZE, 1);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, md5_engine_digest_mode1)
{
    EXPECT_EQ(md5_engine_digest_mode1(),0);
}

int md5_engine_digest_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    const EVP_MD *md5 = EVP_md5();
    int ret = sec2_loop_digest(e, md5, SM3_ENGINE_PACKAGE_SIZE/2, 2);
    ENGINE_free(e);

    return ret;
}

TEST_F(DigestTestGroup, md5_engine_digest_mode2)
{
    EXPECT_EQ(md5_engine_digest_mode2(),0);
}

TEST_F(DigestTestGroup, case3_mode_fork)
{
    pid_t pid = fork();
    if (pid > 0){
        EXPECT_EQ(sm3_soft_digest_mode1(),0);
        EXPECT_EQ(sm3_soft_digest_mode2(),0);
        EXPECT_EQ(sm3_engine_digest_mode1(),0);
        EXPECT_EQ(sm3_engine_digest_mode2(),0);
        EXPECT_EQ(md5_soft_digest_mode1(),0);
        EXPECT_EQ(md5_soft_digest_mode2(),0);
        EXPECT_EQ(md5_engine_digest_mode1(),0);
        EXPECT_EQ(md5_engine_digest_mode2(),0);
    }else{
        EXPECT_EQ(sm3_soft_digest_mode1(),0);
        EXPECT_EQ(sm3_soft_digest_mode2(),0);
        EXPECT_EQ(sm3_engine_digest_mode1(),0);
        EXPECT_EQ(sm3_engine_digest_mode2(),0);
        EXPECT_EQ(md5_soft_digest_mode1(),0);
        EXPECT_EQ(md5_soft_digest_mode2(),0);
        EXPECT_EQ(md5_engine_digest_mode1(),0);
        EXPECT_EQ(md5_engine_digest_mode2(),0);
    }
}
