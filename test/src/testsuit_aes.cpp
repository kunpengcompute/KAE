#include "testsuit_common.h"

class AesCipherTestGroup:public testing::Test
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

//aes_ctr,16字节倍数
int aes_ctr_normal_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ctr(), EVP_aes_192_ctr(), EVP_aes_256_ctr()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 1, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ctr_normal_mode1)
{
    EXPECT_EQ(aes_ctr_normal_mode1(),0);
}

int aes_ctr_normal_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ctr(), EVP_aes_192_ctr(), EVP_aes_256_ctr()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 2, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ctr_normal_mode2)
{
    EXPECT_EQ(aes_ctr_normal_mode2(),0);
}

//aes_ctr,16字节非倍数
int aes_ctr_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ctr(), EVP_aes_192_ctr(), EVP_aes_256_ctr()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 1, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ctr_mode1)
{
    EXPECT_EQ(aes_ctr_mode1(),0);
}

int aes_ctr_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ctr(), EVP_aes_192_ctr(), EVP_aes_256_ctr()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 2, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ctr_mode2)
{
    EXPECT_EQ(aes_ctr_mode2(),0);
}

//aes_cbc,16字节倍数
int aes_cbc_normal_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_cbc(), EVP_aes_192_cbc(), EVP_aes_256_cbc()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 1, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_cbc_normal_mode1)
{
    EXPECT_EQ(aes_cbc_normal_mode1(),0);
}

int aes_cbc_normal_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_cbc(), EVP_aes_192_cbc(), EVP_aes_256_cbc()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 2, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_cbc_normal_mode2)
{
    EXPECT_EQ(aes_cbc_normal_mode2(),0);
}

//aes_cbc,16字节非倍数
int aes_cbc_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_cbc(), EVP_aes_192_cbc(), EVP_aes_256_cbc()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 1, 1);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_cbc_mode1)
{
    EXPECT_EQ(aes_cbc_mode1(),0);
}
/*
int aes_cbc_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_cbc(), EVP_aes_192_cbc(), EVP_aes_256_cbc()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 2, 1);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_cbc_mode2)
{
    EXPECT_EQ(aes_cbc_mode2(),0);
}
*/
//aes_ecb,16字节倍数
int aes_ecb_normal_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ecb(), EVP_aes_192_ecb(), EVP_aes_256_ecb()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 1, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ecb_normal_mode1)
{
    EXPECT_EQ(aes_ecb_normal_mode1(),0);
}

int aes_ecb_normal_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ecb(), EVP_aes_192_ecb(), EVP_aes_256_ecb()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 2, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ecb_normal_mode2)
{
    EXPECT_EQ(aes_ecb_normal_mode2(),0);
}

//aes_ecb,16字节非倍数
int aes_ecb_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ecb(), EVP_aes_192_ecb(), EVP_aes_256_ecb()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 1, 1);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ecb_mode1)
{
    EXPECT_EQ(aes_ecb_mode1(),0);
}
/*
int aes_ecb_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_ecb(), EVP_aes_192_ecb(), EVP_aes_256_ecb()};
    for (int i=0; i < 3; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 2, 1);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 3 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_ecb_mode2)
{
    EXPECT_EQ(aes_ecb_mode2(),0);
}
*/
//aes_xts,16字节倍数
int aes_xts_normal_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_xts(),  EVP_aes_256_xts()};
    for (int i=0; i < 2; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 1, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 2 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_xts_normal_mode1)
{
    EXPECT_EQ(aes_xts_normal_mode1(),0);
}

int aes_xts_normal_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_xts(), EVP_aes_256_xts()};
    for (int i=0; i < 2; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_INTEGER_PACKAGE_SIZE, 2, 0);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 2 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_xts_normal_mode2)
{
    EXPECT_EQ(aes_xts_normal_mode2(),0);
}

//aes_xts,16字节非倍数
int aes_xts_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_xts(), EVP_aes_256_xts()};
    for (int i=0; i < 2; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 1, 1);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 2 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_xts_mode1)
{
    EXPECT_EQ(aes_xts_mode1(),0);
}
/*
int aes_xts_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int result = 0;
    const EVP_CIPHER *evp_aes_cipher[] = { EVP_aes_128_xts(), EVP_aes_256_xts()};
    for (int i=0; i < 2; i++){
        int ret = sec_loop_cipher(e, evp_aes_cipher[i], AES_NOINTEGER_PACKAGE_SIZE, 2, 1);
        if (ret == 0){
            result++;
        }
    }
    ENGINE_free(e);

    return (result == 2 ? 0 : -1);
}

TEST_F(AesCipherTestGroup, aes_xts_mode2)
{
    EXPECT_EQ(aes_xts_mode2(),0);
}
*/
TEST_F(AesCipherTestGroup, aes_ctr_cbc_ecb_xts_fork)
{
    pid_t pid = fork();
    if (pid > 0)
    {
        EXPECT_EQ(aes_ctr_normal_mode1(),0);
        EXPECT_EQ(aes_ctr_normal_mode2(),0);
        EXPECT_EQ(aes_ctr_mode1(),0);
        EXPECT_EQ(aes_ctr_mode2(),0);
        EXPECT_EQ(aes_cbc_normal_mode1(),0);
        EXPECT_EQ(aes_cbc_normal_mode2(),0);
        EXPECT_EQ(aes_cbc_mode1(),0);
//        EXPECT_EQ(aes_cbc_mode2(),0);
        EXPECT_EQ(aes_ecb_normal_mode1(),0);
        EXPECT_EQ(aes_ecb_normal_mode2(),0);
        EXPECT_EQ(aes_ecb_mode1(),0);
//        EXPECT_EQ(aes_ecb_mode2(),0);
        EXPECT_EQ(aes_xts_normal_mode1(),0);
        EXPECT_EQ(aes_xts_normal_mode2(),0);
        EXPECT_EQ(aes_xts_mode1(),0);
//        EXPECT_EQ(aes_xts_mode2(),0);
    }
    else
    {
        EXPECT_EQ(aes_ctr_normal_mode1(),0);
        EXPECT_EQ(aes_ctr_normal_mode2(),0);
        EXPECT_EQ(aes_ctr_mode1(),0);
        EXPECT_EQ(aes_ctr_mode2(),0);
        EXPECT_EQ(aes_cbc_normal_mode1(),0);
        EXPECT_EQ(aes_cbc_normal_mode2(),0);
        EXPECT_EQ(aes_cbc_mode1(),0);
//        EXPECT_EQ(aes_cbc_mode2(),0);
        EXPECT_EQ(aes_ecb_normal_mode1(),0);
        EXPECT_EQ(aes_ecb_normal_mode2(),0);
        EXPECT_EQ(aes_ecb_mode1(),0);
//        EXPECT_EQ(aes_ecb_mode2(),0);
        EXPECT_EQ(aes_xts_normal_mode1(),0);
        EXPECT_EQ(aes_xts_normal_mode2(),0);
        EXPECT_EQ(aes_xts_mode1(),0);
//        EXPECT_EQ(aes_xts_mode2(),0);
    }
}
