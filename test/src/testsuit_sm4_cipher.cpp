#include "testsuit_common.h"

class Sm4CipherTestGroup:public testing::Test
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

//小包加解密,sm4_ctr
int case1_sm4_ctr_small_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ctr_small_cipher_mode1)
{
    EXPECT_EQ(case1_sm4_ctr_small_cipher_mode1(),0);
}

int case1_sm4_ctr_small_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ctr_small_cipher_mode2)
{
    EXPECT_EQ(case1_sm4_ctr_small_cipher_mode2(),0);
}

int case1_sm4_ctr_small_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_SMALL_PACKAGE_SIZE, i, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ctr_small_cipher_mode3)
{
    EXPECT_EQ(case1_sm4_ctr_small_cipher_mode3(),0);
}

//大包加解密,16字节倍数,sm4_ctr
int case2_sm4_ctr_normal_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ctr_normal_big_cipher_mode1)
{
    EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode1(),0);
}

int case2_sm4_ctr_normal_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_BIG_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ctr_normal_big_cipher_mode2)
{
    EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode2(),0);
}

int case2_sm4_ctr_normal_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ctr_normal_big_cipher_mode3)
{
    EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode3(),0);
}

//大包加解密,16字节非倍数,sm4_ctr
int case3_sm4_ctr_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ctr_big_cipher_mode1)
{
    EXPECT_EQ(case3_sm4_ctr_big_cipher_mode1(),0);
}

int case3_sm4_ctr_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ctr_big_cipher_mode2)
{
    EXPECT_EQ(case3_sm4_ctr_big_cipher_mode2(),0);
}

int case3_sm4_ctr_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ctr(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 1, 0);
        if(ret == 0)
            count++;    
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ctr_big_cipher_mode3)
{
    EXPECT_EQ(case3_sm4_ctr_big_cipher_mode3(),0);
}

//小包加解密,sm4_ofb
int case1_sm4_ofb_small_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ofb_small_cipher_mode1)
{
    EXPECT_EQ(case1_sm4_ofb_small_cipher_mode1(),0);
}

int case1_sm4_ofb_small_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ofb_small_cipher_mode2)
{
    EXPECT_EQ(case1_sm4_ofb_small_cipher_mode2(),0);
}

int case1_sm4_ofb_small_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_INTEGER_SMALL_PACKAGE_SIZE, i, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ofb_small_cipher_mode3)
{
    EXPECT_EQ(case1_sm4_ofb_small_cipher_mode3(),0);
}

//大包加解密,16字节倍数,sm4_ofb
int case2_sm4_ofb_normal_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ofb_normal_big_cipher_mode1)
{
    EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode1(),0);
}

int case2_sm4_ofb_normal_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_INTEGER_BIG_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ofb_normal_big_cipher_mode2)
{
    EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode2(),0);
}

int case2_sm4_ofb_normal_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ofb_normal_big_cipher_mode3)
{
    EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode3(),0);
}

//大包加解密,16字节非倍数,sm4_ofb
int case3_sm4_ofb_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ofb_big_cipher_mode1)
{
    EXPECT_EQ(case3_sm4_ofb_big_cipher_mode1(),0);
}

int case3_sm4_ofb_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ofb_big_cipher_mode2)
{
    EXPECT_EQ(case3_sm4_ofb_big_cipher_mode2(),0);
}

int case3_sm4_ofb_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ofb(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 1, 0);
        if(ret == 0)
            count++;    
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ofb_big_cipher_mode3)
{
    EXPECT_EQ(case3_sm4_ofb_big_cipher_mode3(),0);
}

//小包加解密,sm4_cbc
int case1_sm4_cbc_small_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_cbc_small_cipher_mode1)
{
    EXPECT_EQ(case1_sm4_cbc_small_cipher_mode1(),0);
}

int case1_sm4_cbc_small_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_cbc_small_cipher_mode2)
{
    EXPECT_EQ(case1_sm4_cbc_small_cipher_mode2(),0);
}

int case1_sm4_cbc_small_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_SMALL_PACKAGE_SIZE, i, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_cbc_small_cipher_mode3)
{
    EXPECT_EQ(case1_sm4_cbc_small_cipher_mode3(),0);
}

//大包加解密,16字节倍数,sm4_cbc
int case2_sm4_cbc_normal_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_cbc_normal_big_cipher_mode1)
{
    EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode1(),0);
}

int case2_sm4_cbc_normal_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_BIG_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_cbc_normal_big_cipher_mode2)
{
    EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode2(),0);
}

int case2_sm4_cbc_normal_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_cbc_normal_big_cipher_mode3)
{
    EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode3(),0);
}

//大包加解密,16字节非倍数,sm4_cbc
int case3_sm4_cbc_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_NOINTEGER_SMALL_PACKAGE_SIZE, 1, 1);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_cbc_big_cipher_mode1)
{
    EXPECT_EQ(case3_sm4_cbc_big_cipher_mode1(),0);
}

//预期不符
int case3_sm4_cbc_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_NOINTEGER_SMALL_PACKAGE_SIZE, 4, 1);
    ENGINE_free(e);

    return ret;
}
/*
TEST_F(Sm4CipherTestGroup, case3_sm4_cbc_big_cipher_mode2)
{
    EXPECT_EQ(case3_sm4_cbc_big_cipher_mode2(),0);
}
*/
int case3_sm4_cbc_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_cbc(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 1, 1);
        if(ret == 0)
            count++;    
    }
    ENGINE_free(e);

    int result = 0;
    if (count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_cbc_big_cipher_mode3)
{
    EXPECT_EQ(case3_sm4_cbc_big_cipher_mode3(),0);
}

//小包加解密,sm4_ecb
int case1_sm4_ecb_small_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ecb_small_cipher_mode1)
{
    EXPECT_EQ(case1_sm4_ecb_small_cipher_mode1(),0);
}

int case1_sm4_ecb_small_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_INTEGER_SMALL_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ecb_small_cipher_mode2)
{
    EXPECT_EQ(case1_sm4_ecb_small_cipher_mode2(),0);
}

int case1_sm4_ecb_small_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_INTEGER_SMALL_PACKAGE_SIZE, i, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case1_sm4_ecb_small_cipher_mode3)
{
    EXPECT_EQ(case1_sm4_ecb_small_cipher_mode3(),0);
}

//大包加解密,16字节倍数,sm4_ecb
int case2_sm4_ecb_normal_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ecb_normal_big_cipher_mode1)
{
    EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode1(),0);
}

int case2_sm4_ecb_normal_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_INTEGER_BIG_PACKAGE_SIZE, 2, 0);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ecb_normal_big_cipher_mode2)
{
    EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode2(),0);
}

int case2_sm4_ecb_normal_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_INTEGER_BIG_PACKAGE_SIZE, 1, 0);
        if(ret == 0)
            count++;
    }
    ENGINE_free(e);

    int result = 0;
    if(count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case2_sm4_ecb_normal_big_cipher_mode3)
{
    EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode3(),0);
}

//大包加解密,16字节非倍数,sm4_ecb
int case3_sm4_ecb_big_cipher_mode1(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_NOINTEGER_SMALL_PACKAGE_SIZE, 1, 1);
    ENGINE_free(e);

    return ret;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ecb_big_cipher_mode1)
{
    EXPECT_EQ(case3_sm4_ecb_big_cipher_mode1(),0);
}

//预期不符
int case3_sm4_ecb_big_cipher_mode2(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_NOINTEGER_SMALL_PACKAGE_SIZE, 4, 1);
    ENGINE_free(e);

    return ret;
}
/*
TEST_F(Sm4CipherTestGroup, case3_sm4_ecb_big_cipher_mode2)
{
    EXPECT_EQ(case3_sm4_ecb_big_cipher_mode2(),0);
}
*/
int case3_sm4_ecb_big_cipher_mode3(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    int count = 0;
    for (int i = 1; i <= 2; i++) {
        int ret = sec_loop_cipher(e, EVP_sm4_ecb(), SM4_NOINTEGER_BIG_PACKAGE_SIZE, 1, 1);
        if(ret == 0)
            count++;    
    }
    ENGINE_free(e);

    int result = 0;
    if (count == 2){
        result = 0;
    }else{
        result = 1;
    }
    return result;
}

TEST_F(Sm4CipherTestGroup, case3_sm4_ecb_big_cipher_mode3)
{
    EXPECT_EQ(case3_sm4_ecb_big_cipher_mode3(),0);
}

TEST_F(Sm4CipherTestGroup, case3_sm4_cbc_big_cipher_mode3_fork)
{
    pid_t pid = fork();
    if (pid > 0)
    {
        EXPECT_EQ(case1_sm4_ctr_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_ctr_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_ctr_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_ctr_big_cipher_mode1(),0);
        EXPECT_EQ(case3_sm4_ctr_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ctr_big_cipher_mode3(),0);
        EXPECT_EQ(case1_sm4_ofb_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_ofb_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_ofb_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_ofb_big_cipher_mode1(),0);
        EXPECT_EQ(case3_sm4_ofb_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ofb_big_cipher_mode3(),0);
        EXPECT_EQ(case1_sm4_cbc_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_cbc_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_cbc_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_cbc_big_cipher_mode1(),0);
        //EXPECT_EQ(case3_sm4_cbc_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ecb_big_cipher_mode3(),0);
        EXPECT_EQ(case1_sm4_ecb_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_ecb_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_ecb_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_ecb_big_cipher_mode1(),0);
        //EXPECT_EQ(case3_sm4_ecb_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ecb_big_cipher_mode3(),0);
    }
    else
    {
        EXPECT_EQ(case1_sm4_ctr_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_ctr_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_ctr_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_ctr_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_ctr_big_cipher_mode1(),0);
        EXPECT_EQ(case3_sm4_ctr_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ctr_big_cipher_mode3(),0);
        EXPECT_EQ(case1_sm4_ofb_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_ofb_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_ofb_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_ofb_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_ofb_big_cipher_mode1(),0);
        EXPECT_EQ(case3_sm4_ofb_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ofb_big_cipher_mode3(),0);
        EXPECT_EQ(case1_sm4_cbc_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_cbc_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_cbc_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_cbc_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_cbc_big_cipher_mode1(),0);
        //EXPECT_EQ(case3_sm4_cbc_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ecb_big_cipher_mode3(),0);
        EXPECT_EQ(case1_sm4_ecb_small_cipher_mode1(),0);
        EXPECT_EQ(case1_sm4_ecb_small_cipher_mode2(),0);
        EXPECT_EQ(case1_sm4_ecb_small_cipher_mode3(),0);
        EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode1(),0);
        EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode2(),0);
        EXPECT_EQ(case2_sm4_ecb_normal_big_cipher_mode3(),0);
        EXPECT_EQ(case3_sm4_ecb_big_cipher_mode1(),0);
        //EXPECT_EQ(case3_sm4_ecb_big_cipher_mode2(),0);
        EXPECT_EQ(case3_sm4_ecb_big_cipher_mode3(),0);
    }
}
