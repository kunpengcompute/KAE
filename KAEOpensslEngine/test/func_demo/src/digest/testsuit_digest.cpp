/*
 * @Author: l00584920 liuyang645@huawei.com
 * @Date: 2024-08-15 11:55:16
 * @LastEditors: l00584920 liuyang645@huawei.com
 * @LastEditTime: 2024-08-16 11:38:30
 * @FilePath: \KAE_kae2\KAE\KAEOpensslEngine\test\func_demo\src\digest\sm3_digest.cpp
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "gtest/gtest.h"

#include "demo_utils.h"
#include "demo_digest.h"

class DigestTestSuit:public testing::Test
{
protected:
    virtual void SetUp()
    {
        // init_openssl();
    }
    virtual void TearDown()
    {
 
    }

};


//硬算生成私钥
TEST_F(DigestTestSuit, EVP_md5)
{

    int msglen = 8*1024;
    char * msg1 = (char *)malloc(msglen + 1);
    char * msg2 = (char *)malloc(msglen + 1);
    generateRandomASCII(msg1, msglen);
    generateRandomASCII(msg2, msglen);
    unsigned char *digest_value1 = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    unsigned char *digest_value2 = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    unsigned int digest_len1 = 0;
    unsigned int digest_len2 = 0;
    demonstrate_digest(EVP_md5(), msg1, msg2, digest_value1, &digest_len1);

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    ASSERT_FALSE(engine == NULL);
    demonstrate_digest(EVP_md5(), msg1, msg2, digest_value2, &digest_len2);

    EXPECT_EQ(memcmp(digest_value1, digest_value2, digest_len1) , 0);

}

TEST_F(DigestTestSuit, sha256)
{

    int msglen = 8*1024;
    char * msg1 = (char *)malloc(msglen + 1);
    char * msg2 = (char *)malloc(msglen + 1);
    generateRandomASCII(msg1, msglen);
    generateRandomASCII(msg2, msglen);
    unsigned char *digest_value1 = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    unsigned char *digest_value2 = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    unsigned int digest_len1 = 0;
    unsigned int digest_len2 = 0;
    demonstrate_digest(EVP_sha256(), msg1, msg2, digest_value1, &digest_len1);

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    ASSERT_FALSE(engine == NULL);
    demonstrate_digest(EVP_sha256(), msg1, msg2, digest_value2, &digest_len2);

    EXPECT_EQ(memcmp(digest_value1, digest_value2, digest_len1) , 0);

}


TEST_F(DigestTestSuit, sm3)
{

    int msglen = 8*1024;
    char * msg1 = (char *)malloc(msglen + 1);
    char * msg2 = (char *)malloc(msglen + 1);
    generateRandomASCII(msg1, msglen);
    generateRandomASCII(msg2, msglen);
    unsigned char *digest_value1 = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    unsigned char *digest_value2 = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    unsigned int digest_len1 = 0;
    unsigned int digest_len2 = 0;
    demonstrate_digest(EVP_sm3(), msg1, msg2, digest_value1, &digest_len1);

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    ASSERT_FALSE(engine == NULL);
    demonstrate_digest(EVP_sm3(), msg1, msg2, digest_value2, &digest_len2);

    EXPECT_EQ(memcmp(digest_value1, digest_value2, digest_len1) , 0);

}