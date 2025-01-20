/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: 
 * @Author: nwq
 * @Date: 2025-01-13
 * @LastEditTime: 2025-01-13
 */
 
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "gtest/gtest.h"

#include "demo_utils.h"
#include "demo_digest.h"

class MD5TestSuit:public testing::Test
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

// MD5数据完整性检查
TEST_F(MD5TestSuit, MD5_check_data_integrity)
{
    int msglen = 16*1024;
    char *data = (char *)malloc(msglen + 1);
    generateRandomASCII(data, msglen);
    const char *message = data;
    unsigned char expected_md5_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len; 

    // 软算计算预期哈希值
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, message, strlen(message));
    EVP_DigestFinal_ex(mdctx, expected_md5_hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    // 加载 KAE 引擎
    ENGINE* engine = ENGINE_by_id("kae");
    ENGINE_init(engine);
    ASSERT_FALSE(engine == NULL);

    EXPECT_TRUE(check_data_integrity(message, EVP_md5(), expected_md5_hash, &hash_len, engine)) << "Data integrity check failed.";
}

// MD5安全存储密码
TEST_F(MD5TestSuit, MD5_secure_password_storage)
{
    int msglen = 16*1024;
    char *data = (char *)malloc(msglen + 1);
    generateRandomASCII(data, msglen);
    const char *message = data;
    const char *password = "my_secure_password";
    unsigned char expected_md5_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // 软算计算预期哈希值
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    unsigned char salt[] = "random_salt";
    EVP_DigestUpdate(mdctx, salt, sizeof(salt) - 1); // 假定salt是C字符串
    EVP_DigestFinal_ex(mdctx, expected_md5_hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    // 加载 KAE 引擎
    ENGINE* engine = ENGINE_by_id("kae");
    ENGINE_init(engine);
    ASSERT_FALSE(engine == NULL);

    EXPECT_TRUE(secure_password_storage(password, EVP_md5(), expected_md5_hash, &hash_len, engine)) << "Hashed password does not match the expected value.";
}