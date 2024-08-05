/*
 * @Author: l00584920 liuyang645@huawei.com
 * @Date: 2024-07-30 20:47:57
 * @LastEditors: l00584920 liuyang645@huawei.com
 * @LastEditTime: 2024-08-02 11:08:13
 * @FilePath: \KAE_kae2\KAE\KAEOpensslEngine\test\func_demo\src\cipher\testsuit_cipher.cpp
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include "gtest/gtest.h"

#include"aes_cbc.h"
#include"aes_gcm.h"
#include"demo_utils.h"

class CipherTestSuit:public testing::Test
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

/*
AES-128:keysize = 16B
AES-192:keysize = 24B
AES-256:keysize = 32B
*/
//硬算生成私钥
TEST_F(CipherTestSuit, case_aes256cbc_10B)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_FALSE(engine == NULL);

    size_t plaintext_len = 10;
    size_t padded_len = ((plaintext_len / 16) + 1) * 16; // 计算填充后的长度 

    unsigned char *plantest = (unsigned char *)malloc(padded_len);
    unsigned char *ciphertest = (unsigned char *)malloc(padded_len); // aes-56 --> 32字节的秘钥长度
    unsigned char *detest = (unsigned char *)malloc(padded_len);
    memset(plantest, 0, padded_len);
    memset(ciphertest, 0, padded_len);
    memset(detest, 0, padded_len);

    ASSERT_FALSE(plantest == NULL || ciphertest == NULL || detest == NULL);

    int clen = 0;
    int delen = 0;
    rand_buffer(plantest, plaintext_len);

    if (!kae_cbc_encrypt(engine, plantest, plaintext_len, ciphertest, &clen))
        exit -1;

    if (!kae_cbc_decrypt(engine, ciphertest, clen, detest, &delen))
        exit -1;

    EXPECT_EQ(memcmp(plantest, detest, plaintext_len) , 0);

    free(plantest);
    free(ciphertest);
    free(detest);
}

TEST_F(CipherTestSuit, case_aes256cbc_50M)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_FALSE(engine == NULL);

    size_t plaintext_len = 50*1024*1024;
    size_t padded_len = ((plaintext_len / 16) + 1) * 16; // 计算填充后的长度 

    unsigned char *plantest = (unsigned char *)malloc(padded_len);
    unsigned char *ciphertest = (unsigned char *)malloc(padded_len); // aes-56 --> 32字节的秘钥长度
    unsigned char *detest = (unsigned char *)malloc(padded_len);
    memset(plantest, 0, padded_len);
    memset(ciphertest, 0, padded_len);
    memset(detest, 0, padded_len);

    ASSERT_FALSE(plantest == NULL || ciphertest == NULL || detest == NULL);

    int clen = 0;
    int delen = 0;
    rand_buffer(plantest, plaintext_len);
    if (!kae_cbc_encrypt(engine, plantest, plaintext_len, ciphertest, &clen))
        exit -1;

    if (!kae_cbc_decrypt(engine, ciphertest, clen, detest, &delen))
        exit -1;

    EXPECT_EQ(memcmp(plantest, detest, plaintext_len) , 0);

    free(plantest);
    free(ciphertest);
    free(detest);
}

// int kae_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
//                     unsigned char *outbuf, int *outlen,
//                     unsigned char *outtag);
// int kae_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
//                 unsigned char *tag,
//                 unsigned char *outbuf, int *outlen);

TEST_F(CipherTestSuit, case_aes_gcm)
{
   OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_FALSE(engine == NULL);
    // ENGINE * engine = NULL;

    size_t plaintext_len = 8*1024;
    size_t padded_len = ((plaintext_len / 16) + 1) * 16; // 计算填充后的长度 

    unsigned char *plantest = (unsigned char *)malloc(padded_len);
    unsigned char *ciphertest = (unsigned char *)malloc(padded_len); // aes-56 --> 32字节的秘钥长度
    unsigned char *detest = (unsigned char *)malloc(padded_len);
    unsigned char *tag = (unsigned char *)malloc(16);
    memset(plantest, 0, padded_len);
    memset(ciphertest, 0, padded_len);
    memset(detest, 0, padded_len);
    memset(tag, 0, 16);

    ASSERT_FALSE(plantest == NULL || ciphertest == NULL || detest == NULL);

    int clen = 0;
    int delen = 0;
    rand_buffer(plantest, plaintext_len);

    EXPECT_EQ(kae_gcm_encrypt(engine, plantest, plaintext_len, ciphertest, &clen, tag), 1);

    // memset(tag + 1, 1, 1);// 故障注入

    EXPECT_EQ(kae_gcm_decrypt(engine, ciphertest, clen, tag, detest, &delen), 1);

    EXPECT_EQ(memcmp(plantest, detest, plaintext_len) , 0);

    free(plantest);
    free(ciphertest);
    free(detest);
}

TEST_F(CipherTestSuit, case_aes_gcm_fault_injection)
{
   OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_FALSE(engine == NULL);
    // ENGINE * engine = NULL;

    size_t plaintext_len = 256;
    size_t padded_len = ((plaintext_len / 16) + 1) * 16; // 计算填充后的长度 

    unsigned char *plantest = (unsigned char *)malloc(padded_len);
    unsigned char *ciphertest = (unsigned char *)malloc(padded_len); // aes-56 --> 32字节的秘钥长度
    unsigned char *detest = (unsigned char *)malloc(padded_len);
    unsigned char *tag = (unsigned char *)malloc(16);
    memset(plantest, 0, padded_len);
    memset(ciphertest, 0, padded_len);
    memset(detest, 0, padded_len);
    memset(tag, 0, 16);

    ASSERT_FALSE(plantest == NULL || ciphertest == NULL || detest == NULL);

    int clen = 0;
    int delen = 0;
    rand_buffer(plantest, plaintext_len);

    EXPECT_EQ(kae_gcm_encrypt(engine, plantest, plaintext_len, ciphertest, &clen, tag), 1);

    memset(tag + 1, 1, 1);// 故障注入

    EXPECT_EQ(kae_gcm_decrypt(engine, ciphertest, clen, tag, detest, &delen), -1);

    EXPECT_NE(memcmp(plantest, detest, plaintext_len) , 0);

    free(plantest);
    free(ciphertest);
    free(detest);
}

