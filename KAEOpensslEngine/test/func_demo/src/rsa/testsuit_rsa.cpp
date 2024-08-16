#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include "gtest/gtest.h"

#include"aes_cbc.h"
#include"sm4_cbc.h"
#include"aes_gcm.h"
#include"demo_utils.h"
#include"rsa_encrypt.h"

class RsaTestSuit:public testing::Test
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
TEST_F(RsaTestSuit, case0)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    // ENGINE_init(engine);
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    ASSERT_FALSE(engine == NULL);
    
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(engine);
    ASSERT_FALSE(rsa == NULL);
    
    int bit = 1024;
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);

    RSA_free(rsa); 
    ENGINE_free(engine);

}

//硬算生成私钥 RSA不同加密长度 RSA_PKCS1_PADDING模式 2048/8-11 = 245
TEST_F(RsaTestSuit, case_rsa1)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    // ENGINE_init(engine);
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    ASSERT_FALSE(engine == NULL);

    //准备报文数据
    char msg[245+1];
	
    generateRandomASCII(msg, 245);
    printf("[%d][%s]\n", strlen(msg), msg);

    //生成秘钥对
    int bit = 2048;//keylen
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);
    RSA *rsa = RSA_new();//RSA_new_method(engine);?
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);

    //准备加解密buf
    int enclen, declen;
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);

    printf("MSG(%d):\n", key_len + 1);
    PRINTMSG((unsigned char*)msg, key_len + 1);

    // 公钥加密
    enclen = RSA_public_encrypt(strlen((const char *)msg), (unsigned char *)msg, encData, rsa, RSA_PKCS1_PADDING);
    ASSERT_GE(enclen, 0);
    printf("EncData(%d):\n",key_len + 1);
    PRINTMSG(encData, key_len + 1);
    // 私钥解密
    declen = RSA_private_decrypt(enclen, encData, decData, rsa, RSA_PKCS1_PADDING);
    ASSERT_GE(declen, 0);

    printf("DecData(%d):\n", key_len + 1);
    PRINTMSG(decData, key_len + 1);
    EXPECT_EQ(memcmp(decData, msg, declen) , 0);

    free(encData);
    free(decData);
    RSA_free(rsa);
    ENGINE_free(engine);
}

// 硬算签名验签
TEST_F(RsaTestSuit, case_rsa2)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    // ENGINE_init(engine);
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    ASSERT_FALSE(engine == NULL);

    /* 待签名数据*/
    int msglen = 256; //2048密钥长度也只能签256字节
    char *msg = (char *)malloc(msglen + 1);
	
    generateRandomASCII(msg, msglen);

    /* 生成RSA密钥*/
    int bit = 2048;
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);

    EVP_PKEY *evpKey;
    evpKey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(evpKey, rsa);
    
    int key_len = RSA_size(rsa);
    unsigned char *signData = (unsigned char *)malloc(msglen + 1);
    memset(signData, 0, msglen + 1);

    //debug info
    printf("[%d][%s]\n", strlen(msg), msg);
    printf("signData(%d):\n", msglen + 1);
    PRINTMSG((unsigned char *)msg, msglen + 1);

    /* 初始化*/
    unsigned int siglen;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_MD_CTX *mdctx2 = EVP_MD_CTX_new();
    EVP_MD_CTX_init(mdctx);

    EVP_SignInit_ex(mdctx, EVP_md5(), NULL);
	EVP_SignUpdate(mdctx, msg, strlen(msg));
	EVP_SignFinal(mdctx, signData, &siglen, evpKey);
    printf("signData(%d)(siglen=%d):\n", msglen + 1, siglen);
	PRINTMSG(signData, msglen + 1);

    /* 验证签名*/
    EVP_MD_CTX_init(mdctx2);
	EVP_VerifyInit_ex(mdctx2, EVP_md5(), NULL);
	EVP_VerifyUpdate(mdctx2, msg, strlen(msg));
    EXPECT_EQ(EVP_VerifyFinal(mdctx2, signData, siglen, evpKey) , 1);

    //注入故障
    memset(signData + 1, 1, 1);// 故障注入
    printf("signData-BAD(%d):\n", msglen + 1);
	PRINTMSG(signData, msglen + 1);
    EXPECT_EQ(EVP_VerifyFinal(mdctx2, signData, siglen, evpKey) , 0);

	EVP_PKEY_free(evpKey);
    EVP_MD_CTX_free(mdctx);
    EVP_MD_CTX_free(mdctx2);
	RSA_free(rsa);
    ENGINE_free(engine);

}

//硬算加解密，rsa-NED模式
TEST_F(RsaTestSuit, case_rsa3)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);// 通过配置文件加载KAE
    ENGINE *engine = ENGINE_by_id("kae");
    // ENGINE_init(engine);
    ENGINE_set_default(engine, ENGINE_METHOD_ALL);
    ASSERT_FALSE(engine == NULL);

    //准备报文数据
    char msg[245+1];
	
    generateRandomASCII(msg, 245);
    printf("[%d][%s]\n", strlen(msg), msg);

    //生成秘钥对
    int bit = 2048;//keylen
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);
    RSA *rsa = RSA_new();//RSA_new_method(engine);?
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);

    RSA *rsa_public_key = RSA_new();
    rsa_key_copy_NED(rsa, rsa_public_key);

    RSA *rsa_private_key = RSA_new();
    rsa_key_copy_NED(rsa, rsa_private_key);

    //准备加解密buf
    int enclen, declen;
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);

    printf("MSG(%d):\n", key_len + 1);
    PRINTMSG((unsigned char*)msg, key_len + 1);

    // 公钥加密
    enclen = RSA_public_encrypt(strlen((const char *)msg), (unsigned char *)msg, encData, rsa_public_key, RSA_PKCS1_PADDING);
    ASSERT_GE(enclen, 0);
    printf("EncData(%d):\n",key_len + 1);
    PRINTMSG(encData, key_len + 1);
    // 私钥解密
    declen = RSA_private_decrypt(enclen, encData, decData, rsa_private_key, RSA_PKCS1_PADDING);
    ASSERT_GE(declen, 0);

    printf("DecData(%d):\n", key_len + 1);
    PRINTMSG(decData, key_len + 1);
    EXPECT_EQ(memcmp(decData, msg, declen) , 0);

    free(encData);
    free(decData);
    RSA_free(rsa);
    ENGINE_free(engine);
}