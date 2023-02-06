#include "testsuit_common.h"

static int case_rsa_encrypt_dencrypt()
{ 
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
    if(engine == NULL) {
        printf("engine is NULL!\n");
        return FALSE;
    }
    
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(engine);
    if(rsa == NULL) {
        printf("rsa is NULL!\n");
        return FALSE;
    }
    
    int bit = 2048;
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    if(RSA_check_key_ex(rsa, NULL) < 0) {
        printf("Failed to generate the key.\n");
        return FALSE;
    }
  
    int enclen, declen, siglen, verlen;
    unsigned char *srcStr = (unsigned char *)"000056789";
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);
    unsigned char *signData = (unsigned char *)malloc(key_len + 1);
    memset(signData, 0, key_len + 1);
    unsigned char *verData = (unsigned char *)malloc(key_len + 1);
    memset(verData, 0, key_len + 1);

    enclen = rsa_encrypt(rsa, encData, srcStr, RSA_PKCS1_PADDING);
    if(enclen <= 0) {
        printf("Encryption failed.\n");
        return FALSE;
    }

    declen = rsa_decrypt(rsa, decData, encData, enclen, RSA_PKCS1_PADDING);
    if(declen <= 0) {
        printf("Decryption failed.\n");
        return FALSE;
    }

    if(memcmp(decData, srcStr, declen) != 0) {
        printf("Failed to encrypt or decrypt the result.\n");
        return FALSE;
    }

    siglen = rsa_sign(rsa, signData, srcStr, RSA_PKCS1_PADDING);
    if(siglen <= 0) {
        printf("Failed to sign the signature.\n");
        return FALSE;
    }

    verlen = rsa_verify(rsa, verData, signData, siglen, RSA_PKCS1_PADDING);
    if(verlen <= 0) {
        printf("Failed to verify the signature.\n");
        return FALSE;
    }

    if(memcmp(verData, srcStr, declen) != 0) {
        printf("Failed to sign the signature verification result.\n");
        return FALSE;
    }

    RSA_free(rsa);
    return TRUE;
}

class RsaQueueFooCalcTest:public testing::Test
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
//RSA加解密、签名验签
TEST_F(RsaQueueFooCalcTest, case1_sleep_8s_queue_release)
{
    int ret = 0;
    
    for(int i = 0; i < 5; i++) {
        ret = case_rsa_encrypt_dencrypt();
        sleep(8);
    }  
    EXPECT_EQ(ret, 1);
}

TEST_F(RsaQueueFooCalcTest, case2_sleep_3s_multiplexing)
{
    int ret = 0;
    
    for(int i = 0; i < 5; i++) {
        ret = case_rsa_encrypt_dencrypt();
        sleep(3);
    }
    
    EXPECT_EQ(ret, 1);
}
