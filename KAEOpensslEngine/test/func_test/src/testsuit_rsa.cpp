#include"testsuit_common.h"


class RsaTestGroup:public testing::Test
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
//硬算生成私钥
TEST_F(RsaTestGroup, case0)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
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

}

//硬算加解密--公钥加密私钥解密
TEST_F(RsaTestGroup, case1)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_FALSE(engine == NULL);
    
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(engine);
    ASSERT_FALSE(rsa == NULL);
    
    int bit = 2048;
    RSA_generate_key_ex(rsa, bit, e_value, NULL); //创建⼀对rsa的公钥私钥
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);
  
    int enclen, declen;
    unsigned char *srcStr = (unsigned char *)"000056789";
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);

    // srcStr  ==公钥加密==》 encData
    enclen = rsa_public_encrypt(rsa, encData, srcStr, RSA_PKCS1_PADDING);
    ASSERT_GT(enclen , 0);

    // encData ==私钥解密==》 decData
    declen = rsa_private_decrypt(rsa, decData, encData, enclen, RSA_PKCS1_PADDING);
    ASSERT_GE(declen , 0);

    EXPECT_EQ(memcmp(decData, srcStr, declen), 0);

    RSA_free(rsa);
}

////硬算加解密--私钥加密公钥解密
TEST_F(RsaTestGroup, case2)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_FALSE(engine == NULL);
    
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(engine);
    ASSERT_FALSE(rsa == NULL);
    
    int bit = 2048;
    RSA_generate_key_ex(rsa, bit, e_value, NULL); //创建⼀对rsa的公钥私钥
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);
  
    int enclen, declen;
    unsigned char *srcStr = (unsigned char *)"000056789";
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);

    // srcStr  ==私钥加密==》 encData
    enclen = rsa_private_encrypt(rsa, encData, srcStr, RSA_PKCS1_PADDING);
    ASSERT_GT(enclen , 0);

    // encData ==公钥解密==》 decData
    declen = rsa_public_decrypt(rsa, decData, encData, enclen, RSA_PKCS1_PADDING);
    ASSERT_GT(declen , 0);

    EXPECT_EQ(memcmp(decData, srcStr, declen) , 0);

    RSA_free(rsa);
}

//硬算加解密、签名验签（evp） 
TEST_F(RsaTestGroup, case3)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_FALSE(engine == NULL);
    
    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(engine);
    ASSERT_FALSE(rsa == NULL);
    
    int bit = 1024;
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);

    EVP_PKEY *pkey, *pri_key;
    pkey = EVP_PKEY_new();
    pri_key = EVP_PKEY_new();

    RSA *public_key = RSAPublicKey_dup(rsa);
    RSA *private_key = RSAPrivateKey_dup(rsa);
    EVP_PKEY_set1_RSA(pkey, public_key);
    EVP_PKEY_set1_RSA(pri_key, private_key);

    int ret;
    size_t enclen, declen, siglen;
    unsigned char *srcStr = (unsigned char *)"123456789";
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);

    unsigned char *signData = (unsigned char *)malloc(key_len + 1);
    memset(signData, 0, key_len + 1);

    enclen = key_len + 1;
    ret = evp_encrypt(pkey, encData, &enclen, srcStr, engine);
    ASSERT_GT(ret , 0);
    declen = key_len + 1;
    ret = evp_decrypt(pri_key, decData, &declen, encData, enclen, engine);
    ASSERT_GT(ret , 0);
    EXPECT_EQ(memcmp(decData, srcStr, declen) , 0);

    siglen = key_len + 1;
    ret = evp_sign(pri_key, signData, &siglen, srcStr, engine);
    ASSERT_GT(ret , 0);
    ret = evp_verify(pkey, srcStr, strlen((const char *)srcStr), signData, siglen, engine);
    EXPECT_EQ(ret , 1);
	
    RSA_free(rsa);
}

//Evp这些用例当前没走到硬算，API方式被劫持到其他接口了，但是cli的方式调用正常，需要分析。
TEST_F(RsaTestGroup, case4)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");

    unsigned long e = RSA_F4;  // 65537
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(NULL);
    ASSERT_FALSE(rsa == NULL);
    
    int bit = 1024;
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
    ASSERT_GE(RSA_check_key_ex(rsa, NULL) , 0);

    EVP_PKEY *pkey, *pri_key;
    pkey = EVP_PKEY_new();
    pri_key = EVP_PKEY_new();

    const RSA_METHOD *hw_rsa = ENGINE_get_RSA(engine);
    RSA_set_method(rsa, hw_rsa);
    RSA *public_key = RSAPublicKey_dup(rsa);
    RSA *private_key = RSAPrivateKey_dup(rsa);
    EVP_PKEY_set1_RSA(pkey, public_key);
    EVP_PKEY_set1_RSA(pri_key, private_key);

    int ret;
    size_t enclen, declen;
    unsigned char *srcStr = (unsigned char *)"123456789";
    int key_len = RSA_size(rsa);
    unsigned char *encData = (unsigned char *)malloc(key_len + 1);
    memset(encData, 0, key_len + 1);
    unsigned char *decData = (unsigned char *)malloc(key_len + 1);
    memset(decData, 0, key_len + 1);

    unsigned char *signData = (unsigned char *)malloc(key_len + 1);
    memset(signData, 0, key_len + 1);

    unsigned char *verData = (unsigned char *)malloc(key_len + 1);
    memset(verData, 0, key_len + 1);

    ret = evp_encrypt(pkey, encData, &enclen, srcStr, engine);
    ASSERT_GT(ret , 0);
    ret = evp_decrypt(pri_key, decData, &declen, encData, enclen, engine);
    ASSERT_GT(ret , 0);
    EXPECT_EQ(memcmp(decData, srcStr, declen) , 0);

    ret = evp_sign(pri_key, encData, &enclen, srcStr, engine);
    ASSERT_GT(ret , 0);
    ret = evp_verify(pkey, srcStr, strlen((const char *)srcStr), encData, enclen, engine);
    EXPECT_EQ(ret , 1);

    RSA_free(rsa);
}

//RSA不同加密长度 NO_PADDING模式:输入必须和RSA秘钥模长度一致，如果输入明文过长，必须切割,输出长度为RSA秘钥模长度。
TEST_F(RsaTestGroup, case5)
{   
    int ret = 0;	

    char srcStr2[128+1]="a";//128*8=1024
	
    for(int i = 0;i<11;i++)
    {
        strcat(srcStr2,"00000000abc");
    }
    strcat(srcStr2,"abcbfd");
    EXPECT_EQ(strlen(srcStr2),128);
    ret = rsa_various_padding_mode(1024, (unsigned char *)srcStr2, RSA_NO_PADDING);
    EXPECT_EQ(ret , 1);

    char srcStr3[256+1]="a";//256*8=2048

    for(int i = 0;i<22;i++)
    {
        strcat(srcStr3,"00000000abc");//11*22=242
    }
    strcat(srcStr3,"aBCddddddppps");//1+242+13=256=2048bits
    EXPECT_EQ(strlen(srcStr3),256);
    ret = rsa_various_padding_mode(2048, (unsigned char *)srcStr3, RSA_NO_PADDING);
    EXPECT_EQ(ret , 1);

    char srcStr4[384+1]="a";//384*8=3072
	
    for(int i = 0;i<34;i++)
    {
        strcat(srcStr4,"00000000abc");
    }
    strcat(srcStr4,"adfsdfsty");
    EXPECT_EQ(strlen(srcStr4),384);
    ret = rsa_various_padding_mode(3072, (unsigned char *)srcStr4, RSA_NO_PADDING);
    EXPECT_EQ(ret , 1);

    char srcStr5[512+1]="a";//512*8=4096
	
    for(int i = 0;i<46;i++)
    {
        strcat(srcStr5,"00000000abc");
    }
    strcat(srcStr5,"adddf");
    EXPECT_EQ(strlen(srcStr5),512);
    ret = rsa_various_padding_mode(4096, (unsigned char *)srcStr5, RSA_NO_PADDING);
    EXPECT_EQ(ret , 1);
    
}

  
//RSA不同加密长度 RSA_PKCS1_OAEP_PADDING模式:输入明文长度小于RSA_size(rsa)-41,输出长度为RSA秘钥模长度。
TEST_F(RsaTestGroup, case6)
{
    int ret = 0;
    char srcStr1[] = "0000000789";

    char srcStr2[86+1]="a";
	
    for(int i = 0;i<8;i++)
    {
        strcat(srcStr2,srcStr1);
    }
    strcat(srcStr2,"abcds");

    // printf("[%d][%s]\n", strlen(srcStr2), srcStr2);
    
    for (int j = 0; j < 250; j++) {
        ret = rsa_various_padding_mode(1024, (unsigned char *)srcStr2, RSA_PKCS1_OAEP_PADDING); //1024/8-41=87 (应该选86及以下)
        EXPECT_EQ(ret , 1);
    }
    
    char srcStr3[214]="a";
    for(int i = 0;i<21;i++)
    {
        strcat(srcStr3,srcStr1);
    }
    strcat(srcStr3,"abc");

    for (int j = 0; j < 5; j++) {
        ret = rsa_various_padding_mode(2048, (unsigned char *)srcStr3, RSA_PKCS1_OAEP_PADDING);
        EXPECT_EQ(ret , 1);
    }

    char srcStr4[342]="a";
	
    for(int i = 0;i<34;i++)
    {
        strcat(srcStr4,srcStr1);
    }
    strcat(srcStr4,"a");

    for (int j = 0; j < 5; j++) {
        ret = rsa_various_padding_mode(3072, (unsigned char *)srcStr4, RSA_PKCS1_OAEP_PADDING);
        EXPECT_EQ(ret , 1);
    }

    char srcStr5[470]="a";
	
    for(int i = 0;i<46;i++)
    {
        strcat(srcStr5,srcStr1);
    }
    strcat(srcStr5,"abcfghjkd");

    for (int j = 0; j < 1; j++) {
        ret = rsa_various_padding_mode(4096, (unsigned char *)srcStr5, RSA_PKCS1_OAEP_PADDING);
        EXPECT_EQ(ret , 1);
    }
}

//RSA不同加密长度 RSA_PKCS1_PADDING模式 1024/8-11 :输入至少小于RSA_size(rsa)-11,输出长度为RSA秘钥模长度。
TEST_F(RsaTestGroup, case7)
{
    int ret = 0;
    char srcStr1[] = "0000000789";
    unsigned char *srcStr = (unsigned char *)"123456789";   
    ret = rsa_various_padding_mode(1020, srcStr, RSA_PKCS1_PADDING);
    EXPECT_EQ(ret , 1);
    char srcStr2[373]="a";	
    
    for(int i = 0;i<37;i++)
    {
        strcat(srcStr2,srcStr1);
    }
    strcat(srcStr2,"aB");
    //printf("[%d][%s]\n", strlen(srcStr2), srcStr2);
    ret = rsa_various_padding_mode(3072, (unsigned char *)srcStr2, RSA_PKCS1_PADDING);
    EXPECT_EQ(ret , 1);
    char srcStr3[501]="a";
  
    for(int i = 0;i<50;i++)
    {
        strcat(srcStr3,srcStr1);
    }

    ret = rsa_various_padding_mode(4096, (unsigned char *)srcStr3, RSA_PKCS1_PADDING);
    EXPECT_EQ(ret , 1);
    char srcStr4[245]="0";
	
    for(int i = 0;i<24;i++)
    {
        strcat(srcStr4,srcStr1);
    }
    strcat(srcStr4,"abc");
    ret = rsa_various_padding_mode(2048, (unsigned char *)srcStr4, RSA_PKCS1_PADDING);
    EXPECT_EQ(ret , 1);
    char srcStr5[117]="0";
    
    for(int i = 0; i < 11; i++)
    {
        strcat(srcStr5,srcStr1);
    }
    strcat(srcStr5,"abcdef");
    ret = rsa_various_padding_mode(1024, (unsigned char *)srcStr5, RSA_PKCS1_PADDING);
    EXPECT_EQ(ret , 1);
}

//不同秘钥长度硬算切换软算
TEST_F(RsaTestGroup, case8)
{
    
    EXPECT_EQ(rsa_software_and_hardware_switch_mode(512), 1);
    
    EXPECT_EQ( rsa_software_and_hardware_switch_mode(5120), 1);
    
    EXPECT_EQ( rsa_software_and_hardware_switch_mode(6144), 1);
    
}
//不同秘钥长度硬算切换软算(多进程)
TEST_F(RsaTestGroup, case9)
{
    pid_t pid = fork();
    if (pid > 0)
    {
    
        EXPECT_EQ(rsa_software_and_hardware_switch_mode(512), 1);
    
        EXPECT_EQ( rsa_software_and_hardware_switch_mode(5120), 1);
    
        EXPECT_EQ( rsa_software_and_hardware_switch_mode(6144), 1);
    }
    else
    {
        EXPECT_EQ(rsa_software_and_hardware_switch_mode(512), 1);
    
        EXPECT_EQ( rsa_software_and_hardware_switch_mode(5120), 1);
    
        EXPECT_EQ( rsa_software_and_hardware_switch_mode(6144), 1);

    }
    waitpid(pid,NULL,0);
    
}
