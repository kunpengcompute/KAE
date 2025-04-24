
#include <openssl/rsa.h>
#include "gtest/gtest.h"
#include <time.h>

#include "demo_utils.h"
#include "rsa_demo.h"
#include "openssl/engine.h"
#include "kae_bssl.h"

static ENGINE *kae;

class RsaTestSuit : public testing::Test {

protected:
    static void SetUpTestCase(){
        kae = ENGINE_init_kae();
        ASSERT_FALSE(kae == NULL);
    }

    static void TearDownTestCase(){
        ENGINE_free_kae();
    }

    void SetUp() override{

    }

    void TearDown() override{

    }
    
};

// bssl support padding: RSA_PKCS1_PADDING、RSA_NO_PADDING
void bssl_sign_verify(unsigned long e, RSA *rsa, int key_bits, int padding_mode, unsigned char *srcData)
{
    ASSERT_FALSE(rsa == NULL);

    int key_size, src_len, enclen, declen;
    BIGNUM *e_value;

    e_value = BN_new();
    BN_set_word(e_value, e);
    RSA_generate_key_ex(rsa, key_bits, e_value, NULL);
    key_size = RSA_size(rsa);
    src_len = strlen((const char *)srcData);

    unsigned char *encData = (unsigned char *)malloc(key_size + 1);
    memset(encData, 0, key_size + 1);
    unsigned char *decData = (unsigned char *)malloc(key_size + 1);
    memset(decData, 0, key_size + 1);

    enclen = RSA_private_encrypt(src_len, srcData, encData, rsa, padding_mode);
    declen = RSA_public_decrypt(key_size, encData, decData, rsa, padding_mode);

    EXPECT_GT(declen, 0);
    EXPECT_EQ(declen, src_len);
    EXPECT_EQ(memcmp(decData, srcData, declen), 0);

    printf("srcData: %s \n", srcData);
    printf("decData: %s \n", decData);

    BN_free(e_value);
    free(encData);
    free(decData);
}

// bssl support padding: RSA_PKCS1_PADDING、RSA_PKCS1_OAEP_PADDING、RSA_NO_PADDING
void bssl_enc_dec(unsigned long e, RSA *rsa, int key_bits, int padding_mode, unsigned char *srcData)
{
    ASSERT_FALSE(rsa == NULL);

    int key_size, src_len, enclen, declen;
    BIGNUM *e_value;

    e_value = BN_new();
    BN_set_word(e_value, e);
    RSA_generate_key_ex(rsa, key_bits, e_value, NULL);
    key_size = RSA_size(rsa);
    src_len = strlen((const char *)srcData);

    unsigned char *encData = (unsigned char *)malloc(key_size + 1);
    memset(encData, 0, key_size + 1);
    unsigned char *decData = (unsigned char *)malloc(key_size + 1);
    memset(decData, 0, key_size + 1);

    enclen = RSA_public_encrypt(src_len, srcData, encData, rsa, padding_mode);
    declen = RSA_private_decrypt(key_size, encData, decData, rsa, padding_mode);

    EXPECT_GT(declen, 0);
    EXPECT_EQ(declen, src_len);
    EXPECT_EQ(memcmp(decData, srcData, declen), 0);

    printf("srcData: %s \n", srcData);
    printf("decData: %s \n", decData);

    BN_free(e_value);
    free(encData);
    free(decData);
}

TEST_F(RsaTestSuit, bssl_kae_sign_PKCS1)
{
    unsigned long e = RSA_F4;
    int key_bits[] = {1024, 2048, 3072, 4096};
    int n = sizeof(key_bits) / sizeof(key_bits[0]);
    int key_size = 44;

    for (int i = 0; i < n; i++) {
        RSA *rsa = RSA_new_method(kae);

        unsigned char *srcData = (unsigned char *)malloc(key_size + 1);
        memset(srcData, 0, key_size + 1);
        generateRandomASCII(srcData, key_size);

        bssl_sign_verify(e, rsa, key_bits[i], RSA_PKCS1_PADDING, srcData);

        free(srcData);
        RSA_free(rsa);
    }
}

TEST_F(RsaTestSuit, bssl_kae_sign_NOPAD)
{

    unsigned long e = RSA_F4;
    int key_bits[] = {1024, 2048, 3072, 4096};
    int n = sizeof(key_bits) / sizeof(key_bits[0]);

    for (int i = 0; i < n; i++) {
        int key_size = key_bits[i] >> 3;
        RSA *rsa = RSA_new_method(kae);

        unsigned char *srcData = (unsigned char *)malloc(key_size + 1);
        memset(srcData, 0, key_size + 1);
        generateRandomASCII(srcData, key_size);

        bssl_sign_verify(e, rsa, key_bits[i], RSA_NO_PADDING, srcData);

        free(srcData);
        RSA_free(rsa);
    }
}

TEST_F(RsaTestSuit, bssl_kae_enc_dec_PKCS1)
{

    unsigned long e = RSA_F4;
    int key_bits[] = {1024, 2048, 3072, 4096};
    int n = sizeof(key_bits) / sizeof(key_bits[0]);
    int key_size = 44;

    for (int i = 0; i < n; i++) {
        RSA *rsa = RSA_new_method(kae);

        unsigned char *srcData = (unsigned char *)malloc(key_size + 1);
        memset(srcData, 0, key_size + 1);
        generateRandomASCII(srcData, key_size);

        bssl_enc_dec(e, rsa, key_bits[i], RSA_PKCS1_PADDING, srcData);

        free(srcData);
        RSA_free(rsa);
    }
}

TEST_F(RsaTestSuit, bssl_kae_enc_dec_PKCS1_OAEP)
{
    unsigned long e = RSA_F4;
    int key_bits[] = {1024, 2048, 3072, 4096};
    int n = sizeof(key_bits) / sizeof(key_bits[0]);
    int key_size = 44;

    for (int i = 0; i < n; i++) {
        RSA *rsa = RSA_new_method(kae);

        unsigned char *srcData = (unsigned char *)malloc(key_size + 1);
        memset(srcData, 0, key_size + 1);
        generateRandomASCII(srcData, key_size);

        bssl_enc_dec(e, rsa, key_bits[i], RSA_PKCS1_OAEP_PADDING, srcData);

        free(srcData);
        RSA_free(rsa);
    }
}

TEST_F(RsaTestSuit, bssl_kae_enc_dec_NOPAD)
{
    unsigned long e = RSA_F4;
    int key_bits[] = {1024, 2048, 3072, 4096};
    int n = sizeof(key_bits) / sizeof(key_bits[0]);

    for (int i = 0; i < n; i++) {
        int key_size = key_bits[i] >> 3;
        RSA *rsa = RSA_new_method(kae);

        unsigned char *srcData = (unsigned char *)malloc(key_size + 1);
        memset(srcData, 0, key_size + 1);
        generateRandomASCII(srcData, key_size);

        bssl_sign_verify(e, rsa, key_bits[i], RSA_NO_PADDING, srcData);

        free(srcData);
        RSA_free(rsa);
    }
}


TEST_F(RsaTestSuit, bssl_kae_sign_verify_perf)
{
    unsigned long e = RSA_F4;
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(kae);
    ASSERT_FALSE(rsa == NULL);
    int bit = 2048;
    RSA_generate_key_ex(rsa, bit, e_value, NULL); 
  
    int enclen, declen;
    unsigned char *srcData = (unsigned char *)"30k5mz6fa789nigs";
    int key_size = RSA_size(rsa);
    int src_len = strlen((const char *)srcData);
    unsigned char *encData = (unsigned char *)malloc(key_size + 1);
    memset(encData, 0, key_size + 1);
    unsigned char *decData = (unsigned char *)malloc(key_size + 1);
    memset(decData, 0, key_size + 1);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i < 1000;i++ ) {
        enclen = RSA_private_encrypt(src_len, srcData, encData, rsa, RSA_PKCS1_PADDING);
        declen = RSA_public_decrypt(key_size, encData, decData, rsa, RSA_PKCS1_PADDING);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double total_time_s = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("bssl kae sign verify use time %.4f s. \n", total_time_s);

    ASSERT_GT(enclen , 0);
    ASSERT_EQ(declen , src_len);
    EXPECT_EQ(memcmp(decData, srcData, declen) , 0);

    BN_free(e_value);
    RSA_free(rsa);

    free(encData);
    free(decData);

}

TEST_F(RsaTestSuit, bssl_soft_sign_verify_perf)
{
    unsigned long e = RSA_F4;
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new();
    ASSERT_FALSE(rsa == NULL);
    int bit = 2048;
    RSA_generate_key_ex(rsa, bit, e_value, NULL);

    int enclen, declen;
    unsigned char *srcData = (unsigned char *)"30k5mz6fa789nigs";
    int key_size = RSA_size(rsa);
    int src_len = strlen((const char *)srcData);
    unsigned char *encData = (unsigned char *)malloc(key_size + 1);
    memset(encData, 0, key_size + 1);
    unsigned char *decData = (unsigned char *)malloc(key_size + 1);
    memset(decData, 0, key_size + 1);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i < 1000;i++ ) {
        enclen = RSA_private_encrypt(src_len, srcData, encData, rsa, RSA_PKCS1_PADDING);
        declen = RSA_public_decrypt(key_size, encData, decData, rsa, RSA_PKCS1_PADDING);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double total_time_s = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("bssl soft sign verify use time %.4f s. \n", total_time_s);

    ASSERT_GT(enclen , 0);
    ASSERT_EQ(declen , src_len);
    EXPECT_EQ(memcmp(decData, srcData, declen) , 0);

    BN_free(e_value);
    RSA_free(rsa);

    free(encData);
    free(decData);
}

TEST_F(RsaTestSuit, bssl_kae_enc_dec_perf)
{
    unsigned long e = RSA_F4;
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new_method(kae);
    ASSERT_FALSE(rsa == NULL);
    int bit = 2048;
    RSA_generate_key_ex(rsa, bit, e_value, NULL);

    int enclen, declen;
    unsigned char *srcData = (unsigned char *)"30k5mz6fa789nigs";
    int key_size = RSA_size(rsa);
    int src_len = strlen((const char *)srcData);
    unsigned char *encData = (unsigned char *)malloc(key_size + 1);
    memset(encData, 0, key_size + 1);
    unsigned char *decData = (unsigned char *)malloc(key_size + 1);
    memset(decData, 0, key_size + 1);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i < 1000;i++ ) {
        enclen = RSA_public_encrypt(src_len, srcData, encData, rsa, RSA_PKCS1_PADDING);
        declen = RSA_private_decrypt(key_size, encData, decData, rsa, RSA_PKCS1_PADDING);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double total_time_s = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("bssl kae enc dec use time %.4f s. \n", total_time_s);

    ASSERT_GT(enclen , 0);
    ASSERT_EQ(declen , src_len);
    EXPECT_EQ(memcmp(decData, srcData, declen) , 0);

    BN_free(e_value);
    RSA_free(rsa);

    free(encData);
    free(decData);
}

TEST_F(RsaTestSuit, bssl_soft_enc_dec_perf)
{
    unsigned long e = RSA_F4;
    BIGNUM *e_value = BN_new();
    BN_set_word(e_value, e);

    RSA *rsa = RSA_new();
    ASSERT_FALSE(rsa == NULL);
    int bit = 2048;
    RSA_generate_key_ex(rsa, bit, e_value, NULL);
  
    int enclen, declen;
    unsigned char *srcData = (unsigned char *)"30k5mz6fa789nigs";
    int key_size = RSA_size(rsa);
    int src_len = strlen((const char *)srcData);
    unsigned char *encData = (unsigned char *)malloc(key_size + 1);
    memset(encData, 0, key_size + 1);
    unsigned char *decData = (unsigned char *)malloc(key_size + 1);
    memset(decData, 0, key_size + 1);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i < 1000;i++ ) {
        enclen = RSA_public_encrypt(src_len, srcData, encData, rsa, RSA_PKCS1_PADDING);
        declen = RSA_private_decrypt(key_size, encData, decData, rsa, RSA_PKCS1_PADDING);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double total_time_s = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("bssl soft enc dec use time %.4f s. \n", total_time_s);

    ASSERT_GT(enclen , 0);
    ASSERT_EQ(declen , src_len);
    EXPECT_EQ(memcmp(decData, srcData, declen) , 0);

    BN_free(e_value);
    RSA_free(rsa);

    free(encData);
    free(decData);
}