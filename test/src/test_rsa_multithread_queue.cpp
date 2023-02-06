#include "testsuit_common.h"

#define NUM_THREADS 10   //线程个数

static int rsa_encrypt_dencrypt(void)
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
    BN_free(e_value);
    return TRUE;
}
void* case_rsa_encrypt_dencrypt(void*)
{
    for (int i = 0; i <100; i++) {
        rsa_encrypt_dencrypt();
    }

	return NULL;
}

class RsaMultithreadQueueTestGroup:public testing::Test
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
TEST_F(RsaMultithreadQueueTestGroup, RsaMultiTaskQueueMultiplexing)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");

    for (int i = 0; i < NUM_THREADS; ++i) {
        ret = pthread_create(&tids[i], NULL, case_rsa_encrypt_dencrypt, NULL);
        if (ret == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    sleep(3);
    for (int i = 0; i < NUM_THREADS; ++i) {
        ret1 = pthread_create(&tids1[i], NULL, case_rsa_encrypt_dencrypt, NULL);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(engine);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}

TEST_F(RsaMultithreadQueueTestGroup, RsaMultiTaskQueueRelease)
{
    int ret, ret1;
    int result = 0;
    pthread_t tids[NUM_THREADS];
    pthread_t tids1[NUM_THREADS];
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ENGINE *engine = ENGINE_by_id("kae");
    ASSERT_TRUE(engine != NULL);

    for (int i = 0; i < NUM_THREADS; ++i) {
        ret = pthread_create(&tids[i], NULL, case_rsa_encrypt_dencrypt, NULL);
        if (ret == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    sleep(8);
    for (int i = 0; i < NUM_THREADS; ++i) {
        ret1 = pthread_create(&tids1[i], NULL, case_rsa_encrypt_dencrypt, NULL);
        if (ret1 == 0)
            result++;
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(tids1[i], NULL)) {
            printf("Join %dth thread fail!\n", i);
        }
    }
    ENGINE_free(engine);
    EXPECT_EQ((result == 20 ? 0 : -1), 0);
}
