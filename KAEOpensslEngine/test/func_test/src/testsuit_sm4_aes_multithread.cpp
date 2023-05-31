#include "testsuit_common.h"

struct aes_sm4_pthread_dt {
    int cpu_id;
    int buf_len;
    int update_cnt;
    int fillmode;
    ENGINE *engine;
    const EVP_CIPHER *cipher_type;
};

#define TEST_MAX_THRD 100
static const int thrds_num = 20;
static pthread_t system_thrds[TEST_MAX_THRD];
static struct aes_sm4_pthread_dt test_thrds_data[TEST_MAX_THRD];

static int sm4_aes_lenth_data[][3] = {
    {SM4_NOINTEGER_SMALL_PACKAGE_SIZE, 1, 0},  {SM4_INTEGER_SMALL_PACKAGE_SIZE, 2, 0},
    {SM4_NOINTEGER_SMALL_PACKAGE_SIZE, 1, 1},  {SM4_INTEGER_SMALL_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 0},  {AES_INTEGER_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 0},  {AES_INTEGER_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 1},  {AES_INTEGER_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 1},  {AES_INTEGER_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 1},  {AES_INTEGER_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 1},  {AES_INTEGER_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 1},  {AES_INTEGER_PACKAGE_SIZE, 2, 0},
    {AES_NOINTEGER_PACKAGE_SIZE, 1, 1},  {AES_INTEGER_PACKAGE_SIZE, 2, 0}
};

static const EVP_CIPHER* cipher_type[] = { 
    EVP_sm4_ctr(), EVP_sm4_ctr(), EVP_sm4_cbc(), EVP_sm4_cbc(),
    EVP_aes_128_ctr(), EVP_aes_128_ctr(), EVP_aes_256_ctr(), EVP_aes_256_ctr(),
    EVP_aes_128_cbc(), EVP_aes_128_cbc(), EVP_aes_256_cbc(), EVP_aes_256_cbc(),
    EVP_aes_128_ecb(), EVP_aes_128_ecb(), EVP_aes_256_ecb(), EVP_aes_256_ecb(),
    EVP_aes_128_xts(), EVP_aes_128_xts(), EVP_aes_256_xts(), EVP_aes_256_xts()
};

static void setdata(ENGINE *e)
{
    for (int i = 0; i < thrds_num; i++){
        test_thrds_data[i].buf_len = sm4_aes_lenth_data[i][0];
        test_thrds_data[i].update_cnt = sm4_aes_lenth_data[i][1];
        test_thrds_data[i].fillmode = sm4_aes_lenth_data[i][2];
        test_thrds_data[i].cpu_id = i;
        test_thrds_data[i].engine = e;
        test_thrds_data[i].cipher_type = cipher_type[i];
    }
    return;
}

class Sm4AesCipherMultiThreadTestGroup:public testing::Test
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

void *sm4_aes_cipher_multi_thread(void *args){
    struct aes_sm4_pthread_dt *pdata = (aes_sm4_pthread_dt *)args;
    int ret = sec_loop_cipher(pdata->engine, pdata->cipher_type, pdata->buf_len, pdata->update_cnt, pdata->fillmode);
    if (ret != 0){
        printf("The cipher %dth thread fail!\n", pdata->cpu_id);
    }

    return NULL;
}

int test_sm4_aes_multi_thread(void)
{
    ENGINE *e;
    e = ENGINE_by_id("kae");
    setdata(e);
    int ret;
    for (int i = 0; i < thrds_num; i++) {
        ret = pthread_create(&system_thrds[i], NULL,
                             sm4_aes_cipher_multi_thread,
                             &test_thrds_data[i]);
        if (ret) {
            printf("Create %dth thread fail!\n", i);
            return ret;
        }
    }

    for (int i = 0; i < thrds_num; i++) {
        ret = pthread_join(system_thrds[i], NULL);
        if (ret) {
            printf("Join %dth thread fail!\n", i);
            return ret;
        }
    }
    ENGINE_free(e);
    return ret;
}

TEST_F(Sm4AesCipherMultiThreadTestGroup, test_sm4_aes_multi_thread)
{
    EXPECT_EQ(test_sm4_aes_multi_thread(),0);
}
