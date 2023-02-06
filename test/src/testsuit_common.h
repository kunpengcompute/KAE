#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include<sys/wait.h>
#include <openssl/rsa.h>
#include <iostream>
#include <pthread.h>
#include <vector>


#include "openssl/evp.h"
#include "openssl/conf.h"
#include "openssl/obj_mac.h"
#include "openssl/dh.h"
#include "gtest/gtest.h"

#define PATHNAME "."
#define PROJ_ID 0x6666
#define FALSE 0
#define TRUE 1

#define SM3_SOFT_PACKAGE_SIZE   60
#define SM3_ENGINE_PACKAGE_SIZE  768

#define SM4_NOINTEGER_SMALL_PACKAGE_SIZE   201
#define SM4_INTEGER_SMALL_PACKAGE_SIZE   224
#define SM4_NOINTEGER_BIG_PACKAGE_SIZE     2070
#define SM4_INTEGER_BIG_PACKAGE_SIZE     3072

#define AES_NOINTEGER_PACKAGE_SIZE   203
#define AES_INTEGER_PACKAGE_SIZE   224

void init_openssl();
void operate_config(std::string operate);
int GetExpectedResults(char *cmpstr, int size);
int rand_buffer(unsigned char *buf, unsigned long len);
int do_md(const EVP_MD *md, int buf_len, uint8_t *buf_in, uint8_t *buf_out, ENGINE *e, int update_cnt);
int sec2_loop_digest(ENGINE *e, const EVP_MD *md, int buf_len, int update_cnt);
int do_cipher_Encrypt(const EVP_CIPHER *cipher_type, int *buf_len, uint8_t *buf_in,
                    uint8_t *buf_out, uint8_t *key, uint8_t *iv, ENGINE *e, int update_cnt, int addtype, EVP_CIPHER_CTX *ctx);
int do_cipher_Decrypt(const EVP_CIPHER *cipher_type, uint8_t *buf_in,
                    uint8_t *buf_out, uint8_t *key, uint8_t *iv, ENGINE *e, int update_cnt, int addtype, EVP_CIPHER_CTX *ctx);
int sec_loop_cipher(ENGINE *e, const EVP_CIPHER *cipher_type, int buf_len, int update_cnt, int fillmode);
int rsa_encrypt(RSA *key, unsigned char *encData, unsigned char *srcStr, unsigned int padding_mode);
int evp_encrypt(EVP_PKEY *key, unsigned char *encData, size_t *enclen, unsigned char *srcStr, ENGINE *eng);
int rsa_decrypt(RSA *key, unsigned char *decData, unsigned char *encData, size_t enclen, unsigned int padding_mode);
int evp_decrypt(EVP_PKEY *key, unsigned char *decData, size_t *declen, unsigned char *encData, size_t enclen, ENGINE *eng);
int rsa_sign(RSA *key, unsigned char *encData, unsigned char *srcStr, unsigned int padding_mode);
int rsa_verify(RSA *key, unsigned char *decData, unsigned char *encData, size_t enclen, unsigned int padding_mode);
int evp_sign(EVP_PKEY *key, unsigned char *encData, size_t *enclen, unsigned char *srcStr, ENGINE *eng);
int evp_verify(EVP_PKEY *key, unsigned char *decData, size_t declen, unsigned char *encData, size_t enclen, ENGINE *eng); 
int rsa_various_padding_mode(int keylen, unsigned char *srcStr, int padding);
int rsa_software_and_hardware_switch_mode(int keylen);
