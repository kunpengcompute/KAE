/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: 
 * @Author: nwq
 * @Date: 2025-01-13
 * @LastEditTime: 2025-01-13
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <openssl/engine.h>
#include <stdbool.h>

/*-
 * This demonstration will show how to digest data using
 * the soliloqy from Hamlet scene 1 act 3
 * The soliloqy is split into two parts to demonstrate using EVP_DigestUpdate
 * more than once.
 */
int demonstrate_digest(const EVP_MD *message_digest, char * msg1, char * msg2, unsigned char *digest_value,  unsigned int *digest_length)
{
    int ret = 0;
    const char *option_properties = NULL;

    EVP_MD_CTX *digest_context = NULL;
    unsigned int j;

    /*
     * Make a message digest context to hold temporary state
     * during digest creation
     */
    digest_context = EVP_MD_CTX_new();
    if (digest_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /*
     * Initialize the message digest context to use the fetched 
     * digest provider
     */
    if (EVP_DigestInit(digest_context, message_digest) != 1) {
        fprintf(stderr, "EVP_DigestInit failed.\n");
        goto cleanup;
    }

    /* Digest parts one and two of the soliloqy */
    if (EVP_DigestUpdate(digest_context, msg1, strlen(msg1)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestUpdate(digest_context, msg2, strlen(msg2)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestFinal(digest_context, digest_value, digest_length) != 1) {
        fprintf(stderr, "EVP_DigestFinal() failed.\n");
        goto cleanup;
    }

    printf("[DIGEST VALUE]\n");
    PRINTMSG(digest_value, *digest_length);


cleanup:
    if (ret != 1)
        ERR_print_errors_fp(stderr);
    /* OpenSSL free functions will ignore NULL arguments */
    EVP_MD_CTX_free(digest_context);

    return ret;
}

// 数据完整性校验
bool check_data_integrity(const char *received_message, const EVP_MD *digest, unsigned char expected_hash[], unsigned int *hash_len, ENGINE* engine)
{
    unsigned char recv_hash[EVP_MAX_MD_SIZE];

    // 计算接收到的消息的哈希值
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    if (EVP_DigestInit_ex(mdctx, digest, engine) <= 0 ||
        EVP_DigestUpdate(mdctx, received_message, strlen(received_message)) <= 0 ||
        EVP_DigestFinal_ex(mdctx,recv_hash, hash_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    EVP_MD_CTX_free(mdctx);

    return memcmp(recv_hash, expected_hash, *hash_len) == 0;
}

// 密码安全存储模拟
bool secure_password_storage(const char *password, const EVP_MD *digest, unsigned char expected_hash[], unsigned int *hash_len, ENGINE* engine)
{
    unsigned char salt[] = "random_salt"; // 实际应用中应该使用随机盐值
    unsigned char hashed_password[EVP_MAX_MD_SIZE];

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, digest, engine);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestUpdate(mdctx, salt, sizeof(salt) - 1); // 假定salt是C字符串
    EVP_DigestFinal_ex(mdctx, hashed_password, hash_len);
    EVP_MD_CTX_free(mdctx);

    return memcmp(hashed_password, expected_hash, *hash_len) == 0;
}