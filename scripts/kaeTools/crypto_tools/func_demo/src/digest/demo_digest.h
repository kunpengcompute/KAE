/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: 
 * @Author: nwq
 * @Date: 2025-01-13
 * @LastEditTime: 2025-01-13
 */

#ifndef DEMO_DIGEST_H
#define DEMO_DIGEST_H

#ifdef __cplusplus  
extern "C" {  
#endif  

int demonstrate_digest(const EVP_MD *message_digest, char * msg1, char * msg2, unsigned char *digest_value,  unsigned int *digest_length);

bool check_data_integrity(const char *received_message, const EVP_MD *digest, unsigned char expected_hash[], unsigned int *hash_len, ENGINE* engine);

bool secure_password_storage(const char *password, const EVP_MD *digest, unsigned char expected_hash[], unsigned int *hash_len, ENGINE* engine);

#ifdef __cplusplus  
}  
#endif  
#endif