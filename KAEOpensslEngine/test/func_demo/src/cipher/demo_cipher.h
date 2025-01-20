/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: 
 * @Author: nwq
 * @Date: 2025-01-16
 * @LastEditTime: 2025-01-16
 */
#ifndef DEMO_CIPHER_H
#define DEMO_CIPHER_H

#ifdef __cplusplus  
extern "C" {  
#endif 


// 定义一个枚举类型用于标识操作类型
typedef enum {
    ENCRYPT,
    DECRYPT
} Operation;

// 定义一个结构体来封装所有需要传递的信息
typedef struct {
    const EVP_CIPHER *cipher; // 加密算法
    const unsigned char *key;
    const unsigned char *iv;
    int key_len;
    int iv_len;
    Operation op; // 操作类型: 加密或解密
} CipherParams;


bool cipher_encrypt_decrypt(const unsigned char *input, int input_len, unsigned char *output,
                        int *output_len, const CipherParams *params, ENGINE* engine);

bool cipher_encrypt(const unsigned char *input, int input_len, unsigned char *output,
                        int *output_len, const CipherParams *params, ENGINE* engine);

bool cipher_decrypt(const unsigned char *input, int input_len, unsigned char *output,
                        int *output_len, const CipherParams *params, ENGINE* engine);

#ifdef __cplusplus  
}  
#endif  
#endif