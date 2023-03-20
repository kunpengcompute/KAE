/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the cipher interface for soft ciphers
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*****************************************************************************
* @file sec_ciphers_soft.h
*
* This file provides the cipher interface for soft ciphers
*
*****************************************************************************/

#ifndef SEC_CIPHERS_SOFT_H
#define SEC_CIPHERS_SOFT_H

#include "sec_ciphers.h"
#include "engine_kae.h"

typedef struct cipher_threshold_table_s {
    int nid;
    int threshold;
} cipher_threshold_table_t;

typedef struct sw_cipher_s {
    int nid;
    const EVP_CIPHER *(*get_cipher)(void);
} sw_cipher_t;

const EVP_CIPHER *sec_ciphers_get_cipher_sw_impl(int nid);
int sec_ciphers_sw_get_threshold(int nid);
int sec_ciphers_sw_impl_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sec_ciphers_sw_impl_cleanup(EVP_CIPHER_CTX *ctx);
int sec_ciphers_software_encrypt(EVP_CIPHER_CTX *ctx, cipher_priv_ctx_t* priv_ctx);
int sec_ciphers_sw_hw_ctx_sync(EVP_CIPHER_CTX *ctx, sec_cipher_priv_ctx_syncto_t direction);
int sec_ciphers_ecb_encryt(xts_ecb_data* ecb_encryto, uint8_t* buf_out, uint8_t* buf_in, int buf_len);
int sec_ciphers_ecb_decrypt(xts_ecb_data* ecb_encryto, uint8_t* buf_out, uint8_t* buf_in, int buf_len);


#endif

