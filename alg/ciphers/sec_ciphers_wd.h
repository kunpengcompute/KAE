/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the cipher interface for KAE ciphers using wd interface
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
 * @file sec_cipher_wd.h
 *
 * This file provides the interface for SEC ciphers using wd interface
 *
 *****************************************************************************/

#ifndef SEC_CIPHERS_WD_H
#define SEC_CIPHERS_WD_H

#include "sec_ciphers.h"

cipher_engine_ctx_t* wd_ciphers_get_engine_ctx(cipher_priv_ctx_t* priv_ctx);
void wd_ciphers_put_engine_ctx(cipher_engine_ctx_t* e_cipher_ctx);
int wd_ciphers_do_crypto_impl(cipher_engine_ctx_t *e_cipher_ctx);

inline void wd_ciphers_set_input_data(cipher_engine_ctx_t *e_cipher_ctx);
inline void wd_ciphers_get_output_data(cipher_engine_ctx_t *e_cipher_ctx);
inline uint32_t wd_ciphers_get_do_cipher_len(uint32_t offset,  int leftlen);

int wd_ciphers_init_qnode_pool(void);
KAE_QUEUE_POOL_HEAD_S* wd_ciphers_get_qnode_pool(void);
void wd_ciphers_free_engine_ctx(void* engine_ctx);

#endif

