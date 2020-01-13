/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the cipher interface for KAE engine utils dealing
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
* @file sec_ciphers_utils.h
*
* This file provides the implemenation for SEC engine utils dealing 
*
*****************************************************************************/

#ifndef SEC_CIPHERS_CHECKER_H
#define SEC_CIPHERS_CHECKER_H

#include "sec_ciphers.h"
#include "engine_kae.h"

#define IV_SIZE            16

enum CIPHERS_MODE {
    ECB,
    CBC,
    CTR,
    XTS,
};

enum CIPHERS_ALG {
    SM4,
    AES,
    DES,
    M_3DES,
};

int sec_ciphers_is_iv_may_overflow(EVP_CIPHER_CTX *ctx, cipher_priv_ctx_t *priv_ctx);
int sec_ciphers_get_cipher_mode(int nid);
int sec_ciphers_get_cipher_alg(int nid);

void sec_ciphers_ctr_iv_inc(uint8_t *counter, uint32_t c);
void sec_ciphers_ctr_iv_sub(uint8_t *counter);
void sec_ciphers_xts_iv_inc(cipher_priv_ctx_t* priv_ctx);

void sec_ciphers_update_iv(cipher_priv_ctx_t *tmp_docipher_ctx, int cipher_length);

#endif

