/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for KAE engine utils dealing with wrapdrive
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
* @file sec_ciphers_utils.c
*
* This file provides the interface for SEC engine dealing with wrapdrive
*
*****************************************************************************/


#include "sec_ciphers_utils.h"
#include "engine_types.h"
#include "sec_ciphers_soft.h"

int sec_ciphers_get_cipher_mode(int nid)
{
    uint32_t c_mode = NO_C_MODE;

    switch (nid) {
        case NID_aes_128_ecb:
        case NID_aes_192_ecb:
        case NID_aes_256_ecb:
            c_mode = ECB;
            break;
        case NID_aes_128_cbc:
        case NID_aes_192_cbc:
        case NID_aes_256_cbc:
        case NID_sm4_cbc:
            c_mode = CBC;
            break;
        case NID_aes_128_ctr:
        case NID_aes_192_ctr:
        case NID_aes_256_ctr:
        case NID_sm4_ctr:
            c_mode = CTR;
            break;
        case NID_aes_128_xts:
        case NID_aes_256_xts:
            c_mode = XTS;
            break;
        default:
            US_WARN("nid=%d don't support by sec engine.", nid);
            break;
    }

    return c_mode;
}

int sec_ciphers_get_cipher_alg(int nid)
{
    uint32_t c_alg = NO_C_ALG;
    switch (nid) {
        case NID_sm4_ctr:
        case NID_sm4_cbc:
            c_alg = SM4;
            break;
        case NID_aes_128_ecb:
        case NID_aes_192_ecb:
        case NID_aes_256_ecb:
        case NID_aes_128_cbc:
        case NID_aes_192_cbc:
        case NID_aes_256_cbc:
        case NID_aes_128_ctr:
        case NID_aes_192_ctr:
        case NID_aes_256_ctr:
        case NID_aes_128_xts:
        case NID_aes_256_xts:
            c_alg = AES;
            break;
        default:
            US_WARN("nid=%d don't support by sec engine.", nid);
            break;
    }

    return c_alg;
}

/*
 *   SEC ENGINE IV: {Flag, Random, Counter} 
 *   | <--4--> <--8-->  | <---4bytes ---> |
 *   |   Flag, Random   |     counter     |
 */
static unsigned int __iv_to_engine_counter(const uint8_t *iv)
{
    unsigned int counter = 0;
    const unsigned int SEC_IV_COUNTER_POSTION = 12;

    counter |= iv[SEC_IV_COUNTER_POSTION];
    counter <<= 8; // left shift 8
    counter |= iv[(unsigned int)(SEC_IV_COUNTER_POSTION + 1)]; // count num 1
    counter <<= 8; // left shift 8
    counter |= iv[(unsigned int)(SEC_IV_COUNTER_POSTION + 2)]; // count num 2
    counter <<= 8; // left shift 8
    counter |= iv[(unsigned int)(SEC_IV_COUNTER_POSTION + 3)]; // count num 3

    return counter;
}

/* increment counter (128-bit int) by c */
void sec_ciphers_ctr_iv_inc(uint8_t *counter, uint32_t c)
{
    uint32_t n = 16;

    do {
        --n;
        c += counter[n];
        counter[n] = (uint8_t)c;
        c >>= 8; // right shift 8
    } while (n);
}

void sec_ciphers_xts_iv_inc(cipher_priv_ctx_t* priv_ctx)
{
    uint32_t i = 0;
    unsigned int carry;
    unsigned int res;

    union {
        uint64_t u[2]; // union length 2
        uint32_t d[4]; // union length 4
        uint8_t  c[16]; // union length 16
    }tweak;
    
    kae_memcpy(tweak.c, priv_ctx->ecb_encryto->encryto_iv, 16); // encrypto iv length 16
    
    for (i = 0; i < priv_ctx->ecb_encryto->countNum; i++) {
        // cppcheck-suppress *
        res = 0x87 & (((int)tweak.d[3]) >> 31); // algorithm para 31
        carry = (unsigned int)(tweak.u[0] >> 63); // algorithm para 63
        tweak.u[0] = (tweak.u[0] << 1) ^ res;
        tweak.u[1] = (tweak.u[1] << 1) | carry;
    }
            
    sec_ciphers_ecb_decrypt(priv_ctx->ecb_encryto, priv_ctx->ecb_encryto->iv_out, tweak.c, 16); // iv len 16

    kae_memcpy(priv_ctx->iv, priv_ctx->ecb_encryto->iv_out, 16); // update iv len 16
}

void sec_ciphers_ctr_iv_sub(uint8_t *counter)
{
    unsigned int n = 16;
    int c = 0;

    do {
        --n;
        c = counter[n] < 1 ? 1 : 0;
        counter[n] = (unsigned char)(counter[n] + c * 256 - 1); // algorithm para 256
        if (c == 0) {
            break;
        }
    } while (n);
}

void sec_ciphers_update_iv(cipher_priv_ctx_t *tmp_docipher_ctx, int cipher_length)
{
    unsigned int inc_counter = 0;
    
    switch (tmp_docipher_ctx->c_mode) {
        case CBC:
            if (tmp_docipher_ctx->encrypt == OPENSSL_ENCRYPTION) {
                kae_memcpy(tmp_docipher_ctx->iv, tmp_docipher_ctx->out + cipher_length - IV_SIZE, IV_SIZE);
            }
            break;
        case CTR:
            inc_counter = cipher_length >> 4;  // right shift 4
            sec_ciphers_ctr_iv_inc(tmp_docipher_ctx->iv, inc_counter);
            break;
        case XTS:
            // update iv here
            break;
        default:
            break;
    }

    return;
}

int sec_ciphers_is_iv_may_overflow(EVP_CIPHER_CTX *ctx, cipher_priv_ctx_t *priv_ctx)
{
    unsigned int will_inc_counter = 0;
    unsigned int current_counter = 0;

    if (sec_ciphers_get_cipher_mode(EVP_CIPHER_CTX_nid(ctx)) == CTR) {
        // （input length + prev offset）/ 16 = will_inc_counter
        will_inc_counter = (priv_ctx->inl + priv_ctx->offset) >> 4; // right shift 4
        current_counter = __iv_to_engine_counter(priv_ctx->iv);
        if ((0xFFFFFFFFU - current_counter < will_inc_counter)) {
            US_DEBUG("ciphers increase iv overflow 0xFFFFFFFF.");
            return 1;
        }
    }

    return 0;
}

