/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the implementation for switch to soft ciphers
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
 * @file sec_ciphers_soft.c
 *
 * This file provides the implementation for switch to soft ciphers
 *
 *****************************************************************************/
#include "../../../common/kae_types.h"
#include "../../../common/kae_log.h"
#include "sec_ciphers_soft.h"
#include "sec_ciphers.h"
#include "sec_ciphers_utils.h"

#define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 192

static cipher_threshold_table_t g_sec_ciphers_pkt_threshold_table[] = {
    {NID_aes_128_ecb, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_192_ecb, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_ecb, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_192_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_192_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_xts, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_xts, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_cfb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_192_cfb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_cfb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_128_ofb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_192_ofb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_aes_256_ofb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sm4_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sm4_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sm4_ofb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sm4_cfb128, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
    {NID_sm4_ecb, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
};
static int g_sec_ciphers_pkt_threshold_table_size = BLOCKSIZES_OF(g_sec_ciphers_pkt_threshold_table);

int sec_ciphers_sw_get_threshold(int nid)
{
    int i = 0;

    do {
        if (g_sec_ciphers_pkt_threshold_table[i].nid == nid)
            return g_sec_ciphers_pkt_threshold_table[i].threshold;
    } while (++i < g_sec_ciphers_pkt_threshold_table_size);

    US_ERR("nid %d not found in threshold table", nid);

    return KAE_FAIL;
}

int sec_ciphers_sw_hw_ctx_sync(EVP_CIPHER_CTX *ctx, sec_cipher_priv_ctx_syncto_t direction)
{
    cipher_priv_ctx *priv_ctx = NULL;
    unsigned int num = 0;
    unsigned int offset = 0;

    US_DEBUG("sw hw state sync start. ctx=%p", ctx);

    priv_ctx = (cipher_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (unlikely(priv_ctx == NULL)) {
        US_ERR("cipher priv ctx data is NULL.");
        return KAE_FAIL;
    }

    if (direction == SEC_CIHPER_SYNC_S2W) {
        kae_memcpy(priv_ctx->iv, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_iv_length(ctx));
        num = EVP_CIPHER_CTX_num(ctx);
        if (num)
            sec_ciphers_ctr_iv_sub(priv_ctx->iv);
        priv_ctx->offset = num;
        priv_ctx->left_len = 0;
    } else {
        if (priv_ctx->do_cipher_len != 0) {
            offset = priv_ctx->offset;
            kae_memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), priv_ctx->iv, EVP_CIPHER_CTX_iv_length(ctx));
            EVP_CIPHER_CTX_set_num(ctx, offset);
        }
    }

    US_DEBUG("state sync success, direct=%d[1:SW_TO_HW, 2:HW_TO_SW], offset=%d", direction, num);

    return KAE_SUCCESS;
}

int sec_ciphers_ecb_encryt(xts_ecb_data *ecb_encryto, uint8_t *buf_out, uint8_t *buf_in, int buf_len)
{
    int out_len1, tmplen;
    /* Encrypt */
    if (!EVP_EncryptInit_ex(ecb_encryto->ecb_ctx, ecb_encryto->cipher_type, NULL, ecb_encryto->key2, NULL)) {
        US_ERR("EVP_EncryptInit failed.\n");
        return KAE_FAIL;
    }
    EVP_CIPHER_CTX_set_padding(ecb_encryto->ecb_ctx, 0);

    if (!EVP_EncryptUpdate(ecb_encryto->ecb_ctx, buf_out, &out_len1, buf_in, buf_len)) {
        US_ERR("EVP_EncryptUpdate failed.\n");
        return KAE_FAIL;
    }

    if (!EVP_EncryptFinal_ex(ecb_encryto->ecb_ctx, buf_out + out_len1, &tmplen)) {
        /* Error */
        return KAE_FAIL;
    }
    out_len1 += tmplen;

    return KAE_SUCCESS;
}

int sec_ciphers_ecb_decrypt(xts_ecb_data *ecb_encryto, uint8_t *buf_out, uint8_t *buf_in, int buf_len)
{
    int out_len1, tmplen;

    /* decrypt */
    if (!EVP_DecryptInit_ex(ecb_encryto->ecb_ctx, ecb_encryto->cipher_type, NULL, ecb_encryto->key2, NULL)) {
        US_ERR("EVP_EncryptInit failed.\n");
        return KAE_FAIL;
    }

    EVP_CIPHER_CTX_set_padding(ecb_encryto->ecb_ctx, 0);

    if (!EVP_DecryptUpdate(ecb_encryto->ecb_ctx, buf_out, &out_len1, buf_in, buf_len)) {
        US_ERR("EVP_EncryptUpdate failed.\n");
        return KAE_FAIL;
    }

    if (!EVP_DecryptFinal_ex(ecb_encryto->ecb_ctx, buf_out + out_len1, &tmplen)) {
        /* Error */
        return KAE_FAIL;
    }
    out_len1 += tmplen;

    return KAE_SUCCESS;
}
