/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for switch to soft ciphers
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
 * This file provides the implemenation for switch to soft ciphers
 *
 *****************************************************************************/
#include "engine_types.h"
#include "sec_ciphers_soft.h"
#include "sec_ciphers.h"
#include "sec_ciphers_utils.h"

#define CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 192

static cipher_threshold_table_t g_sec_ciphers_pkt_threshold_table[] = {
    { NID_aes_128_ecb, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_192_ecb, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_256_ecb, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_128_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_192_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_256_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_128_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_192_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_256_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_128_xts, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_aes_256_xts, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    
    { NID_sm4_cbc, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
    { NID_sm4_ctr, CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
};
static int g_sec_ciphers_pkt_threshold_table_size = BLOCKSIZES_OF(g_sec_ciphers_pkt_threshold_table);

static sw_cipher_t g_sec_ciphers_sw_cipher_table[] = {

    { NID_aes_128_ecb, EVP_aes_128_ecb },
    { NID_aes_192_ecb, EVP_aes_192_ecb },
    { NID_aes_256_ecb, EVP_aes_256_ecb },
    { NID_aes_128_cbc, EVP_aes_128_cbc },
    { NID_aes_192_cbc, EVP_aes_192_cbc },
    { NID_aes_256_cbc, EVP_aes_256_cbc },
    { NID_aes_128_ctr, EVP_aes_128_ctr },
    { NID_aes_192_ctr, EVP_aes_192_ctr },
    { NID_aes_256_ctr, EVP_aes_256_ctr },
    { NID_aes_128_xts, EVP_aes_128_xts },
    { NID_aes_256_xts, EVP_aes_256_xts },

    { NID_sm4_cbc, EVP_sm4_cbc },
    { NID_sm4_ctr, EVP_sm4_ctr },
};
static int g_sec_ciphers_sw_cipher_table_size = BLOCKSIZES_OF(g_sec_ciphers_sw_cipher_table);

static int sec_ciphers_sw_impl_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

int sec_ciphers_sw_get_threshold(int nid)
{
    int i = 0;

    do {
        if (g_sec_ciphers_pkt_threshold_table[i].nid == nid) {
            return g_sec_ciphers_pkt_threshold_table[i].threshold;
        }
    } while (++i < g_sec_ciphers_pkt_threshold_table_size);

    US_ERR("nid %d not found in threshold table", nid);

    return KAE_FAIL;
}

const EVP_CIPHER *sec_ciphers_get_cipher_sw_impl(int nid)
{
    int i = 0;

    for (i = 0; i < g_sec_ciphers_sw_cipher_table_size; i++) {
        if (nid == g_sec_ciphers_sw_cipher_table[i].nid) {
            return (g_sec_ciphers_sw_cipher_table[i].get_cipher)();
        }
    }
    US_WARN("Invalid nid %d\n", nid);

    return (EVP_CIPHER *)NULL;
}

int sec_ciphers_sw_impl_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
    int ret = KAE_FAIL;
    unsigned int sw_size = 0;

    cipher_priv_ctx_t* priv_ctx = NULL;
    const EVP_CIPHER *sw_cipher = NULL;

    /* allowed iv to be empty. */
    if (unlikely(key == NULL)) {
        US_ERR("kae sw init parameter is NULL. key=%p", key);
        return KAE_FAIL;
    }
    if (unlikely(ctx == NULL)) {
        US_ERR("kae sw init parameter is NULL. ctx=%p", ctx);
        return KAE_FAIL;
    }

    priv_ctx = (cipher_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (unlikely(priv_ctx == NULL)) {
        US_ERR("state is NULL");
        return KAE_FAIL;
    }
    
    sw_cipher = sec_ciphers_get_cipher_sw_impl(EVP_CIPHER_CTX_nid(ctx));
    if (unlikely(sw_cipher == NULL)) {
        int nid = EVP_CIPHER_CTX_nid(ctx);
        US_ERR("get openssl software cipher failed. nid = %d", nid);
        return KAE_FAIL;
    }

    sw_size = EVP_CIPHER_impl_ctx_size(sw_cipher);
    if (unlikely(sw_size == 0)) {
        US_ERR("get EVP cipher ctx size failed, sw_size=%d", sw_size);
        return KAE_FAIL;
    }
    
    if (priv_ctx->sw_ctx_data == NULL) {
        priv_ctx->sw_ctx_data = kae_malloc(sw_size);
        if (priv_ctx->sw_ctx_data == NULL) {
            US_ERR("Unable to allocate memory [%u bytes] for sw_ctx_data", sw_size);
            return KAE_FAIL;
        }
    }
    kae_memset(priv_ctx->sw_ctx_data, 0, sw_size);
    
    if (iv == NULL) {
        iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    }
    
    /* real implementation: Openssl soft arithmetic key initialization function */
    EVP_CIPHER_CTX_set_cipher_data(ctx, priv_ctx->sw_ctx_data);
    ret = EVP_CIPHER_meth_get_init(sw_cipher)(ctx, key, iv, enc);
    EVP_CIPHER_CTX_set_cipher_data(ctx, priv_ctx);
    if (ret != OPENSSL_SUCCESS) {
        US_ERR("OPENSSL init key failed. ctx=%p", ctx);
        kae_free(priv_ctx->sw_ctx_data);
        return KAE_FAIL;
    }
    US_DEBUG("kae sw init impl success. ctx=%p", ctx);

    return KAE_SUCCESS;
}

int sec_ciphers_sw_impl_cleanup(EVP_CIPHER_CTX *ctx)
{
    cipher_priv_ctx_t* priv_ctx = NULL;

    if (unlikely(ctx == NULL)) {
        US_WARN("ctx is NULL");
        return KAE_FAIL;
    }

#ifdef KAE_DEBUG_KEY_ENABLE
    dump_data("iv", EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_iv_length(ctx));
#endif

    priv_ctx = (cipher_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (unlikely(priv_ctx == NULL)) {
        US_WARN("ctx cipher private data is NULL.");
        return KAE_FAIL;
    }

    kae_free(priv_ctx->sw_ctx_data);

    US_DEBUG("kae sw cleanup impl success, ctx=%p", ctx);

    return KAE_SUCCESS;
}

static int sec_ciphers_sw_impl_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, 
    const unsigned char *in, size_t inl)
{
    if (unlikely((ctx == NULL) || (out == NULL) || (in == NULL))) {
        US_ERR("kae sw cipher parameter is null.ctx=%p, in=%p, out=%p, inl=%d", ctx, out, in, (int)inl);
        return KAE_FAIL;
    }

    cipher_priv_ctx_t* priv_ctx = (cipher_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (unlikely(priv_ctx == NULL)) {
        US_ERR("state is NULL");
        return KAE_FAIL;
    }

    const EVP_CIPHER* sw_cipher = sec_ciphers_get_cipher_sw_impl(EVP_CIPHER_CTX_nid(ctx));
    if (unlikely(sw_cipher == NULL)) {
        US_ERR("get OpenSSL cipher failed. ctx=%p", ctx);
        return KAE_FAIL;
    }

    EVP_CIPHER_CTX_set_cipher_data(ctx, priv_ctx->sw_ctx_data);
    int ret = EVP_CIPHER_meth_get_do_cipher(sw_cipher)(ctx, out, in, inl);
    if (unlikely(ret == OPENSSL_FAIL)) {
        EVP_CIPHER_CTX_set_cipher_data(ctx, priv_ctx);
        US_ERR("OpenSSL do cipher failed. ctx=%p", ctx);
        return KAE_FAIL;
    }
    
    EVP_CIPHER_CTX_set_cipher_data(ctx, priv_ctx);

    US_DEBUG("kae sw impl do cipher success, ctx=%p", ctx);

    return KAE_SUCCESS;
}

int sec_ciphers_software_encrypt(EVP_CIPHER_CTX *ctx, cipher_priv_ctx_t* priv_ctx)
{
    int ret = sec_ciphers_sw_impl_do_cipher(ctx, priv_ctx->out, priv_ctx->in, priv_ctx->left_len);
    if (ret != KAE_SUCCESS) {
        US_ERR("kae software do cipher or small packet cipher offload failed.");
        return KAE_FAIL;
    }
    
    // after openssl software do cipher, sync priv data to next priv data for hareware to contiune to do cipher */
    ret = sec_ciphers_sw_hw_ctx_sync(ctx, SEC_CIHPER_SYNC_S2W);
    if (unlikely(ret != KAE_SUCCESS)) {
        US_ERR("kae sw hw state sync failed.");
        return KAE_FAIL;
    }

    US_DEBUG("Cipher success, ctx=%p", ctx);
    return KAE_SUCCESS;
}

int sec_ciphers_sw_hw_ctx_sync(EVP_CIPHER_CTX *ctx, sec_cipher_priv_ctx_syncto_t direction)
{
    cipher_priv_ctx_t* priv_ctx = NULL;
    unsigned int num = 0;
    unsigned int offset = 0;

    US_DEBUG("sw hw state sync start. ctx=%p", ctx);

    priv_ctx = (cipher_priv_ctx_t *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (unlikely(priv_ctx == NULL)) {
        US_ERR("cipher priv ctx data is NULL.");
        return KAE_FAIL;
    }

    if (direction == SEC_CIHPER_SYNC_S2W) {
        kae_memcpy(priv_ctx->iv, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_iv_length(ctx));
        num = EVP_CIPHER_CTX_num(ctx);
        if (num) {
            sec_ciphers_ctr_iv_sub(priv_ctx->iv);
        }
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


int sec_ciphers_ecb_encryt(xts_ecb_data* ecb_encryto, uint8_t* buf_out, uint8_t* buf_in, int buf_len)
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

int sec_ciphers_ecb_decrypt(xts_ecb_data* ecb_encryto, uint8_t* buf_out, uint8_t* buf_in, int buf_len)
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

