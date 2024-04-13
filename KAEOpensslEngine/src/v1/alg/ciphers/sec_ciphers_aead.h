/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the interface for KAE engine dealing with wrapdrive
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
 * @file sec_cipher.h
 *
 * This file provides the interface for SEC engine dealing with wrapdrive
 *
 *****************************************************************************/

#ifndef SEC_CIPHERS_AEAD_H
#define SEC_CIPHERS_AEAD_H
#include <openssl/engine.h>

#define SEC_AEAD_RETURN_FAIL_IF(cond, mesg, ret) \
	do { \
		if (unlikely(cond)) { \
			US_ERR(mesg); \
				return (ret); \
		} \
	} while (0)

#define SEC_AEAD_GOTO_FAIL_IF(cond, mesg, tag) \
	do { \
		if (unlikely(cond)) { \
			US_ERR(mesg); \
				goto tag; \
		} \
	} while (0)

enum openssl_aead_enc_t {
	OPENSSL_DECRYPTION = 0,
	OPENSSL_ENCRYPTION = 1
};

enum sec_aead_priv_ctx_syncto {
	SEC_CIHPER_SYNC_S2W = 1,    // software priv ctx sync to hareware priv ctx
	SEC_CIHPER_SYNC_H2S,        // hareware priv ctx sync to software priv ctx
};
typedef enum sec_aead_priv_ctx_syncto sec_aead_priv_ctx_syncto_t;

typedef struct xts_ecb_data_strcut {
	EVP_CIPHER_CTX *ecb_ctx;
	const EVP_CIPHER *cipher_type;
	uint8_t *key2;
	uint8_t  key2_len;
	uint8_t *iv_out;
	uint8_t *encryto_iv;
	uint32_t countNum;
} xts_ecb_data;

typedef struct aead_engine_ctx aead_engine_ctx_t;

struct aead_priv_ctx {
	uint8_t         *key;         // key
	uint32_t        key_len;     // key length
	unsigned char   iv[16];
	unsigned char   mac[16];
	const uint8_t	*in;
	uint8_t         *out;
	uint32_t        c_mode;
	uint32_t        c_alg;
	int 			encrypt;

	size_t          switch_threshold; // crypt small packet offload threshold
	void            *sw_ctx_data;      // Pointer for context data that will be used by Small packet offload feature.
	aead_engine_ctx_t *e_aead_ctx;
};

typedef struct aead_priv_ctx aead_priv_ctx_t;

struct aead_engine_ctx {
	KAE_QUEUE_DATA_NODE_S		*q_node;
	struct wcrypto_aead_op_data   op_data;
	struct wcrypto_aead_ctx_setup setup;
	void                            *wd_ctx;    // one ctx or a list of ctx

	aead_priv_ctx_t               *priv_ctx;
};

EVP_CIPHER *sec_ciphers_set_gcm_method(int nid)

#endif
