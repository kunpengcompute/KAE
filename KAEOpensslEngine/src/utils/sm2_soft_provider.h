/*
 * Copyright 2026 Huawei Technologies Co.,Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef KAE_SM2_SOFT_PROVIDER_H
#define KAE_SM2_SOFT_PROVIDER_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/ec.h>
#include <openssl/evp.h>

struct kae_sm2_soft_ctx {
	void *key;
	const EVP_PKEY *pkey;
	int key_has_private;
	EC_KEY *legacy_ec;
	const EVP_PKEY *legacy_pkey;
};

EC_KEY *kae_sm2_get_legacy_ec(EVP_PKEY *pkey,
				      struct kae_sm2_soft_ctx *soft);
int kae_sm2_soft_sign(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
		      unsigned char *sig, size_t *siglen,
		      const unsigned char *tbs, size_t tbslen);
int kae_sm2_soft_verify(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
			const unsigned char *sig, size_t siglen,
			const unsigned char *tbs, size_t tbslen);
int kae_sm2_soft_encrypt(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
			 unsigned char *out, size_t *outlen,
			 const unsigned char *in, size_t inlen);
int kae_sm2_soft_decrypt(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
			 unsigned char *out, size_t *outlen,
			 const unsigned char *in, size_t inlen);
void kae_sm2_soft_cleanup(struct kae_sm2_soft_ctx *soft);
#endif

#endif
