/*
 * Copyright 2026 Huawei Technologies Co.,Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
#include "utils/sm2_soft_provider.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <string.h>
#include <strings.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>

struct sm2_provider_methods {
	OSSL_LIB_CTX *libctx;
	OSSL_PROVIDER *provider;
	void *provctx;
	OSSL_FUNC_keymgmt_new_fn *key_new;
	OSSL_FUNC_keymgmt_free_fn *key_free;
	OSSL_FUNC_keymgmt_import_fn *key_import;
	OSSL_FUNC_signature_newctx_fn *sig_newctx;
	OSSL_FUNC_signature_freectx_fn *sig_freectx;
	OSSL_FUNC_signature_sign_init_fn *sign_init;
	OSSL_FUNC_signature_sign_fn *sign;
	OSSL_FUNC_signature_verify_init_fn *verify_init;
	OSSL_FUNC_signature_verify_fn *verify;
	OSSL_FUNC_asym_cipher_newctx_fn *cipher_newctx;
	OSSL_FUNC_asym_cipher_freectx_fn *cipher_freectx;
	OSSL_FUNC_asym_cipher_encrypt_init_fn *encrypt_init;
	OSSL_FUNC_asym_cipher_encrypt_fn *encrypt;
	OSSL_FUNC_asym_cipher_decrypt_init_fn *decrypt_init;
	OSSL_FUNC_asym_cipher_decrypt_fn *decrypt;
	int ready;
};

static struct sm2_provider_methods g_sm2_provider;
static CRYPTO_ONCE g_sm2_provider_once = CRYPTO_ONCE_STATIC_INIT;

static const OSSL_DISPATCH *find_sm2_algorithm(OSSL_PROVIDER *provider,
					       int operation)
{
	const OSSL_ALGORITHM *algs;
	int no_cache = 0;

	algs = OSSL_PROVIDER_query_operation(provider, operation, &no_cache);
	if (!algs)
		return NULL;
	for (; algs->algorithm_names; algs++) {
		const char *name = algs->algorithm_names;

		while (*name) {
			const char *end = strchr(name, ':');

			if (!end)
				end = name + strlen(name);
			if (end - name == 3 && !strncasecmp(name, "SM2", 3))
				return algs->implementation;
			name = *end == ':' ? end + 1 : end;
		}
	}
	return NULL;
}

static void load_key_methods(const OSSL_DISPATCH *dispatch)
{
	for (; dispatch && dispatch->function_id; dispatch++) {
		switch (dispatch->function_id) {
		case OSSL_FUNC_KEYMGMT_NEW:
			g_sm2_provider.key_new = OSSL_FUNC_keymgmt_new(dispatch);
			break;
		case OSSL_FUNC_KEYMGMT_FREE:
			g_sm2_provider.key_free = OSSL_FUNC_keymgmt_free(dispatch);
			break;
		case OSSL_FUNC_KEYMGMT_IMPORT:
			g_sm2_provider.key_import = OSSL_FUNC_keymgmt_import(dispatch);
			break;
		default:
			break;
		}
	}
}

static void load_signature_methods(const OSSL_DISPATCH *dispatch)
{
	for (; dispatch && dispatch->function_id; dispatch++) {
		switch (dispatch->function_id) {
		case OSSL_FUNC_SIGNATURE_NEWCTX:
			g_sm2_provider.sig_newctx = OSSL_FUNC_signature_newctx(dispatch);
			break;
		case OSSL_FUNC_SIGNATURE_FREECTX:
			g_sm2_provider.sig_freectx = OSSL_FUNC_signature_freectx(dispatch);
			break;
		case OSSL_FUNC_SIGNATURE_SIGN_INIT:
			g_sm2_provider.sign_init = OSSL_FUNC_signature_sign_init(dispatch);
			break;
		case OSSL_FUNC_SIGNATURE_SIGN:
			g_sm2_provider.sign = OSSL_FUNC_signature_sign(dispatch);
			break;
		case OSSL_FUNC_SIGNATURE_VERIFY_INIT:
			g_sm2_provider.verify_init = OSSL_FUNC_signature_verify_init(dispatch);
			break;
		case OSSL_FUNC_SIGNATURE_VERIFY:
			g_sm2_provider.verify = OSSL_FUNC_signature_verify(dispatch);
			break;
		default:
			break;
		}
	}
}

static void load_cipher_methods(const OSSL_DISPATCH *dispatch)
{
	for (; dispatch && dispatch->function_id; dispatch++) {
		switch (dispatch->function_id) {
		case OSSL_FUNC_ASYM_CIPHER_NEWCTX:
			g_sm2_provider.cipher_newctx = OSSL_FUNC_asym_cipher_newctx(dispatch);
			break;
		case OSSL_FUNC_ASYM_CIPHER_FREECTX:
			g_sm2_provider.cipher_freectx = OSSL_FUNC_asym_cipher_freectx(dispatch);
			break;
		case OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT:
			g_sm2_provider.encrypt_init = OSSL_FUNC_asym_cipher_encrypt_init(dispatch);
			break;
		case OSSL_FUNC_ASYM_CIPHER_ENCRYPT:
			g_sm2_provider.encrypt = OSSL_FUNC_asym_cipher_encrypt(dispatch);
			break;
		case OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT:
			g_sm2_provider.decrypt_init = OSSL_FUNC_asym_cipher_decrypt_init(dispatch);
			break;
		case OSSL_FUNC_ASYM_CIPHER_DECRYPT:
			g_sm2_provider.decrypt = OSSL_FUNC_asym_cipher_decrypt(dispatch);
			break;
		default:
			break;
		}
	}
}

static void load_sm2_provider(void)
{
	g_sm2_provider.libctx = OSSL_LIB_CTX_new();
	if (!g_sm2_provider.libctx)
		return;
	g_sm2_provider.provider = OSSL_PROVIDER_load(g_sm2_provider.libctx,
						      "default");
	if (!g_sm2_provider.provider) {
		OSSL_LIB_CTX_free(g_sm2_provider.libctx);
		g_sm2_provider.libctx = NULL;
		return;
	}
	g_sm2_provider.provctx =
		OSSL_PROVIDER_get0_provider_ctx(g_sm2_provider.provider);
	load_key_methods(find_sm2_algorithm(g_sm2_provider.provider,
					    OSSL_OP_KEYMGMT));
	load_signature_methods(find_sm2_algorithm(g_sm2_provider.provider,
						  OSSL_OP_SIGNATURE));
	load_cipher_methods(find_sm2_algorithm(g_sm2_provider.provider,
					       OSSL_OP_ASYM_CIPHER));
	g_sm2_provider.ready = g_sm2_provider.key_new &&
		g_sm2_provider.key_free && g_sm2_provider.key_import &&
		g_sm2_provider.sig_newctx && g_sm2_provider.sig_freectx &&
		g_sm2_provider.sign_init && g_sm2_provider.sign &&
		g_sm2_provider.verify_init && g_sm2_provider.verify &&
		g_sm2_provider.cipher_newctx && g_sm2_provider.cipher_freectx &&
		g_sm2_provider.encrypt_init && g_sm2_provider.encrypt &&
		g_sm2_provider.decrypt_init && g_sm2_provider.decrypt;
}

static int provider_ready(void)
{
	return CRYPTO_THREAD_run_once(&g_sm2_provider_once, load_sm2_provider) &&
		g_sm2_provider.ready;
}

EC_KEY *kae_sm2_get_legacy_ec(EVP_PKEY *pkey,
				      struct kae_sm2_soft_ctx *soft)
{
	BIGNUM *private_key = NULL;
	unsigned char *public_key = NULL;
	EC_POINT *point = NULL;
	EC_KEY *ec = NULL;
	char group_name[32];
	size_t public_key_len = 0;

	if (!pkey || !soft)
		return NULL;
	if (!EVP_PKEY_get0_provider(pkey))
		return (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
	if (soft->legacy_ec && soft->legacy_pkey == pkey)
		return soft->legacy_ec;
	if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
					    group_name, sizeof(group_name), NULL) ||
	    strcasecmp(group_name, "SM2") ||
	    !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
					     NULL, 0, &public_key_len) ||
	    !public_key_len)
		return NULL;

	public_key = OPENSSL_malloc(public_key_len);
	ec = EC_KEY_new_by_curve_name(NID_sm2);
	if (!public_key || !ec ||
	    !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
					     public_key, public_key_len,
					     &public_key_len))
		goto err;
	point = EC_POINT_new(EC_KEY_get0_group(ec));
	if (!point || !EC_POINT_oct2point(EC_KEY_get0_group(ec), point,
					 public_key, public_key_len, NULL) ||
	    !EC_KEY_set_public_key(ec, point))
		goto err;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &private_key) &&
	    !EC_KEY_set_private_key(ec, private_key))
		goto err;

	EC_KEY_free(soft->legacy_ec);
	soft->legacy_ec = ec;
	soft->legacy_pkey = pkey;
	EC_POINT_free(point);
	BN_clear_free(private_key);
	OPENSSL_free(public_key);
	return ec;
err:
	EC_POINT_free(point);
	EC_KEY_free(ec);
	BN_clear_free(private_key);
	OPENSSL_free(public_key);
	return NULL;
}

static void free_provider_key(struct kae_sm2_soft_ctx *soft)
{
	if (soft->key && g_sm2_provider.key_free)
		g_sm2_provider.key_free(soft->key);
	soft->key = NULL;
	soft->pkey = NULL;
	soft->key_has_private = 0;
}

static void *import_provider_key(struct kae_sm2_soft_ctx *soft,
				 EVP_PKEY *pkey, int need_private)
{
	EC_KEY *ec;
	const EC_GROUP *group;
	const EC_POINT *point;
	const BIGNUM *private_key;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	unsigned char *public_key = NULL;
	void *key = NULL;
	size_t public_key_len;
	int selection;

	if (!soft || !pkey || !provider_ready())
		return NULL;
	if (soft->key && soft->pkey == pkey &&
	    (!need_private || soft->key_has_private))
		return soft->key;
	ec = kae_sm2_get_legacy_ec(pkey, soft);
	if (!ec)
		return NULL;
	private_key = EC_KEY_get0_private_key(ec);
	if (need_private && !private_key)
		return NULL;
	group = EC_KEY_get0_group(ec);
	point = EC_KEY_get0_public_key(ec);
	public_key_len = EC_POINT_point2oct(group, point,
					    POINT_CONVERSION_UNCOMPRESSED,
					    NULL, 0, NULL);
	public_key = OPENSSL_malloc(public_key_len);
	bld = OSSL_PARAM_BLD_new();
	if (!public_key_len || !public_key || !bld ||
	    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
			       public_key, public_key_len, NULL) != public_key_len ||
	    !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					    "SM2", 0) ||
	    !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
					     public_key, public_key_len))
		goto out;
	selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS |
		OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
	if (private_key) {
		if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
					    private_key))
			goto out;
		selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
	}
	params = OSSL_PARAM_BLD_to_param(bld);
	key = g_sm2_provider.key_new(g_sm2_provider.provctx);
	if (!params || !key ||
	    !g_sm2_provider.key_import(key, selection, params)) {
		if (key)
			g_sm2_provider.key_free(key);
		key = NULL;
		goto out;
	}
	free_provider_key(soft);
	soft->key = key;
	soft->pkey = pkey;
	soft->key_has_private = private_key != NULL;
out:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	OPENSSL_free(public_key);
	return key;
}

int kae_sm2_soft_sign(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
		      unsigned char *sig, size_t *siglen,
		      const unsigned char *tbs, size_t tbslen)
{
	void *key = import_provider_key(soft, pkey, 1);
	void *ctx;
	size_t sigsize;
	int ret;

	if (!key || !siglen)
		return 0;
	ctx = g_sm2_provider.sig_newctx(g_sm2_provider.provctx,
					 "provider=default");
	if (!ctx)
		return 0;
	sigsize = sig ? *siglen : 0;
	ret = g_sm2_provider.sign_init(ctx, key, NULL) &&
		g_sm2_provider.sign(ctx, sig, siglen, sigsize, tbs, tbslen);
	g_sm2_provider.sig_freectx(ctx);
	return ret;
}

int kae_sm2_soft_verify(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
			const unsigned char *sig, size_t siglen,
			const unsigned char *tbs, size_t tbslen)
{
	void *key = import_provider_key(soft, pkey, 0);
	void *ctx;
	int ret;

	if (!key)
		return 0;
	ctx = g_sm2_provider.sig_newctx(g_sm2_provider.provctx,
					 "provider=default");
	if (!ctx)
		return 0;
	ret = g_sm2_provider.verify_init(ctx, key, NULL) &&
		g_sm2_provider.verify(ctx, sig, siglen, tbs, tbslen);
	g_sm2_provider.sig_freectx(ctx);
	return ret;
}

static int soft_cipher(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen, int decrypt)
{
	void *key = import_provider_key(soft, pkey, decrypt);
	void *ctx;
	size_t outsize;
	int ret;

	if (!key || !outlen)
		return 0;
	ctx = g_sm2_provider.cipher_newctx(g_sm2_provider.provctx);
	if (!ctx)
		return 0;
	outsize = out ? *outlen : 0;
	if (decrypt)
		ret = g_sm2_provider.decrypt_init(ctx, key, NULL) &&
			g_sm2_provider.decrypt(ctx, out, outlen, outsize, in, inlen);
	else
		ret = g_sm2_provider.encrypt_init(ctx, key, NULL) &&
			g_sm2_provider.encrypt(ctx, out, outlen, outsize, in, inlen);
	g_sm2_provider.cipher_freectx(ctx);
	return ret;
}

int kae_sm2_soft_encrypt(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
			 unsigned char *out, size_t *outlen,
			 const unsigned char *in, size_t inlen)
{
	return soft_cipher(soft, pkey, out, outlen, in, inlen, 0);
}

int kae_sm2_soft_decrypt(struct kae_sm2_soft_ctx *soft, EVP_PKEY *pkey,
			 unsigned char *out, size_t *outlen,
			 const unsigned char *in, size_t inlen)
{
	return soft_cipher(soft, pkey, out, outlen, in, inlen, 1);
}

void kae_sm2_soft_cleanup(struct kae_sm2_soft_ctx *soft)
{
	if (!soft)
		return;
	free_provider_key(soft);
	EC_KEY_free(soft->legacy_ec);
	soft->legacy_ec = NULL;
	soft->legacy_pkey = NULL;
}
#endif
