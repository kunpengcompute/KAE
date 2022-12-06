/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:    This file provides the implementation for KAE engine DH.
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

#include <openssl/evp.h>
#include "hpre_dh.h"
#include "hpre_dh_wd.h"
#include "hpre_dh_soft.h"
#include "hpre_dh_util.h"
#include "../../utils/engine_types.h"
#include "../../utils/engine_opensslerr.h"
#include "../../async/async_task_queue.h"
#include "../../utils/engine_log.h"

#define DH768BITS 768
#define DH1024BITS 1024
#define DH1536BITS 1536
#define DH2048BITS 2048
#define DH3072BITS 3072
#define DH4096BITS 4096

#define GENERATOR_2 2

#ifndef OPENSSL_NO_DH
const int DHPKEYMETH_IDX = 1;
#else
const int DHPKEYMETH_IDX = -1;
#endif

const char *g_hpre_dh_device = "hisi_hpre";
static DH_METHOD *g_hpre_dh_method;
static EVP_PKEY_METHOD *g_hpre_dh_pkey_meth;

static int hpre_dh_generate_key(DH *dh);

static int hpre_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);

static int hpre_db_bn_mod_exp(
		const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

static int check_dh_bit_useful(const int bit);

static int prepare_dh_data(const int bits, const BIGNUM *g, DH *dh, hpre_dh_engine_ctx_t **eng_ctx, BIGNUM **priv_key);

static int hpre_dh_ctx_poll(void *engine_ctx);

const DH_METHOD *hpre_get_dh_methods(void)
{
	int ret = 1;

	if (g_hpre_dh_method != NULL)
		return g_hpre_dh_method;

	/*
	 *  if (!kae_get_device(g_hpre_dh_device)) {
	 *  const DH_METHOD* default_soft_method = DH_OpenSSL();
	 *  return default_soft_method;
	 *  }
	 */
	g_hpre_dh_method = DH_meth_new("HPRE DH method", 0);
	if (g_hpre_dh_method == NULL) {
		KAEerr(KAE_F_HPRE_GET_DH_METHODS, KAE_R_MALLOC_FAILURE);
		US_ERR("Failed to allocate HPRE DH methods");
		return NULL;
	}

	ret &= DH_meth_set_generate_key(g_hpre_dh_method, hpre_dh_generate_key);
	ret &= DH_meth_set_compute_key(g_hpre_dh_method, hpre_dh_compute_key);
	ret &= DH_meth_set_bn_mod_exp(g_hpre_dh_method, hpre_db_bn_mod_exp);
	if (ret == 0) {
		KAEerr(KAE_F_HPRE_GET_DH_METHODS, KAE_R_DH_SET_METHODS_FAILURE);
		US_ERR("Failed to set HPRE DH methods");
		return NULL;
	}

	return g_hpre_dh_method;
}

int hpre_module_dh_init(void)
{
	wd_hpre_dh_init_qnode_pool();

	(void)get_dh_pkey_meth();
	(void)hpre_get_dh_methods();

	/* register async poll func */
	async_register_poll_fn_v1(ASYNC_TASK_DH, hpre_dh_ctx_poll);

	return HPRE_DH_SUCCESS;
}

void hpre_dh_destroy(void)
{
	if (g_hpre_dh_method != NULL) {
		DH_meth_free(g_hpre_dh_method);
		g_hpre_dh_method = NULL;
	}
}

EVP_PKEY_METHOD *get_dh_pkey_meth(void)
{
	const EVP_PKEY_METHOD *def_dh = EVP_PKEY_meth_get0(DHPKEYMETH_IDX);

	if (g_hpre_dh_pkey_meth == NULL) {
		g_hpre_dh_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_DH, 0);
		if (g_hpre_dh_pkey_meth == NULL) {
			US_ERR("failed to new pkey meth");
			return NULL;
		}
		EVP_PKEY_meth_copy(g_hpre_dh_pkey_meth, def_dh);
	}

	return g_hpre_dh_pkey_meth;
}

EVP_PKEY_METHOD *get_dsa_pkey_meth(void)
{
	return (EVP_PKEY_METHOD *)EVP_PKEY_meth_get0(DHPKEYMETH_IDX);
}

static int hpre_dh_ctx_poll(void *engine_ctx)
{
	int ret;
	hpre_dh_engine_ctx_t *eng_ctx = (hpre_dh_engine_ctx_t *)engine_ctx;
	struct wd_queue *q = eng_ctx->qlist->kae_wd_queue;
poll_again:
	ret = wcrypto_dh_poll(q, 1);
	if (!ret) {
		goto poll_again;
	} else if (ret < 0) {
		US_ERR("dh poll fail!\n");
		return ret;
	}
	return ret;
}

static int hpre_dh_generate_key(DH *dh)
{
	int bits = DH_bits(dh);
	const BIGNUM *p = NULL;
	const BIGNUM *g = NULL;
	const BIGNUM *q = NULL;
	BIGNUM *pub_key = NULL;
	BIGNUM *priv_key = NULL;
	hpre_dh_engine_ctx_t *eng_ctx = NULL;
	int ret = HPRE_DH_FAIL;

	if (dh == NULL) {
		KAEerr(KAE_F_HPRE_DH_KEYGEN, KAE_R_DH_INVALID_PARAMETER);
		US_ERR("DH_BUILTIN_KEYGEN KAE_R_DH_INVALID_PARAMETER");
		return HPRE_DH_FAIL;
	}

	hpre_dh_soft_get_pg(dh, &p, &g, &q);
	if (p == NULL || g == NULL) {
		KAEerr(KAE_F_HPRE_DH_KEYGEN, KAE_R_DH_INVALID_PARAMETER);
		US_ERR("invalid g or p.");
		return HPRE_DH_FAIL;
	}
	// check whether it is dsa parameter.
	CHECK_AND_GOTO(q != NULL, end_soft, "q is not null, then switch to soft!");

	// check whether bits exceeds the limit.
	if (bits > OPENSSL_DH_MAX_MODULUS_BITS) {
		KAEerr(KAE_F_HPRE_DH_KEYGEN, KAE_R_DH_KEY_SIZE_TOO_LARGE);
		US_ERR("DH_BUILTIN_KEYGEN DH_KEY_SIZE_TOO_LARGE");
		return HPRE_DH_FAIL;
	}

	ret = prepare_dh_data(bits, g, dh, &eng_ctx, &priv_key);
	CHECK_AND_GOTO(ret != HPRE_DH_SUCCESS, end_soft, "prepare dh data failed!");

	// construct opdata
	ret = hpre_dh_fill_genkey_opdata(g, p, priv_key, eng_ctx);
	CHECK_AND_GOTO(ret != HPRE_DH_SUCCESS, end_soft, "fill opdata fail then switch to soft!");

	// call wd api
	ret = hpre_dh_genkey(eng_ctx);
	CHECK_AND_GOTO(ret != HPRE_DH_SUCCESS, end_soft, "hpre generate dh key failed.switch to soft!");

	// get public key from opdata
	ret = hpre_dh_get_pubkey(eng_ctx, &pub_key);
	CHECK_AND_GOTO(ret != HPRE_DH_SUCCESS, end_soft, "get pub key failed.switch to soft!");

	// set public key and secret key to the DH.
	hpre_dh_soft_set_pkeys(dh, pub_key, priv_key);

end_soft:
	if (pub_key != DH_get0_pub_key(dh))
		BN_free(pub_key);
	if (priv_key != DH_get0_priv_key(dh))
		BN_free(priv_key);
	hpre_dh_free_eng_ctx(eng_ctx);

	if (ret != HPRE_DH_SUCCESS)
		return hpre_dh_soft_generate_key(dh);

	US_DEBUG("hpre dh generate key success!");
	return HPRE_DH_SUCCESS;
}

static int hpre_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
	int bits = DH_bits(dh);
	const BIGNUM *p = NULL;
	const BIGNUM *g = NULL;
	const BIGNUM *q = NULL;
	BIGNUM *priv_key = NULL;
	hpre_dh_engine_ctx_t *eng_ctx = NULL;
	int ret = HPRE_DH_FAIL;
	int ret_size = 0;

	if (dh == NULL || key == NULL || pub_key == NULL || DH_get0_priv_key(dh) == NULL) {
		KAEerr(KAE_F_HPRE_DH_KEYCOMP, KAE_R_DH_INVALID_PARAMETER);
		US_ERR("KAE_F_HPRE_DH_KEYCOMP KAE_R_DH_INVALID_PARAMETER");
		return HPRE_DH_FAIL;
	}

	hpre_dh_soft_get_pg(dh, &p, &g, &q);
	if (p == NULL || g == NULL) {
		KAEerr(KAE_F_HPRE_DH_KEYCOMP, KAE_R_DH_INVALID_PARAMETER);
		US_ERR("invalid g or p.");
		return HPRE_DH_FAIL;
	}
	// check whether it is dsa parameter.
	CHECK_AND_GOTO(q != NULL, end_soft, "q is not null, then switch to soft!");

	// check whether bits exceeds the limit.
	if (bits > OPENSSL_DH_MAX_MODULUS_BITS) {
		KAEerr(KAE_F_HPRE_DH_KEYCOMP, KAE_R_DH_KEY_SIZE_TOO_LARGE);
		US_ERR("DH_BUILTIN_KEYGEN DH_KEY_SIZE_TOO_LARGE");
		return HPRE_DH_FAIL;
	}

	ret = prepare_dh_data(bits, g, dh, &eng_ctx, &priv_key);
	CHECK_AND_GOTO(ret != HPRE_DH_SUCCESS, end_soft, "prepare dh data failed!");

	// construct opdata
	ret = hpre_dh_fill_compkey_opdata(g, p, priv_key, pub_key, eng_ctx);
	CHECK_AND_GOTO(ret != HPRE_DH_SUCCESS, end_soft, "fill opdata fail then switch to soft!");

	// call wd api to generate shared secret key.
	ret = hpre_dh_compkey(eng_ctx);
	CHECK_AND_GOTO(ret != HPRE_DH_SUCCESS, end_soft, "hpre compute dh key failed.switch to soft!");

	ret_size = hpre_dh_get_output_chars(eng_ctx, key);

end_soft:

	hpre_dh_free_eng_ctx(eng_ctx);

	if (ret != HPRE_DH_SUCCESS)
		return hpre_dh_soft_compute_key(key, pub_key, dh);

	US_DEBUG("hpre dh compute key success!");
	return ret_size;
}

static int hpre_db_bn_mod_exp(
		const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
	return BN_mod_exp_mont(r, a, p, m, ctx, m_ctx);
}

static int check_dh_bit_useful(const int bit)
{
	switch (bit) {
	case DH768BITS:
	case DH1024BITS:
	case DH1536BITS:
	case DH2048BITS:
	case DH3072BITS:
	case DH4096BITS:
		return 1;
	default:
		break;
	}
	return 0;
}

static int prepare_dh_data(const int bits, const BIGNUM *g, DH *dh, hpre_dh_engine_ctx_t **eng_ctx, BIGNUM **priv_key)
{
	int ret = HPRE_DH_FAIL;
	bool is_g2 = BN_is_word(g, GENERATOR_2);
	// check whether the bits is supported by hpre.
	CHECK_AND_GOTO(!check_dh_bit_useful(bits), err, "op sizes not supported by hpre engine then back to soft!");

	// get ctx
	*eng_ctx = hpre_dh_get_eng_ctx(dh, bits, is_g2);
	CHECK_AND_GOTO(*eng_ctx == NULL, err, "get eng ctx fail then switch to soft!");

	// get private key
	ret = hpre_dh_soft_try_get_priv_key(dh, priv_key);
	CHECK_AND_GOTO(ret != OPENSSL_SUCCESS, err, "get priv key fail then switch to soft!");

	return HPRE_DH_SUCCESS;
err:
	return HPRE_DH_FAIL;
}
