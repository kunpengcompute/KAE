/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the implementation for switch to soft dh.
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

#include "hpre_dh_soft.h"
#include "../../utils/engine_types.h"
#include "../../../utils/engine_log.h"

static int generate_new_priv_key(const DH *dh, BIGNUM *new_priv_key);

void hpre_dh_soft_get_pg(const DH *dh, const BIGNUM **p, const BIGNUM **g, const BIGNUM **q)
{
	DH_get0_pqg(dh, p, q, g);
}

int hpre_dh_soft_try_get_priv_key(const DH *dh, BIGNUM **priv_key)
{
	int generate_new_key = 0;
	BIGNUM *new_priv_key = NULL;

	// get the private key from dh.
	*priv_key = (BIGNUM *)DH_get0_priv_key(dh);
	if (*priv_key == NULL) {
		new_priv_key = BN_secure_new();
		if (new_priv_key == NULL)
			goto err;
		generate_new_key = 1;
	}

	if (generate_new_key) {
		// generate random private key，referencing function 'generate_key' in openssl
		if (generate_new_priv_key(dh, new_priv_key) == OPENSSL_FAIL)
			goto err;
		else
			*priv_key = new_priv_key;
	}
	return OPENSSL_SUCCESS;

err:
	BN_free(new_priv_key);
	return OPENSSL_FAIL;
}

void hpre_dh_soft_set_pkeys(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	const BIGNUM *old_pub = DH_get0_pub_key(dh);
	const BIGNUM *old_priv = DH_get0_priv_key(dh);

	if (old_pub != pub_key && old_priv != priv_key)
		DH_set0_key(dh, pub_key, priv_key);
	else if (old_pub != pub_key)
		DH_set0_key(dh, pub_key, NULL);
	else if (old_priv != priv_key)
		DH_set0_key(dh, NULL, priv_key);
}

int hpre_dh_soft_generate_key(DH *dh)
{
	int (*dh_soft_generate_key)(DH *dh);

	dh_soft_generate_key = DH_meth_get_generate_key(DH_OpenSSL());
	int ret = dh_soft_generate_key(dh);

	if (ret < 0) {
		US_ERR("dh soft key generate fail: %d", ret);
		return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

int hpre_dh_soft_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
	int (*dh_soft_compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh);

	dh_soft_compute_key = DH_meth_get_compute_key(DH_OpenSSL());
	int ret = dh_soft_compute_key(key, pub_key, dh);

	if (ret < 0) {
		US_ERR("dh soft key compute fail: %d", ret);
		return OPENSSL_FAIL;
	}

	return ret;
}

static int generate_new_priv_key(const DH *dh, BIGNUM *new_priv_key)
{
	const BIGNUM *q = DH_get0_q(dh);
	int l;

	if (q) {
		do {
			if (!BN_priv_rand_range(new_priv_key, q))
				return OPENSSL_FAIL;
		} while (BN_is_zero(new_priv_key) || BN_is_one(new_priv_key));
	} else {
		l = DH_get_length(dh) ? DH_get_length(dh) : BN_num_bits(DH_get0_p(dh)) - 1;
		if (!BN_priv_rand(new_priv_key, l, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
			return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}
