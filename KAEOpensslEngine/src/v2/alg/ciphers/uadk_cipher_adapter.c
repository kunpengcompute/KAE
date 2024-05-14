/*
 * Copyright 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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
 *
 */
#include "uadk_cipher_adapter.h"

#define HW_SEC_V2	2
#define HW_SEC_V3	3

static int g_platform;

static int cipher_hw_v2_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ecb,
	NID_aes_192_ecb,
	NID_aes_256_ecb,
	NID_aes_128_xts,
	NID_aes_256_xts,
	NID_sm4_cbc,
	NID_sm4_ecb,
	NID_des_ede3_cbc,
	NID_des_ede3_ecb,
	NID_aes_128_gcm,
	NID_aes_192_gcm,
	NID_aes_256_gcm
};

static int cipher_hw_v3_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_aes_128_ecb,
	NID_aes_192_ecb,
	NID_aes_256_ecb,
	NID_aes_128_xts,
	NID_aes_256_xts,
	NID_sm4_cbc,
	NID_sm4_ecb,
	NID_des_ede3_cbc,
	NID_des_ede3_ecb,
	NID_aes_128_cfb128,
	NID_aes_192_cfb128,
	NID_aes_256_cfb128,
	NID_aes_128_ofb128,
	NID_aes_192_ofb128,
	NID_aes_256_ofb128,
	NID_sm4_cfb128,
	NID_sm4_ofb128,
	NID_sm4_ctr,
	NID_aes_128_gcm,
	NID_aes_192_gcm,
	NID_aes_256_gcm
};

static struct engine_cipher_info c_info[] = {
	{NID_aes_128_cbc, NULL},
	{NID_aes_192_cbc, NULL},
	{NID_aes_256_cbc, NULL},
	{NID_aes_128_ctr, NULL},
	{NID_aes_192_ctr, NULL},
	{NID_aes_256_ctr, NULL},
	{NID_aes_128_ecb, NULL},
	{NID_aes_192_ecb, NULL},
	{NID_aes_256_ecb, NULL},
	{NID_aes_128_xts, NULL},
	{NID_aes_256_xts, NULL},
	{NID_sm4_cbc, NULL},
	{NID_sm4_ecb, NULL},
	{NID_des_ede3_cbc, NULL},
	{NID_des_ede3_ecb, NULL},
	{NID_aes_128_cfb128, NULL},
	{NID_aes_192_cfb128, NULL},
	{NID_aes_256_cfb128, NULL},
	{NID_aes_128_ofb128, NULL},
	{NID_aes_192_ofb128, NULL},
	{NID_aes_256_ofb128, NULL},
	{NID_sm4_cfb128, NULL},
	{NID_sm4_ofb128, NULL},
	{NID_sm4_ctr, NULL},
	{NID_aes_128_gcm, NULL},
	{NID_aes_192_gcm, NULL},
	{NID_aes_256_gcm, NULL}
};

static const unsigned int num_cc = ARRAY_SIZE(c_info);

static void uadk_e_create_ciphers(int index)
{
	switch (c_info[index].nid) {
	case NID_aes_128_gcm:
	case NID_aes_192_gcm:
	case NID_aes_256_gcm:
		c_info[index].cipher = uadk_create_gcm_cipher_meth(c_info[index].nid);
		break;
	case NID_aes_128_cbc:
	case NID_aes_192_cbc:
	case NID_aes_256_cbc:
	case NID_aes_128_ctr:
	case NID_aes_192_ctr:
	case NID_aes_256_ctr:
	case NID_aes_128_ecb:
	case NID_aes_192_ecb:
	case NID_aes_256_ecb:
	case NID_aes_128_xts:
	case NID_aes_256_xts:
	case NID_sm4_cbc:
	case NID_sm4_ecb:
	case NID_des_ede3_cbc:
	case NID_des_ede3_ecb:
	case NID_aes_128_cfb128:
	case NID_aes_192_cfb128:
	case NID_aes_256_cfb128:
	case NID_aes_128_ofb128:
	case NID_aes_192_ofb128:
	case NID_aes_256_ofb128:
	case NID_sm4_cfb128:
	case NID_sm4_ofb128:
	case NID_sm4_ctr:
		c_info[index].cipher = uadk_create_cipher_meth(c_info[index].nid);
		break;
	default:
		break;
	}
}

int uadk_e_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	__u32 i;

	if (!e)
		return 0;

	if ((nids == NULL) && ((cipher == NULL) || (nid < 0))) {
		if (cipher != NULL)
			*cipher = NULL;
		return 0;
	}

	if (cipher == NULL) {
		if (g_platform == HW_SEC_V2) {
			*nids = cipher_hw_v2_nids;
			return ARRAY_SIZE(cipher_hw_v2_nids);
		} else if (g_platform == HW_SEC_V3) {
			*nids = cipher_hw_v3_nids;
			return ARRAY_SIZE(cipher_hw_v3_nids);
		}

		return 0;
	}

	for (i = 0; i < num_cc; i++) {
		if (nid == c_info[i].nid) {
			if (c_info[i].cipher == NULL)
				uadk_e_create_ciphers(i);

			*cipher = c_info[i].cipher;
			return 1;
		}
	}

	*cipher = NULL;
	return 0;
}

int uadk_e_bind_ciphers(ENGINE *e)
{
	struct uacce_dev *dev;

	dev = wd_get_accel_dev("cipher");
	if (!dev) {
		fprintf(stderr, "no device available, switch to software!\n");
		return 0;
	}

	if (!strcmp(dev->api, "hisi_qm_v2"))
		g_platform = HW_SEC_V2;
	else
		g_platform = HW_SEC_V3;

	free(dev);

	return ENGINE_set_ciphers(e, uadk_e_ciphers);
}

void uadk_e_destroy_ciphers(void)
{
	uadk_e_destroy_cipher(c_info, num_cc);
	uadk_e_destroy_aead(c_info, num_cc);
}
