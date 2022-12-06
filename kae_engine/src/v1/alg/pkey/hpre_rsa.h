/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the implementation for KAE rsa using wd interface
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

#ifndef HPRE_RSA_H
#define HPRE_RSA_H

#include <semaphore.h>
#include <asm/types.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

#include "../../utils/engine_utils.h"
#include "../../utils/engine_opensslerr.h"

#define RSA_MIN_MODULUS_BITS    512

#define RSA1024BITS     1024
#define RSA2048BITS     2048
#define RSA3072BITS     3072
#define RSA4096BITS     4096

#define HPRE_CONT        (-1)
#define HPRE_CRYPTO_SUCC  1
#define HPRE_CRYPTO_FAIL  0
#define HPRE_CRYPTO_SOFT (-1)


enum {
	INVALID = 0,
	PUB_ENC,
	PUB_DEC,
	PRI_ENC,
	PRI_DEC,
	MAX_CODE,
};

struct bignum_st {
	BN_ULONG *d;
	int top;
	int dmax;
	int neg;
	int flags;
};

RSA_METHOD *hpre_get_rsa_methods(void);

int hpre_module_init(void);

void hpre_destroy(void);

EVP_PKEY_METHOD *get_rsa_pkey_meth(void);

#endif

