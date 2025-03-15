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


#ifndef HPRE_DH_SOFT_H
#define HPRE_DH_SOFT_H

#include <openssl/dh.h>

/*
 * get p, g, q in dh.
 */
void hpre_dh_soft_get_pg(const DH *dh, const BIGNUM **p, const BIGNUM **g, const BIGNUM **q);

/*
 * get private key in dh, if null, then generate a random one.
 */
int hpre_dh_soft_try_get_priv_key(const DH *dh, BIGNUM **priv_key);

/*
 * put private key and public key in the dh.
 */
void hpre_dh_soft_set_pkeys(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);

/*
 * call openssl API to generate public key .
 */
int hpre_dh_soft_generate_key(DH *dh);

/*
 * call openssl API to generate secret key .
 */
int hpre_dh_soft_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);

#endif
