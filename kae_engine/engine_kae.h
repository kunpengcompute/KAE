/*
 * Copyright (c) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the interface for an OpenSSL KAE engine
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

#ifndef ENGINE_KAE_H
#define ENGINE_KAE_H

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "engine_opensslerr.h"
#include "engine_log.h"

/* Engine id */
extern const char *g_engine_kae_id ;

int kae_get_device(const char *dev);

extern void sec_ciphers_set_enabled(int nid, int enabled);
extern void sec_digests_set_enabled(int nid, int enabled);
extern void sec_ciphers_free_ciphers(void);
extern int cipher_module_init(void);
extern int sec_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);

extern void sec_digests_free_methods(void);
extern int digest_module_init(void);
extern int sec_engine_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);

extern RSA_METHOD *hpre_get_rsa_methods(void);
extern int hpre_module_init(void);
extern void hpre_destroy(void);

extern const DH_METHOD *hpre_get_dh_methods(void);
extern int hpre_module_dh_init(void);
extern void hpre_dh_destroy(void);

extern int hpre_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
			   const int **pnids, int nid);
extern int wd_get_nosva_dev_num(const char *algorithm);

#endif  // !ENGINE_KAE_H

