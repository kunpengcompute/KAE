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
#ifndef UADK_ADAPT_H
#define UADK_ADAPT_H
#include <openssl/engine.h>
#include <uadk/wd.h>

struct engine_cipher_info {
	int nid;
	EVP_CIPHER *cipher;
};

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

EVP_CIPHER *uadk_create_gcm_cipher_meth(int nid);
EVP_CIPHER *uadk_create_cipher_meth(int nid);
void uadk_e_destroy_aead(struct engine_cipher_info *info, int num);
void uadk_e_destroy_cipher(struct engine_cipher_info *info, int num);

int uadk_e_bind_ciphers(ENGINE *e);
void uadk_e_destroy_ciphers(void);
#endif
