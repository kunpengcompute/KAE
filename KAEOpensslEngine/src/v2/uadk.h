/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2022 Linaro ltd.
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
#ifndef UADK_H
#define UADK_H
#include <openssl/engine.h>

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#define ENV_STRING_LEN		256
#define ENGINE_SEND_MAX_CNT	90000000
#define ENGINE_RECV_MAX_CNT	60000000

enum {
	HW_V2,
	HW_V3,
};

extern const char *engine_uadk_id;
int uadk_e_bind_ciphers(ENGINE *e);
void uadk_e_destroy_ciphers(void);
int uadk_e_bind_digest(ENGINE *e);
void uadk_e_destroy_digest(void);
int uadk_e_bind_rsa(ENGINE *e);
void uadk_e_destroy_rsa(void);
int uadk_e_bind_dh(ENGINE *e);
void uadk_e_destroy_dh(void);
int uadk_e_bind_ecc(ENGINE *e);
void uadk_e_destroy_ecc(void);
int uadk_e_is_env_enabled(const char *alg_name);
int uadk_e_set_env(const char *var_name, int numa_id);
void uadk_e_ecc_lock_init(void);
void uadk_e_rsa_lock_init(void);
void uadk_e_dh_lock_init(void);
void uadk_e_cipher_lock_init(void);
void uadk_e_digest_lock_init(void);
#endif
