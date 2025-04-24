/*
 * Copyright (C) 2025. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:    This file provides the implementation for KAE engine rsa
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

#include <openssl/mem.h>

#ifndef BSSL_CUSTOM_H
#define BSSL_CUSTOM_H

#define DEFAULT_VOID (0)
#define DEFAULT_NULL (NULL)
#define DEFAULT_INT (1)

#define BN_set_flags(b, n) DEFAULT_VOID
#define RSA_set_method(rsa, meth) DEFAULT_INT
#define RSA_PKCS1_OpenSSL() DEFAULT_VOID
#define RSA_get_version(r) DEFAULT_INT

#define EVP_PKEY_meth_get0(idx) DEFAULT_NULL
#define EVP_PKEY_meth_new(id, flags) DEFAULT_NULL
#define EVP_PKEY_meth_copy(dst, src) DEFAULT_VOID

#define ERR_unload_strings(lib, src) DEFAULT_INT
#define ERR_load_strings(lib, src) DEFAULT_INT
#define ERR_PUT_error ERR_put_error

#define OPENSSL_zalloc bssl_openssl_malloc
void *bssl_openssl_malloc(size_t size);

#endif