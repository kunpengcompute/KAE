/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
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

/*
 * The Apache-2.0 notice above applies only to original modifications
 * by Huawei Technologies Co., Ltd. This file has been adapted for KAE.
 * Upstream portions retain their original copyright notices and
 * license terms.
 * The upstream Apache-2.0 notice is retained below; see LICENSE in the
 * KAEOpensslEngine directory for the full license text.
 */

/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef SM4_ARMv8_H
#define SM4_ARMv8_H

#include "arm_arch.h"

#define SM4_KEY_SCHEDULE	32

# if defined(OPENSSL_CPUID_OBJ)
#  if (defined(__arm__) || defined(__arm) || defined(__aarch64__))
#   include "arm_arch.h"
#   if __ARM_MAX_ARCH__>=7
#    if defined(VPSM4_EX_ASM)
#     define VPSM4_EX_CAPABLE (OPENSSL_armcap_P & ARMV8_AES)
#    endif
#     define HWSM4_CAPABLE (OPENSSL_armcap_P & ARMV8_SM4)
#   endif
#  endif
# endif /* OPENSSL_CPUID_OBJ */

typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

int sm4_v8_set_encrypt_key(const unsigned char *userKey, SM4_KEY *key);
int sm4_v8_set_decrypt_key(const unsigned char *userKey, SM4_KEY *key);
void sm4_v8_encrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void sm4_v8_decrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void sm4_v8_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       unsigned char *ivec, const int enc);
void sm4_v8_ecb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       const int enc);
void sm4_v8_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const void *key,
                                const unsigned char ivec[16]);
/* xts mode in GB/T 17964-2021 */
void sm4_v8_xts_encrypt_gb(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);
void sm4_v8_xts_decrypt_gb(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);
/* xts mode in IEEE Std 1619-2007 */
void sm4_v8_xts_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);
void sm4_v8_xts_decrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);


#endif