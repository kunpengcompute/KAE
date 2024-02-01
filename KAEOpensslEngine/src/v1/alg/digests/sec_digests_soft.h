/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides the digest interface for soft digests
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

#ifndef SEC_DIGESTS_SOFT_H
#define SEC_DIGESTS_SOFT_H

#include "sec_digests.h"

int sec_digests_soft_init(sec_digest_priv_t *ctx, uint32_t e_nid);
int sec_digests_soft_update(EVP_MD_CTX *ctx, const void *data, size_t data_len, uint32_t e_nid);
int sec_digests_soft_final(EVP_MD_CTX *ctx, unsigned char *digest, uint32_t e_nid);
int sec_digests_soft_work(sec_digest_priv_t *md_ctx, int len, unsigned char *digest);
void sec_digests_soft_cleanup(sec_digest_priv_t *md_ctx);
int sec_digests_soft_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);

#endif
