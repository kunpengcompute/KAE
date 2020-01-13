/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the digest interface for KAE digests using wd interface
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

#ifndef SEC_DIGESTS_WD_H
#define SEC_DIGESTS_WD_H

#include "sec_digests.h"


digest_engine_ctx_t* wd_digests_get_engine_ctx(sec_digest_priv_t* md_ctx);
void wd_digests_put_engine_ctx(digest_engine_ctx_t* e_digest_ctx);
int wd_digests_doimpl(digest_engine_ctx_t *e_digest_ctx);

inline void wd_digests_set_input_data(digest_engine_ctx_t *e_digest_ctx);
inline void wd_digests_get_output_data(digest_engine_ctx_t *e_digest_ctx);
inline uint32_t wd_digests_get_do_digest_len(digest_engine_ctx_t *e_digest_ctx, int leftlen);

KAE_QUEUE_POOL_HEAD_S* wd_digests_get_qnode_pool(void);
int wd_digests_init_qnode_pool(void);
void wd_digests_free_engine_ctx(void* digest_ctx);

#endif

