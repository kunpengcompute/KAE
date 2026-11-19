/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description: This file provides the inplemenation for a KAE engine fork
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

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "async_fork.h"
#include "async_check.h"
#include "async_poll.h"
#include "../algorithm/pkey/hpre_rsa.h"
#include "../algorithm/pkey/hpre_sm2.h"
#include "../algorithm/pkey/hpre_dh.h"
#include "../algorithm/cipher/sec_ciphers.h"
#include "../algorithm/digest/sec_digests.h"
#include "../../common/kae_log.h"
#include "../algorithm/pkey/hpre_rsa_wd.h"
#include "../algorithm/pkey/hpre_dh_wd.h"
#include "../algorithm/cipher/sec_ciphers_wd.h"
#include "../algorithm/cipher/sec_ciphers_aead.h"
#include "../algorithm/digest/sec_digests_wd.h"

void engine_init_child_at_fork_handler_v1(void)
{
    US_DEBUG("call engine_init_child_at_fork_handler_v1");

    if (g_sec_digests_qnode_pool)
        g_sec_digests_qnode_pool->pool_use_num = 0;
    if (g_sec_ciphers_qnode_pool)
        g_sec_ciphers_qnode_pool->pool_use_num = 0;
    if (g_sec_aeads_qnode_pool)
        g_sec_aeads_qnode_pool->pool_use_num = 0;
    if (g_hpre_rsa_qnode_pool)
        g_hpre_rsa_qnode_pool->pool_use_num = 0;
    if (g_hpre_dh_qnode_pool)
        g_hpre_dh_qnode_pool->pool_use_num = 0;
    if (g_hpre_sm2_qnode_pool)
        g_hpre_sm2_qnode_pool->pool_use_num = 0;

    (void)hpre_module_rsa_init();
    (void)hpre_module_dh_init();
    (void)sec_cipher_module_init();  // cipher + aead
    (void)sec_digest_module_init();
    (void)hpre_module_sm2_init();

    kae_check_thread_reset();
    if (!kae_checking_q_thread_init())
        US_WARN("kae queue check thread init failed");
    async_module_init_v1();
}

void engine_do_before_fork_handler(void)
{}

void engine_init_parent_at_fork_handler(void)
{}
