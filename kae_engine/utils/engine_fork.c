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

#include "engine_fork.h"
#include "engine_check.h"
#include "async_poll.h"
#include "hpre_rsa.h"
#include "hpre_dh.h"
#include "sec_ciphers.h"
#include "sec_digests.h"
#include "engine_log.h"
#include "hpre_wd.h"
#include "hpre_dh_wd.h"
#include "sec_ciphers_wd.h"
#include "sec_digests_wd.h"

void engine_init_child_at_fork_handler(void)
{
    US_DEBUG("call engine_init_child_at_fork_handler");

    if (g_sec_digests_qnode_pool) {
        g_sec_digests_qnode_pool->pool_use_num = 0;
    }
    if (g_sec_ciphers_qnode_pool) {
        g_sec_ciphers_qnode_pool->pool_use_num = 0;
    }
    if (g_hpre_rsa_qnode_pool) {
        g_hpre_rsa_qnode_pool->pool_use_num = 0;
    }
    if (g_hpre_dh_qnode_pool) {
        g_hpre_dh_qnode_pool->pool_use_num = 0;
    }
    
    (void)hpre_module_init();
    (void)hpre_module_dh_init();
    (void)cipher_module_init();
    (void)digest_module_init();
    
    kae_check_thread_reset();
    if (!kae_checking_q_thread_init()) {
        US_WARN("kae queue check thread init failed");
    }
    async_module_init();

    return;
}

void engine_do_before_fork_handler(void)
{
    kae_check_thread_reset();
    (void)wd_digests_uninit_qnode_pool();
    (void)wd_ciphers_uninit_qnode_pool();
    (void)wd_hpre_dh_uninit_qnode_pool();
    (void)wd_hpre_uninit_qnode_pool();
    return;
}

void engine_init_parent_at_fork_handler(void)
{
    return;
}
