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

void engine_init_child_at_fork_handler(void)
{
    US_DEBUG("call engine_init_child_at_fork_handler");

    kae_check_thread_reset();
    if (!kae_checking_q_thread_init()) {
        US_WARN("kae queue check thread init failed");
    }
    
    (void)hpre_module_init();
    (void)hpre_module_dh_init();
    (void)cipher_module_init();
    (void)digest_module_init();
    async_module_init();

    return;
}

void engine_do_before_fork_handler(void)
{
    return;
}

void engine_init_parent_at_fork_handler(void)
{
    return;
}
