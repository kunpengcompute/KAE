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
#include "../async/async_poll.h"
#include "../alg/pkey/hpre_rsa.h"
#include "../alg/pkey/hpre_sm2.h"
#include "../alg/dh/hpre_dh.h"
#include "../alg/ciphers/sec_ciphers.h"
#include "../alg/digests/sec_digests.h"
#include "../../utils/engine_log.h"
#include "../alg/pkey/hpre_wd.h"
#include "../alg/dh/hpre_dh_wd.h"
#include "../alg/ciphers/sec_ciphers_wd.h"
#include "../alg/ciphers/sec_ciphers_aead.h"
#include "../alg/digests/sec_digests_wd.h"

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

	(void)hpre_module_init();
	(void)hpre_module_dh_init();
	(void)cipher_module_init();//cipher + aead
	(void)digest_module_init();
#ifndef KAE_GMSSL
	(void)hpre_module_sm2_init();
#endif

	kae_check_thread_reset();
	if (!kae_checking_q_thread_init())
		US_WARN("kae queue check thread init failed");
	async_module_init_v1();
}

void engine_do_before_fork_handler(void)
{
}

void engine_init_parent_at_fork_handler(void)
{
}
