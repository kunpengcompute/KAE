/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description: This file provides the implementation for an engine check thread
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

#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "../alg/ciphers/sec_ciphers_wd.h"
#include "../alg/ciphers/sec_ciphers_aead.h"
#include "../alg/digests/sec_digests_wd.h"
#include "../alg/pkey/hpre_wd.h"
#include "../alg/pkey/hpre_sm2.h"
#include "../alg/dh/hpre_dh_wd.h"
#include "engine_check.h"
#include "../../utils/engine_utils.h"
#include "../../utils/engine_log.h"

KAE_CHECK_Q_TASK g_kae_check_q_task = {
	.init_flag = NOT_INIT,
};
static pthread_once_t g_check_thread_is_initialized = PTHREAD_ONCE_INIT;

static struct kae_spinlock g_kae_async_spinmtx = {
	.lock = 0,
};

static unsigned int    g_kae_async_enabled = 1;

void kae_enable_async(void)
{
	KAE_SPIN_LOCK(g_kae_async_spinmtx);
	g_kae_async_enabled = 1;
	KAE_SPIN_UNLOCK(g_kae_async_spinmtx);
}

void kae_disable_async(void)
{
	KAE_SPIN_LOCK(g_kae_async_spinmtx);
	g_kae_async_enabled = 0;
	KAE_SPIN_UNLOCK(g_kae_async_spinmtx);
}

int kae_is_async_enabled(void)
{
	return g_kae_async_enabled;
}

static void kae_set_exit_flag(void)
{
	g_kae_check_q_task.exit_flag = 1;
}

static void *kae_checking_q_loop_fn(void *args)
{
	(void)args;

	while (1) {
		if (g_kae_check_q_task.exit_flag)
			break;

		usleep(KAE_QUEUE_CHECKING_INTERVAL);
		if (g_kae_check_q_task.exit_flag)
			break; // double check

		kae_queue_pool_check_and_release(wd_ciphers_get_qnode_pool(), wd_ciphers_free_engine_ctx);
		kae_queue_pool_check_and_release(wd_aead_get_qnode_pool(), wd_aead_free_engine_ctx);
		kae_queue_pool_check_and_release(wd_digests_get_qnode_pool(), wd_digests_free_engine_ctx);
		kae_queue_pool_check_and_release(wd_hpre_get_qnode_pool(), NULL);
#ifndef KAE_GMSSL
		kae_queue_pool_check_and_release(wd_hpre_sm2_get_qnode_pool(), NULL);
#endif
		kae_queue_pool_check_and_release(wd_hpre_dh_get_qnode_pool(), NULL);
	}
	US_INFO("check thread exit normally.");

	return NULL;  // lint !e527
}

static void kae_checking_q_thread_destroy(void)
{
	kae_set_exit_flag();
	pthread_join(g_kae_check_q_task.thread_id, NULL);

	(void)wd_digests_uninit_qnode_pool();
	(void)wd_ciphers_uninit_qnode_pool();
	(void)wd_hpre_dh_uninit_qnode_pool();
	(void)wd_hpre_uninit_qnode_pool();
#ifndef KAE_GMSSL
	(void)wd_sm2_uninit_qnode_pool();
#endif
	(void)wd_aead_uninit_qnode_pool();
}

static void kae_check_thread_init(void)
{
	pthread_t thread_id;

	if (g_kae_check_q_task.init_flag == INITED)
		return;

	if (!kae_create_thread_joinable(&thread_id, NULL, kae_checking_q_loop_fn, NULL)) {
		US_ERR("fail to create check thread");
		return;
	}

	g_kae_check_q_task.thread_id = thread_id;
	g_kae_check_q_task.init_flag = INITED;

	(void)OPENSSL_atexit(kae_checking_q_thread_destroy);
}

int kae_checking_q_thread_init(void)
{
	US_DEBUG("check queue thread init begin");

	if (g_kae_check_q_task.init_flag == INITED)
		return 1;

	pthread_once(&g_check_thread_is_initialized, kae_check_thread_init);

	if (g_kae_check_q_task.init_flag != INITED) {
		US_ERR("check thread init failed");
		g_check_thread_is_initialized = PTHREAD_ONCE_INIT;
		return 0;
	}

	return 1;
}

void kae_check_thread_reset(void)
{
	kae_memset(&g_kae_check_q_task, 0, sizeof(KAE_CHECK_Q_TASK));
	g_check_thread_is_initialized = PTHREAD_ONCE_INIT;
}
