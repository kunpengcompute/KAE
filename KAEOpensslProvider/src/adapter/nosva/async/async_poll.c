/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description: This file provides the implementation for the KAE engine thread polling
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <openssl/err.h>

#include "async_poll.h"
#include "async_event.h"
#include "async_task_queue.h"
#include "async_check.h"
#include "../../common/kae_log.h"
#include "../../common/kae_utils.h"

#define ASYNC_POLL_TASK_NUM 1024

static void async_polling_thread_destroy(void);
static pid_t polling_pid;

static void *async_poll_process_func(void *args)
{
    (void)args;
    int ret;
    async_poll_task *task;
    void *eng_ctx;
    int type;
    op_done_t *op_done;

    while (1) {
        if (sem_wait(&g_async_poll_queue.full_sem) != 0) {
            if (errno == EINTR) {
                /* sem_wait is interrupted by interrupt, continue */
                continue;
            }
            US_ERR("wait async full_sem failed, errno:%d", errno);  // lint !e666
        }

        if (__atomic_load_n(&g_async_poll_queue.shutdown, __ATOMIC_ACQUIRE))
            break;
        task = async_get_queue_task_v1();
        if (task == NULL) {
            usleep(1);
            continue;
        }

        eng_ctx = task->eng_ctx;
        op_done = task->op_done;
        type = task->type;

        US_DEBUG("async poll thread start to recv result.");

        ret = g_async_recv_func[type](eng_ctx);

        op_done->verifyRst = ret;

        op_done->flag = 1;
        if (op_done->job)
            async_wake_job_v1(op_done->job, ASYNC_STATUS_OK);

        US_DEBUG("process task done.");
    }

    US_DEBUG("polling thread exit.");
    return NULL;
}

void async_polling_thread_reset(void)
{
    g_async_poll_queue.init_mark = 0;
    kae_memset(&g_async_poll_queue, 0, sizeof(g_async_poll_queue));
}

int async_polling_thread_init(void)
{
    pthread_t thread_id;

    US_DEBUG("init polling thread.");
    if (g_async_poll_queue.init_mark == INITED)
        return 1;

    kae_memset(&g_async_poll_queue, 0, sizeof(async_poll_queue_t));

    if (!async_poll_task_init_v1()) {
        US_ERR("init poll task queue failed.");
        return 0;
    }

    if (pthread_create(&thread_id, NULL, async_poll_process_func, NULL) != 0) {
        US_DEBUG("fail to create polling thread");
        goto _err;
    }

    g_async_poll_queue.thread_id = thread_id;
    g_async_poll_queue.init_mark = INITED;
    polling_pid = getpid();
    /* The provider teardown joins this thread before the module can unload. */

    return 1;

_err:
    async_poll_task_free_v1();
    return 0;
}

static void async_polling_thread_destroy(void)
{
    if (g_async_poll_queue.init_mark != INITED || polling_pid != getpid())
        return;

    __atomic_store_n(&g_async_poll_queue.shutdown, 1, __ATOMIC_RELEASE);
    sem_post(&g_async_poll_queue.full_sem);
    pthread_join(g_async_poll_queue.thread_id, NULL);
    async_poll_task_free_v1();
    g_async_poll_queue.exit_mark = 1;
    g_async_poll_queue.init_mark = 0;
}

void async_module_uninit_v1(void)
{
    async_polling_thread_destroy();
}

void async_module_init_v1(void)
{
    if (kae_is_async_enabled()) {
        if (g_async_poll_queue.init_mark == INITED && polling_pid == getpid())
            return;
        /* A fork child has no polling thread to join. */
        OPENSSL_free(g_async_poll_queue.async_poll_task_queue_head);
        async_polling_thread_reset();
        if (!async_polling_thread_init())
            kae_disable_async();
    }
}
/*lint -e(10)*/
