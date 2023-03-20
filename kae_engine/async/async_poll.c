/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the implemenation for the KAE engine thread polling
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
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#include "engine_check.h"
#include "async_poll.h"
#include "async_event.h"
#include "async_task_queue.h"
#include "engine_utils.h"

#include <openssl/err.h>

#define ASYNC_POLL_TASK_NUM 1024

static void async_polling_thread_destroy();

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
            US_ERR("wait async full_sem failed, errno:%d", errno); //lint !e666
        }

        task = async_get_queue_task();
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
        if (op_done->job) {
            async_wake_job(op_done->job, ASYNC_STATUS_OK);
        }
        
        US_DEBUG("process task done.");
    }

    US_DEBUG("polling thread exit.");
    return NULL;
}

void async_polling_thread_reset()
{
    g_async_poll_queue.init_mark = 0;
    kae_memset(&g_async_poll_queue, 0, sizeof(g_async_poll_queue));
}

int async_polling_thread_init()
{
    US_DEBUG("init polling thread.");
    if (g_async_poll_queue.init_mark == INITED) return 1;

    kae_memset(&g_async_poll_queue, 0, sizeof(async_poll_queue_t));

    if (pthread_mutex_init(&(g_async_poll_queue.async_task_mutex), NULL) < 0) {
        US_ERR("init queue mutex failed, errno:%d", errno);  //lint !e666
    }

    if (!async_poll_task_init()) {
        US_ERR("init poll task queue failed.");
        return 0;
    }

    pthread_t thread_id;
    if (kae_create_thread(&thread_id, NULL, async_poll_process_func, NULL) == 0) {
        US_DEBUG("fail to create polling thread");
        goto _err;
    }

    g_async_poll_queue.thread_id = thread_id;
    g_async_poll_queue.init_mark = INITED;
    (void)OPENSSL_atexit(async_polling_thread_destroy);

    return 1;

_err:
    async_poll_task_free();
    return 0;
}

static void async_polling_thread_destroy()
{
    if (g_async_poll_queue.exit_mark == 1)  return;

    async_poll_task_free();

    g_async_poll_queue.exit_mark = 1;

    return;
}

void async_module_init()
{
    if (kae_is_async_enabled()) {
        async_poll_task_free();

        async_polling_thread_reset();
        if (!async_polling_thread_init()) {
            kae_disable_async();
        }
    }
}
/*lint -e(10)*/

