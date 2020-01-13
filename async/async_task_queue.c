/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the implemenation for the KAE engine async task queue
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
#include <openssl/err.h>

#include "async_task_queue.h"
#include "engine_kae.h"
#include "async_event.h"
#include "engine_utils.h"

#define ASYNC_POLL_TASK_NUM 4096

async_poll_queue_t g_async_poll_queue = {
    .init_mark = 0,
};

async_recv_t g_async_recv_func[MAX_ALG_SIZE];

int async_register_poll_fn(int type, async_recv_t func)
{
    if (type < 0 || type >= MAX_ALG_SIZE) {
        return -1;
    }

    g_async_recv_func[type] = func;
    return 0;
}

int async_poll_task_init()
{
    kae_memset(&g_async_poll_queue, 0, sizeof(g_async_poll_queue));

    g_async_poll_queue.async_poll_task_queue_head = 
        (async_poll_task*)malloc(sizeof(async_poll_task) * ASYNC_POLL_TASK_NUM);
    if (g_async_poll_queue.async_poll_task_queue_head == NULL) {
        US_ERR("no enough memory for task queue, errno=%d", errno);  //lint !e666
        return 0;
    }
    kae_memset(g_async_poll_queue.async_poll_task_queue_head, 0,
               sizeof(async_poll_task) * ASYNC_POLL_TASK_NUM);
    g_async_poll_queue.left_task = ASYNC_POLL_TASK_NUM;
    
    int ret = sem_init(&g_async_poll_queue.empty_sem, 0, (unsigned int)g_async_poll_queue.left_task);
    if (ret != 0) {
        US_ERR("fail to init empty semaphore, errno=%d", errno); //lint !e666
        goto _err;
    }

    if (sem_init(&g_async_poll_queue.full_sem, 0, 0) != 0) {
        US_ERR("fail to init full semaphore, errno=%d", errno);  //lint !e666
        goto _err;
    }

    US_DEBUG("async poll task init done.");
    return 1;
_err:
    async_poll_task_free();
    return 0;
}

async_poll_task* async_get_queue_task()
{
    async_poll_task *task_queue;
    async_poll_task *cur_task;
    int tail_pos;

    if (pthread_mutex_lock(&g_async_poll_queue.async_task_mutex) != 0) {
        US_ERR("lock queue mutex failed, errno:%d", errno); //lint !e666
        return NULL;
    }

    tail_pos = g_async_poll_queue.tail_pos;
    task_queue = g_async_poll_queue.async_poll_task_queue_head;
    cur_task = &task_queue[tail_pos];

    g_async_poll_queue.tail_pos = (tail_pos + 1) % ASYNC_POLL_TASK_NUM;
    g_async_poll_queue.cur_task--;
    g_async_poll_queue.left_task++;

    if (pthread_mutex_unlock(&g_async_poll_queue.async_task_mutex) != 0) {
        US_ERR("unlock queue mutex failed, errno:%d", errno); //lint !e666
    }

    if (sem_post(&g_async_poll_queue.empty_sem) != 0) {
        US_ERR("post empty sem failed, errno:%d", errno); //lint !e666
    }

    US_DEBUG("get task end");
    return cur_task;
}

static int async_add_queue_task(void *eng_ctx, op_done_t *op_done, enum task_type type)
{
    async_poll_task *task_queue;
    async_poll_task *task;
    int head_pos;

    if (sem_wait(&g_async_poll_queue.empty_sem) != 0) {
        US_ERR("wait empty sem failed, errno:%d", errno); //lint !e666
        return 0;
    }

    if (pthread_mutex_lock(&g_async_poll_queue.async_task_mutex) != 0) {
        US_ERR("lock queue mutex failed, errno:%d", errno); //lint !e666
    }

    head_pos = g_async_poll_queue.head_pos;
    task_queue = g_async_poll_queue.async_poll_task_queue_head;
    task = &task_queue[head_pos];
    task->eng_ctx = eng_ctx;
    task->op_done = op_done;
    task->type = type;

    head_pos = (head_pos + 1) % ASYNC_POLL_TASK_NUM;
    g_async_poll_queue.head_pos = head_pos;
    g_async_poll_queue.cur_task++;
    g_async_poll_queue.left_task--;

    if (pthread_mutex_unlock(&g_async_poll_queue.async_task_mutex) != 0) {
        US_ERR("unlock queue mutex failed, errno:%d", errno); //lint !e666
    }

    if (sem_post(&g_async_poll_queue.full_sem) != 0) {
        US_ERR("post full sem failed, errno:%d", errno); //lint !e666
    }

    US_DEBUG("add task success");
    return 1;
}

static void async_poll_queue_free()
{
    async_poll_task *task = g_async_poll_queue.async_poll_task_queue_head;
    if (task != NULL) {
        OPENSSL_free(task);
    }
    g_async_poll_queue.async_poll_task_queue_head = NULL;
}

int async_add_poll_task(void *eng_ctx, op_done_t *op_done, enum task_type type)
{
    US_DEBUG("start to add task to poll queue");
    return async_add_queue_task(eng_ctx, op_done, type);
}

void async_poll_task_free()
{
    int error;
    error = pthread_mutex_lock(&g_async_poll_queue.async_task_mutex);
    if (error != 0) {
        US_ERR("lock mutex failed, errno=%d", errno); //lint !e666
        return ;
    }
    async_poll_queue_free();
    pthread_mutex_unlock(&g_async_poll_queue.async_task_mutex);

    sem_destroy(&g_async_poll_queue.empty_sem);
    sem_destroy(&g_async_poll_queue.full_sem);
    pthread_mutex_destroy(&g_async_poll_queue.async_task_mutex);

    US_DEBUG("async task free succ");
    return;
}
/*lint -e(10)*/

