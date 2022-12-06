/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description: This file provides interface for the KAE engine async task queue
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

#ifndef ASYNC_TASK_QUEUE_H
#define ASYNC_TASK_QUEUE_H
#include <pthread.h>
#include "async_callback.h"
#include <uadk/v1/wd.h>
#include "../../uadk_async.h"

#include <semaphore.h>

#define MAX_ALG_SIZE 6

typedef int (*async_recv_t)(void *engine_ctx);

struct async_wd_polling_arg {
	enum task_type type;
	void *eng_ctx;
	op_done_t *op_done;
};
typedef struct async_wd_polling_arg async_poll_task;

typedef struct async_poll_queue_t {
	async_poll_task *async_poll_task_queue_head;
	int head_pos;
	int tail_pos;
	int cur_task;
	int left_task;
	int shutdown;
	sem_t           empty_sem;
	sem_t           full_sem;
	pthread_mutex_t async_task_mutex;
	pthread_t       thread_id;
	int init_mark;
	int exit_mark;
} async_poll_queue_t;

extern async_poll_queue_t g_async_poll_queue;
extern async_recv_t g_async_recv_func[MAX_ALG_SIZE];

int async_register_poll_fn_v1(int type, async_recv_t async_recv);
int async_poll_task_init_v1(void);
async_poll_task *async_get_queue_task_v1(void);

int async_add_poll_task_v1(void *ctx, op_done_t *op_done, enum task_type type);
void async_poll_task_free_v1(void);

#endif
