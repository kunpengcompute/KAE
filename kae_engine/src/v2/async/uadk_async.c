/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2022 Linaro ltd.
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <openssl/async.h>
#include "v2/uadk.h"
#include "v2/async/uadk_async.h"

static struct async_poll_queue poll_queue;

static async_recv_t async_recv_func[ASYNC_TASK_MAX];

static void async_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
			     OSSL_ASYNC_FD readfd, void *custom)
{
	close(readfd);
}

int async_setup_async_event_notification(struct async_op *op)
{
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	void *custom;

	memset(op, 0, sizeof(struct async_op));
	op->job = ASYNC_get_current_job();
	if (op->job == NULL)
		return 1;

	waitctx = ASYNC_get_wait_ctx(op->job);
	if (waitctx == NULL)
		return 0;

	if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id,
				  &efd, &custom) == 0) {
		efd = eventfd(0, EFD_NONBLOCK);
		if (efd == -1)
			return 0;

		if (ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_uadk_id, efd,
					       custom, async_fd_cleanup) == 0) {
			async_fd_cleanup(waitctx, engine_uadk_id, efd, NULL);
			return 0;
		}
	}

	return 1;
}

int async_clear_async_event_notification(void)
{
	ASYNC_JOB *job;
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	size_t num_add_fds;
	size_t num_del_fds;
	void *custom = NULL;

	job = ASYNC_get_current_job();
	if (job == NULL)
		return 0;

	waitctx = ASYNC_get_wait_ctx(job);
	if (waitctx == NULL)
		return 0;

	if (ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &num_add_fds,
					   NULL, &num_del_fds) == 0)
		return 0;

	if (num_add_fds > 0) {
		if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id,
					  &efd, &custom) == 0)
			return 0;

		async_fd_cleanup(waitctx, engine_uadk_id, efd, NULL);

		if (ASYNC_WAIT_CTX_clear_fd(waitctx, engine_uadk_id) == 0)
			return 0;
	}

	return 1;
}

static void async_poll_task_free(void)
{
	int error;
	struct async_poll_task *task;

	error = pthread_mutex_lock(&poll_queue.async_task_mutex);
	if (error != 0)
		return;

	task = poll_queue.head;
	if (task != NULL)
		OPENSSL_free(task);

	poll_queue.head = NULL;
	pthread_mutex_unlock(&poll_queue.async_task_mutex);
	sem_destroy(&poll_queue.empty_sem);
	sem_destroy(&poll_queue.full_sem);
	pthread_mutex_destroy(&poll_queue.async_task_mutex);
}

static int async_get_poll_task(int *id)
{
	int idx = poll_queue.rid;
	int cnt = 0;

	while (!poll_queue.status[idx]) {
		idx = (idx + 1) % ASYNC_QUEUE_TASK_NUM;
		if (cnt++ == ASYNC_QUEUE_TASK_NUM)
			return 0;
	}

	*id = idx;
	poll_queue.rid = (idx + 1) % ASYNC_QUEUE_TASK_NUM;

	return 1;
}

static struct async_poll_task *async_get_queue_task(void)
{
	struct async_poll_task *cur_task = NULL;
	struct async_poll_task *task_queue;
	int idx, ret;

	if (pthread_mutex_lock(&poll_queue.async_task_mutex) != 0)
		return NULL;

	ret = async_get_poll_task(&idx);
	if (!ret)
		goto err;

	task_queue = poll_queue.head;
	cur_task = &task_queue[idx];
	poll_queue.is_recv = 0;

err:
	if (pthread_mutex_unlock(&poll_queue.async_task_mutex) != 0)
		return NULL;

	if (cur_task && cur_task->op == NULL)
		return NULL;

	return cur_task;
}

void async_free_poll_task(int id, bool is_cb)
{
	if (pthread_mutex_lock(&poll_queue.async_task_mutex) != 0)
		return;

	poll_queue.status[id] = 0;

	if (is_cb)
		poll_queue.is_recv = 1;

	if (pthread_mutex_unlock(&poll_queue.async_task_mutex) != 0)
		return;

	(void)sem_post(&poll_queue.empty_sem);
}

int async_get_free_task(int *id)
{
	struct async_poll_task *task_queue;
	struct async_poll_task *task;
	int idx, ret;
	int cnt = 0;

	if (sem_wait(&poll_queue.empty_sem) != 0)
		return 0;

	if (pthread_mutex_lock(&poll_queue.async_task_mutex) != 0)
		return 0;

	idx = poll_queue.sid;
	while (poll_queue.status[idx]) {
		idx = (idx + 1) % ASYNC_QUEUE_TASK_NUM;
		if (cnt++ == ASYNC_QUEUE_TASK_NUM) {
			ret = 0;
			goto out;
		}
	}

	*id = idx;
	poll_queue.sid = (idx + 1) % ASYNC_QUEUE_TASK_NUM;
	poll_queue.status[idx] = 1;
	task_queue = poll_queue.head;
	task = &task_queue[idx];
	task->op = NULL;
	ret = 1;

out:
	if (pthread_mutex_unlock(&poll_queue.async_task_mutex) != 0)
		return 0;

	return ret;
}

static int async_add_poll_task(void *ctx, struct async_op *op, enum task_type type, int id)
{
	struct async_poll_task *task_queue;
	struct async_poll_task *task;
	int ret;

	task_queue = poll_queue.head;
	task = &task_queue[id];
	task->ctx = ctx;
	task->type = type;
	task->op = op;

	ret = sem_post(&poll_queue.full_sem);
	if (ret)
		return 0;

	return 1;
}

int async_pause_job(void *ctx, struct async_op *op, enum task_type type, int id)
{
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	void *custom;
	uint64_t buf;
	int ret;

	ret = async_add_poll_task(ctx, op, type, id);
	if (ret == 0)
		return ret;

	waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)op->job);
	if (waitctx == NULL)
		return 0;

	do {
		if (ASYNC_pause_job() == 0)
			return 0;

		ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id, &efd, &custom);
		if (ret <= 0)
			continue;

		if (read(efd, &buf, sizeof(uint64_t)) == -1) {
			if (errno != EAGAIN)
				fprintf(stderr, "failed to read from fd: %d - error: %d\n",
				       efd, errno);
			/* Not resumed by the expected async_wake_job() */
		}
	} while (!op->done);

	return ret;
}

int async_wake_job(ASYNC_JOB *job)
{
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	void *custom;
	uint64_t buf = 1;
	int ret;

	waitctx = ASYNC_get_wait_ctx(job);
	if (waitctx == NULL)
		return 0;

	ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id, &efd, &custom);
	if (ret > 0) {
		if (write(efd, &buf, sizeof(uint64_t)) == -1)
			fprintf(stderr, "failed to write to fd: %d - error: %d\n", efd, errno);
	}

	return ret;
}

void async_register_poll_fn(int type, async_recv_t func)
{
	if (type < 0 || type >= ASYNC_TASK_MAX) {
		fprintf(stderr, "alg type is error, type= %d.\n", type);
		return;
	}

	async_recv_func[type] = func;
}

static void *async_poll_process_func(void *args)
{
	struct async_poll_task *task;
	struct async_op *op;
	int ret, idx;

	while (1) {
		if (sem_wait(&poll_queue.full_sem) != 0) {
			if (errno == EINTR) {
				/* sem_wait is interrupted by interrupt, continue */
				continue;
			}
		}

		task = async_get_queue_task();
		if (task == NULL) {
			(void)sem_post(&poll_queue.full_sem);
			usleep(1);
			continue;
		}

		op = task->op;
		idx = op->idx;
		ret = async_recv_func[task->type](task->ctx);
		if (!poll_queue.is_recv && op->job) {
			op->done = 1;
			op->ret = ret;
			async_wake_job(op->job);
			async_free_poll_task(idx, 0);
		}
	}

	return NULL;
}

int async_module_init(void)
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;

	memset(&poll_queue, 0, sizeof(struct async_poll_queue));

	if (pthread_mutex_init(&(poll_queue.async_task_mutex), NULL) < 0)
		return 0;

	poll_queue.head = malloc(sizeof(struct async_poll_task) * ASYNC_QUEUE_TASK_NUM);
	if (poll_queue.head == NULL)
		return 0;

	memset(poll_queue.head, 0,
	       sizeof(struct async_poll_task) * ASYNC_QUEUE_TASK_NUM);

	if (sem_init(&poll_queue.empty_sem, 0,
		     ASYNC_QUEUE_TASK_NUM) != 0)
		goto err;

	if (sem_init(&poll_queue.full_sem, 0, 0) != 0)
		goto err;

	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&thread_id, &thread_attr, async_poll_process_func, NULL))
		goto err;

	poll_queue.thread_id = thread_id;
	OPENSSL_atexit(async_poll_task_free);

	return 1;

err:
	async_poll_task_free();
	return 0;
}
