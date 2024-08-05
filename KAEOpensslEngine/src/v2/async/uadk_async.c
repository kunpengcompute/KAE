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
#include "utils/engine_log.h"

static const char *uadk_async_key = "uadk_async_key";
static struct async_poll_queue poll_queue;

static int g_uadk_e_keep_polling;

static async_recv_t async_recv_func[ASYNC_TASK_MAX];

static int uadk_e_get_async_poll_state(void)
{
	return g_uadk_e_keep_polling;
}

static void uadk_e_set_async_poll_state(int state)
{
	g_uadk_e_keep_polling = state;
}

static void async_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
			     OSSL_ASYNC_FD readfd, void *custom)
{
	close(readfd);
}

int async_setup_async_event_notification(struct async_op *op)
{
	ASYNC_WAIT_CTX *waitctx;
	void *custom = NULL;
	OSSL_ASYNC_FD efd;

	memset(op, 0, sizeof(struct async_op));
	op->job = ASYNC_get_current_job();
	if (!op->job)
		return DO_SYNC;

	waitctx = ASYNC_get_wait_ctx(op->job);
	if (!waitctx)
		return UADK_E_FAIL;

	if (!ASYNC_WAIT_CTX_get_fd(waitctx, uadk_async_key, &efd, &custom)) {
		efd = eventfd(0, EFD_NONBLOCK);
		if (efd == -1)
			return UADK_E_FAIL;

		if (!ASYNC_WAIT_CTX_set_wait_fd(waitctx, uadk_async_key, efd,
					       custom, async_fd_cleanup)) {
			async_fd_cleanup(waitctx, uadk_async_key, efd, NULL);
			return UADK_E_FAIL;
		}
	}

	return UADK_E_SUCCESS;
}

int async_clear_async_event_notification(void)
{
	size_t num_add_fds, num_del_fds;
	ASYNC_WAIT_CTX *waitctx;
	void *custom = NULL;
	OSSL_ASYNC_FD efd;
	ASYNC_JOB *job;

	job = ASYNC_get_current_job();
	if (!job)
		return UADK_E_FAIL;

	waitctx = ASYNC_get_wait_ctx(job);
	if (!waitctx)
		return UADK_E_FAIL;

	if (!ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &num_add_fds, NULL, &num_del_fds))
		return UADK_E_FAIL;

	if (num_add_fds > 0) {
		if (!ASYNC_WAIT_CTX_get_fd(waitctx, uadk_async_key, &efd, &custom))
			return UADK_E_FAIL;

		async_fd_cleanup(waitctx, uadk_async_key, efd, NULL);

		if (!ASYNC_WAIT_CTX_clear_fd(waitctx, uadk_async_key))
			return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

void async_poll_task_free(void)
{
	struct async_poll_task *task;
	int error;

	/* Disable async poll state first */
	uadk_e_set_async_poll_state(DISABLE_ASYNC_POLLING);

	error = pthread_mutex_lock(&poll_queue.async_task_mutex);
	if (error)
		return;

	task = poll_queue.head;
	if (task)
		OPENSSL_free(task);

	poll_queue.head = NULL;

	pthread_mutex_unlock(&poll_queue.async_task_mutex);
	pthread_attr_destroy(&poll_queue.thread_attr);
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
			return UADK_E_FAIL;
	}

	*id = idx;
	poll_queue.rid = (idx + 1) % ASYNC_QUEUE_TASK_NUM;

	return UADK_E_SUCCESS;
}

static struct async_poll_task *async_get_queue_task(void)
{
	struct async_poll_task *cur_task = NULL;
	struct async_poll_task *task_queue;
	int idx, ret;

	if (pthread_mutex_lock(&poll_queue.async_task_mutex))
		return NULL;

	ret = async_get_poll_task(&idx);
	if (ret == UADK_E_FAIL)
		goto err;

	task_queue = poll_queue.head;
	cur_task = &task_queue[idx];
	poll_queue.is_recv = 0;

err:
	if (pthread_mutex_unlock(&poll_queue.async_task_mutex))
		return NULL;

	if (cur_task && !cur_task->op)
		return NULL;

	return cur_task;
}

void async_free_poll_task(int id, bool is_cb)
{
	if (pthread_mutex_lock(&poll_queue.async_task_mutex))
		return;

	poll_queue.status[id] = 0;

	if (is_cb)
		poll_queue.is_recv = 1;

	if (pthread_mutex_unlock(&poll_queue.async_task_mutex))
		return;

	(void)sem_post(&poll_queue.empty_sem);
}

int async_get_free_task(int *id)
{
	struct async_poll_task *task_queue;
	struct async_poll_task *task;
	int idx, ret;
	int cnt = 0;

	if (sem_wait(&poll_queue.empty_sem))
		return UADK_E_FAIL;

	if (pthread_mutex_lock(&poll_queue.async_task_mutex))
		return UADK_E_FAIL;

	idx = poll_queue.sid;
	while (poll_queue.status[idx]) {
		idx = (idx + 1) % ASYNC_QUEUE_TASK_NUM;
		if (cnt++ == ASYNC_QUEUE_TASK_NUM) {
			ret = UADK_E_FAIL;
			goto out;
		}
	}

	*id = idx;
	poll_queue.sid = (idx + 1) % ASYNC_QUEUE_TASK_NUM;
	poll_queue.status[idx] = 1;
	task_queue = poll_queue.head;
	task = &task_queue[idx];
	task->op = NULL;
	ret = UADK_E_SUCCESS;

out:
	if (pthread_mutex_unlock(&poll_queue.async_task_mutex))
		return UADK_E_FAIL;

	return ret;
}

static int async_add_poll_task(void *ctx, struct async_op *op, enum task_type type)
{
	struct async_poll_task *task_queue;
	struct async_poll_task *task;
	int ret;

	task_queue = poll_queue.head;
	task = &task_queue[op->idx];
	task->ctx = ctx;
	task->type = type;
	task->op = op;

	ret = sem_post(&poll_queue.full_sem);
	if (ret)
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;
}

int async_pause_job(void *ctx, struct async_op *op, enum task_type type)
{
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	void *custom;
	uint64_t buf;
	int ret;

	ret = async_add_poll_task(ctx, op, type);
	if (!ret)
		return ret;

	waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)op->job);
	if (!waitctx)
		return UADK_E_FAIL;

	do {
		if (!ASYNC_pause_job())
			return UADK_E_FAIL;

		ret = ASYNC_WAIT_CTX_get_fd(waitctx, uadk_async_key, &efd, &custom);
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
	uint64_t buf = 1;
	void *custom;
	int ret;

	waitctx = ASYNC_get_wait_ctx(job);
	if (!waitctx)
		return UADK_E_FAIL;

	ret = ASYNC_WAIT_CTX_get_fd(waitctx, uadk_async_key, &efd, &custom);
	if (ret > 0) {
		if (write(efd, &buf, sizeof(uint64_t)) == -1) {
			fprintf(stderr, "failed to write to fd: %d - error: %d\n", efd, errno);
			return errno;
		}
	}

	return ret;
}

void async_register_poll_fn(int type, async_recv_t func)
{
	if (type < ASYNC_TASK_CIPHER || type >= ASYNC_TASK_MAX) {
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

	while (uadk_e_get_async_poll_state()) {
		if (sem_wait(&poll_queue.full_sem)) {
			if (errno == EINTR) {
				/* sem_wait is interrupted by interrupt, continue */
				continue;
			}
		}

		task = async_get_queue_task();
		if (!task) {
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

	memset(&poll_queue, 0, sizeof(struct async_poll_queue));

	if (pthread_mutex_init(&(poll_queue.async_task_mutex), NULL) < 0)
		return UADK_E_FAIL;

	poll_queue.head = OPENSSL_malloc(ASYNC_QUEUE_TASK_NUM * sizeof(struct async_poll_task));
	if (!poll_queue.head)
		return UADK_E_FAIL;

	if (sem_init(&poll_queue.empty_sem, 0, ASYNC_QUEUE_TASK_NUM) != 0)
		goto err;

	if (sem_init(&poll_queue.full_sem, 0, 0) != 0)
		goto err;

	uadk_e_set_async_poll_state(ENABLE_ASYNC_POLLING);

	pthread_attr_init(&poll_queue.thread_attr);
	pthread_attr_setdetachstate(&poll_queue.thread_attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&thread_id, &poll_queue.thread_attr, async_poll_process_func, NULL))
		goto err;

	poll_queue.thread_id = thread_id;
	return UADK_E_SUCCESS;

err:
	async_poll_task_free();
	return UADK_E_FAIL;
}
