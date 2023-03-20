/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides implementation for async events in KAE engine
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

#ifndef _USE_GNU
# define _USE_GNU
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <openssl/err.h>

#include "async_event.h"
#include "engine_kae.h"

static void async_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key, OSSL_ASYNC_FD readfd, void *custom)
{
    (void)ctx;
    (void)key;
    (void)custom;
    if (close(readfd) != 0) {
        US_WARN("Failed to close fd: %d - error: %d\n", readfd, errno);
    }
}

int async_setup_async_event_notification(int jobStatus)
{
    (void)jobStatus;
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;

    job = ASYNC_get_current_job();
    if (job == NULL) {
        US_ERR("Could not obtain current async job\n");
        return 0;
    }

    waitctx = ASYNC_get_wait_ctx(job);
    if (waitctx == NULL) {
        US_ERR("current job has no waitctx.");
        return 0;
    }

    if (ASYNC_WAIT_CTX_get_fd(waitctx, g_engine_kae_id, &efd,
                              &custom) == 0) {
        efd = eventfd(0, EFD_NONBLOCK);
        if (efd == -1) {
            US_ERR("efd error.");
            return 0;
        }

        if (ASYNC_WAIT_CTX_set_wait_fd(waitctx, g_engine_kae_id, efd,
                                       custom, async_fd_cleanup) == 0) {
            US_ERR("set wait fd error.");
            async_fd_cleanup(waitctx, g_engine_kae_id, efd, NULL);
            return 0;
        }
    }
    return 1;
}

int async_clear_async_event_notification()
{
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    size_t num_add_fds = 0;
    size_t num_del_fds = 0;
    void *custom = NULL;

    job = ASYNC_get_current_job();
    if (job == NULL) {
        US_ERR("no async job.");
        return 0;
    }
    
    waitctx = ASYNC_get_wait_ctx(job);
    if (waitctx == NULL) {
        US_ERR("The job has no waitctx");
        return 0;
    }

    if (ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &num_add_fds, NULL, &num_del_fds) == 0) {
        US_ERR("no add fds.");
        return 0;
    }

    if (num_add_fds > 0) {
        if (ASYNC_WAIT_CTX_get_fd(waitctx, g_engine_kae_id, &efd, &custom) == 0) {
            US_ERR("no fd.");
            return 0;
        }

        async_fd_cleanup(waitctx, g_engine_kae_id, efd, NULL);

        if (ASYNC_WAIT_CTX_clear_fd(waitctx, g_engine_kae_id) == 0) {
            US_ERR("clear fd error.");
            return 0;
        }
    }

    return 1;
}

int async_pause_job(volatile ASYNC_JOB *job, int jobStatus)
{
    (void)jobStatus;

    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;
    uint64_t buf = 0;
    int ret = 0;

    waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job);
    if (waitctx == NULL) {
        US_ERR("error. waitctx is NULL\n");
        return ret;
    }

    if (ASYNC_pause_job() == 0) {
        US_ERR("Failed to pause the job\n");
        return ret;
    }

    ret = ASYNC_WAIT_CTX_get_fd(waitctx, g_engine_kae_id, &efd, &custom);
    if (ret > 0) {
        if (read(efd, &buf, sizeof(uint64_t)) == -1) {
            if (errno != EAGAIN) {
                US_WARN("Failed to read from fd: %d - error: %d\n", efd, errno);
            }
            /* Not resumed by the expected async_wake_job() */
            return ASYNC_JOB_RESUMED_UNEXPECTEDLY;
        }
    }

    return ret;
}


int async_wake_job(volatile ASYNC_JOB *job, int jobStatus)
{
    (void)jobStatus;

    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD efd;
    void *custom = NULL;
    uint64_t buf = 1;
    int ret = 0;

    waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)job);
    if (waitctx == NULL) {
        US_ERR("error. waitctx is NULL\n");
        return ret;
    }

    ret = ASYNC_WAIT_CTX_get_fd(waitctx, g_engine_kae_id, &efd, &custom);
    if (ret > 0) {
        if (write(efd, &buf, sizeof(uint64_t)) == -1) {
            US_ERR("Failed to write to fd: %d - error: %d\n", efd, errno);
        }
    }

    US_DEBUG("- async wake job success - ");
    return ret;
}
/*lint -e(10)*/

