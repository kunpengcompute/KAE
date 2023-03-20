/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides interface for async events in KAE engine
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

#ifndef __ASYNC_EVENTS_H__
#define __ASYNC_EVENTS_H__

#include <unistd.h>

#include <openssl/async.h>


#define ASYNC_JOB_RESUMED_UNEXPECTEDLY (-1)
#define ASYNC_CHK_JOB_RESUMED_UNEXPECTEDLY(x) \
    ((x) == ASYNC_JOB_RESUMED_UNEXPECTEDLY)

#define ASYNC_STATUS_UNSUPPORTED 0
#define ASYNC_STATUS_ERR         1
#define ASYNC_STATUS_OK          2
#define ASYNC_STATUS_EAGAIN      3

int async_setup_async_event_notification(int jobStatus);
int async_clear_async_event_notification();
int async_pause_job(volatile ASYNC_JOB *job, int jobStatus);
int async_wake_job(volatile ASYNC_JOB *job, int jobStatus);

#endif

