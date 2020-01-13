/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the implemenation for utis module
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

#include <pthread.h>
#include "engine_utils.h"
#include "engine_log.h"

int kae_create_thread(pthread_t *thread_id, const pthread_attr_t *attr,
    void *(*start_func)(void *), void *p_arg)
{
    (void)attr;

    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(thread_id, &thread_attr, start_func, p_arg) != 0) {
        US_ERR("fail to create thread, reason:%s", strerror(errno)); //lint !e666
        return 0;
    }

    return 1;
}

int kae_create_thread_joinable(pthread_t *thread_id, const pthread_attr_t *attr,
    void *(*start_func)(void *), void *p_arg)
{
    (void)attr;

    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
    if (pthread_create(thread_id, &thread_attr, start_func, p_arg) != 0) {
        US_ERR("fail to create thread, reason:%s", strerror(errno)); //lint !e666
        return 0;
    }
    return 1;
}

inline int kae_join_thread(pthread_t threadId, void **retval)
{
    return pthread_join(threadId, retval);
}

