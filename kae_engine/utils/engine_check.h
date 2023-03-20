/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the interface for an engine check thread
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

#ifndef ENGINE_CHECK_H
#define ENGINE_CHECK_H

#include <pthread.h>

#define KAE_QUEUE_CHECKING_INTERVAL 15000


struct kae_check_q_task_s {
    int             init_flag;
    int             exit_flag;
    pthread_t       thread_id;
};

typedef struct kae_check_q_task_s KAE_CHECK_Q_TASK;

void kae_enable_async(void);
void kae_disable_async(void);
int  kae_is_async_enabled(void);
int  kae_checking_q_thread_init(void);
void kae_check_thread_reset();

#endif // end of ENGINE_CHECK_H

