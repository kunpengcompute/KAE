/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides interface for callback in KAE engine
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

#ifndef ASYNC_CALLBACK_H
#define ASYNC_CALLBACK_H

#include <sys/types.h>

#include <openssl/async.h>


typedef struct {
    volatile int flag;
    volatile int verifyRst;
    volatile ASYNC_JOB *job;
} op_done_t;

void async_init_op_done(op_done_t *op_done);

void async_cleanup_op_done(op_done_t *op_done);

#endif

