/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides implementation for callback in KAE engine
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

#include "async_callback.h"
#include "engine_log.h"
#include "engine_utils.h"

#include <openssl/err.h>

void async_init_op_done(op_done_t *op_done)
{
    if ((op_done == NULL)) {
        US_ERR("error! paramater is NULL.");
        return ;
    }

    op_done->flag = 0;
    op_done->verifyRst = 0;
    op_done->job = ASYNC_get_current_job();
}

void async_cleanup_op_done(op_done_t *op_done)
{
    if ((op_done == NULL)) {
        US_ERR("error! paramater is NULL.");
        return;
    }

    op_done->verifyRst = 0;

    if (op_done->job) {
        op_done->job = NULL;
    }

    return;
}
/*lint -e(10)*/

