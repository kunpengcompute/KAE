/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the interface for wd_alg_queue.c
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

#ifndef __WD_ALG_QUEUE_H
#define __WD_ALG_QUEUE_H

#include "wd.h"
#include "engine_utils.h"

struct wd_queue* wd_new_queue(int algtype);

void wd_free_queue(struct wd_queue* queue);


#endif

