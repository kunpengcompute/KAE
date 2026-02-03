/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
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

#ifndef KAESNAPPY_COMMON_H
#define KAESNAPPY_COMMON_H

#define CONF_KAESNAPPY

#define KAE_SNAPPY_PROCESS_IDLE 0
#define KAE_SNAPPY_PROCESS_HW_BUSY (-1)

enum kae_snappy_async_data_format {
    KAESNAPPY_ASYNC_SMALL_BLOCK = 0,
    KAESNAPPY_ASYNC_BLOCK,
    KAESNAPPY_ASYNC_FRAME,
    KAESNAPPY_ASYNC_BUTT,
};

#include "kaesnappy.h"

#endif
