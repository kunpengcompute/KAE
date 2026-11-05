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

#ifndef KAEZLIB_COMMON_H
#define KAEZLIB_COMMON_H

#define CONF_KAEZLIB

#define KAE_ZLIB_PROCESS_IDLE    0
#define KAE_ZLIB_PROCESS_HW_BUSY (-1)

enum kaezip_async_data_format {
    KAEZIP_ASYNC_BLOCK = 0,
    KAEZIP_ASYNC_BUTT,
};

#include "kaezip.h"

#endif