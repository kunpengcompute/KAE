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

#ifndef KAESNAPPY_ADAPTER
#define KAESNAPPY_ADAPTER
#include "kaesnappy_common.h"

enum {
    HW_NONE,
    HW_V1,
    HW_V2,
    HW_V3   //  unused now
};

int  kaesnappy_init_v1(SNAPPY_CCtx* zc);
void kaesnappy_release_v1(SNAPPY_CCtx* zc);
int  kaesnappy_compress_v1(SNAPPY_CCtx* zc, const void* src, size_t srcSize);

int  kaesnappy_init_v2(SNAPPY_CCtx* zc);
void kaesnappy_release_v2(SNAPPY_CCtx* zc);
int  kaesnappy_compress_v2(SNAPPY_CCtx* zc, const void* src, size_t srcSize);

int wd_get_available_dev_num(const char* alogrithm);
#endif
