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

#ifndef KAEZSTD_COMP_H
#define KAEZSTD_COMP_H

#include "kaezstd_common.h"

void kaezstd_setstatus_v1(ZSTD_CCtx* zc, unsigned int status);
int  kaezstd_compress_v1(ZSTD_CCtx* zc, const void* src, size_t srcSize);

#endif