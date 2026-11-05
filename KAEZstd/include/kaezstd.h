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

#ifndef KAEZSTD_H
#define KAEZSTD_H

#include "zstd.h"
#ifdef BUILD_KAEZSTD
#include "zstd_internal.h"
#include "zstd_compress_internal.h"
#endif

#define TUPLE_STATUS_COMPRESS 2
#define TUPLE_STATUS_RLEBLOCK 1
#define TUPLE_STATUS_NOCOMPRESS 0

#define VERSION_STRUCT_LEN 100
typedef struct {
    char productName[VERSION_STRUCT_LEN];
    char productVersion[VERSION_STRUCT_LEN];
    char componentName[VERSION_STRUCT_LEN];
    char componentVersion[VERSION_STRUCT_LEN];
}KAEZstdVersion;
extern int kaezstd_get_version(KAEZstdVersion* ver);
extern int kaezstd_init(ZSTD_CCtx* zc);
extern void kaezstd_reset(ZSTD_CCtx* zc);
extern void kaezstd_release(ZSTD_CCtx* zc);
extern void kaezstd_setstatus(ZSTD_CCtx* zc, unsigned int status);
extern int kaezstd_compress(ZSTD_CCtx* zc, const void* src, size_t srcSize);

#endif
