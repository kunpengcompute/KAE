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

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * Upstream portions are licensed under the BSD 3-Clause License; see LICENSE.zstd
 * in the KAEZstd directory for the full license text.
 * The Apache-2.0 notice above applies only to KAEZstd modifications.
 */

#ifndef FUNC_COMMON_H
#define FUNC_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <zstd.h>      // presumes zstd library is installed

#include "common.h"

typedef struct {
    void* buffIn;
    void* buffOut;
    size_t buffInSize;
    size_t buffOutSize;
    ZSTD_CCtx* cctx;
} Resources;

struct CompressOut {
    void *oBuff; // 待压缩的缓冲区，original buff
    size_t oSize; // 待压缩的字节数
    void *cBuff; // 压缩后的缓冲区，compressed buff
    size_t const cSize; // 压缩后的字节数

    CompressOut(void *oBuff, size_t oSize, void *cBuff, size_t cSize)
        : oBuff(oBuff), oSize(oSize), cBuff(cBuff), cSize(cSize) {}
};

struct DecompressOut {
    void *dBuff; // 解压后的缓冲区，decompressed buff
    size_t const dSize; // 解压后的字节数

    DecompressOut(void *buff, size_t size) : dBuff(buff), dSize(size) {}
};

CompressOut DoCompress(int streamLen, int cLevel, int nbThreads);
CompressOut DoCompressStream2(int streamLen, int cLevel, int nbThreads);
DecompressOut Decompress(CompressOut compressOut);
DecompressOut DecompressStream(CompressOut compressOut);

#endif /* FUNC_COMMON_H */