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

#include <climits>
#include <cstddef>

#include <gtest/gtest.h>

extern "C" {
#include <lz4_accelerater.h>

#include "kaelz4.h"
#include "kaelz4_comp.h"
}

// Purpose: v1 direct compression entry validation. Verifies that invalid
// top-level arguments are rejected before zc->kaeConfig is dereferenced.
TEST(KAELz4SyncInterface, CompressV1RejectsInvalidTopLevelArguments)
{
    unsigned char src[1] = {0};
    LZ4_CCtx ctx = {};

    EXPECT_EQ(kaelz4_compress_v1(nullptr, src, sizeof(src)), KAE_LZ4_INVAL_PARA);
    EXPECT_EQ(kaelz4_compress_v1(&ctx, nullptr, sizeof(src)), KAE_LZ4_INVAL_PARA);
    EXPECT_EQ(kaelz4_compress_v1(&ctx, src, 0), KAE_LZ4_INVAL_PARA);
    EXPECT_EQ(kaelz4_compress_v1(&ctx, src, sizeof(src)), KAE_LZ4_INVAL_PARA);
}

// Purpose: v1 direct compression size validation. Verifies that oversized input
// is rejected before touching the fixed 2 MiB staging buffer or hardware ctx.
TEST(KAELz4SyncInterface, CompressV1RejectsInputLargerThanStagingBuffer)
{
    unsigned char src[1] = {0};
    LZ4_CCtx ctx = {};
    ctx.kaeConfig = 1;

    EXPECT_EQ(kaelz4_compress_v1(&ctx, src, COMP_BLOCK_SIZE + 1UL), KAE_LZ4_INVAL_PARA);
}

// Purpose: v1 direct compression size validation. Verifies that size_t values
// beyond the unsigned-int fields in kaelz4_ctx are rejected before truncation.
TEST(KAELz4SyncInterface, CompressV1RejectsSizeBeyondUint)
{
    unsigned char src[1] = {0};
    LZ4_CCtx ctx = {};
    ctx.kaeConfig = 1;

    EXPECT_EQ(kaelz4_compress_v1(&ctx, src, static_cast<size_t>(UINT_MAX) + 1UL), KAE_LZ4_INVAL_PARA);
}
