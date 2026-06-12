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
