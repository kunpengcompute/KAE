/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy nosva compress
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */
#include "kaesnappy_ctx.h"
#include "kaesnappy_comp.h"
#include "kaesnappy_log.h"

#define KZL_MEMCPY_8(dst, src, size) vst1_u8((dst), vld1_u8(src))
#define KZL_MEMCPY_16(dst, src, size) vst1q_u8((dst), vld1q_u8(src))

__thread struct kaesnappy_async_ctrl g_async_ctrl = {0};

static int kaesnappy_data_parsing(SNAPPY_CCtx* zc, kaesnappy_ctx_t* config)
{
    if (!config->snappy_data.literals_start || !config->snappy_data.sequences_start) {
        US_ERR("snappy literals or sequences start is NULL!\n");
        return KAE_SNAPPY_INVAL_PARA;
    }

    zc->seqStore.litStart = config->snappy_data.literals_start;
    zc->seqStore.lit = zc->seqStore.litStart;
    zc->seqStore.lit += config->snappy_data.lit_num;

    zc->seqStore.sequencesStart = config->snappy_data.sequences_start;
    zc->seqStore.sequences = zc->seqStore.sequencesStart;
    zc->seqStore.sequences += config->snappy_data.seq_num;
    return KAE_SNAPPY_SUCC;
}

int kaesnappy_compress_v1(SNAPPY_CCtx* zc, const void* src, size_t srcSize)
{
    kaesnappy_ctx_t* kaesnappy_ctx = (kaesnappy_ctx_t*)zc->kaeConfig;
    if (kaesnappy_ctx == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_SNAPPY_INVAL_PARA;
    }

    US_INFO("kaesnappy compress srcSize : %lu", srcSize);
    kaesnappy_ctx->in           = (void*)src;
    kaesnappy_ctx->in_len       = srcSize;
    kaesnappy_ctx->out          = NULL;
    kaesnappy_ctx->consumed     = 0;
    kaesnappy_ctx->produced     = 0;
    kaesnappy_ctx->avail_out    = KAEZIP_STREAM_CHUNK_OUT;
    kaesnappy_ctx->flush = (zc->kaeFrameMode == 1) ? WCRYPTO_FINISH :
            (srcSize & 0x3) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
    kaesnappy_ctx->do_comp_len = kaesnappy_ctx->in_len;

    kaesnappy_set_input_data(kaesnappy_ctx);
    struct wcrypto_comp_op_data *op_data = &kaesnappy_ctx->op_data;

    int ret = wcrypto_do_comp(kaesnappy_ctx->wd_ctx, op_data, NULL);   // sync
    if (unlikely(ret < 0)) {
        US_ERR("snappy wcrypto_do_comp fail! ret = %d\n", ret);
        return ret;
    } else {
        struct wcrypto_lz77_zstd_format* snappy_data = &kaesnappy_ctx->snappy_data;
        zc->seqnum = snappy_data->seq_num; // 获取硬件返回三元组数目，用于遍历解析
    }

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    kaesnappy_get_output_data(kaesnappy_ctx);
    ret = kaesnappy_data_parsing(zc, kaesnappy_ctx);

    return ret;
}

#define PREFL1_64B(ptr) __builtin_prefetch((ptr), 0, 0)
#define PREFL2_64B(ptr) __builtin_prefetch((ptr), 0, 2)
#define PREFL1L2_256B(l1ptr, l2ptr) do { \
    PREFL1_64B((l1ptr) + 0 * 64);  \
    PREFL2_64B((l2ptr) + 0 * 64);  \
    PREFL1_64B((l1ptr) + 1 * 64);  \
    PREFL2_64B((l2ptr) + 1 * 64);  \
    PREFL1_64B((l1ptr) + 2 * 64);  \
    PREFL2_64B((l2ptr) + 2 * 64);  \
    PREFL1_64B((l1ptr) + 3 * 64);  \
    PREFL2_64B((l2ptr) + 3 * 64);  \
} while (0)

#define CRC32D_64B(crc, ptr) do { \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 0)); \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 1)); \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 2)); \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 3)); \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 4)); \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 5)); \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 6)); \
    (crc) = __crc32d((crc), *(const uint64_t *)((ptr) + 8 * 7)); \
} while (0)
#define CRC32D_64B_X4(crc, ptr) do { \
    CRC32D_64B((crc), (ptr) + 0 * 64); \
    CRC32D_64B((crc), (ptr) + 1 * 64); \
    CRC32D_64B((crc), (ptr) + 2 * 64); \
    CRC32D_64B((crc), (ptr) + 3 * 64); \
} while (0)

#define PLATFORM_IS_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)

static inline uint32_t DecodeFixed32(const char* ptr)
{
    if (PLATFORM_IS_LITTLE_ENDIAN) {
        uint32_t result;
        memcpy(&result, ptr, sizeof(result));
        return result;
    } else {
        return ((uint32_t)(ptr[0]) | ((uint32_t)(ptr[1]) << 8) | ((uint32_t)(ptr[2]) << 16) | ((uint32_t)(ptr[3]) << 24));
    }
}

static inline uint64_t DecodeFixed64(char* ptr)
{
    if (PLATFORM_IS_LITTLE_ENDIAN) {
        uint64_t result;
        memcpy(&result, ptr, sizeof(result));
        return result;
    } else {
        uint64_t lo = DecodeFixed32(ptr);
        uint64_t hi = DecodeFixed32(ptr + 4);
        return (hi << 32) | lo;
    }
}

static inline uint64_t LE_LOAD64(uint8_t* p)
{
    return DecodeFixed64((char*)(p));
}

static void SNAPPY_write16(void* memPtr, U16 value) { ((SNAPPY_unalign*)memPtr)->u16 = value; }

static unsigned SNAPPY_isLittleEndian(void)
{
    const union { U32 u; BYTE c[4]; } one = { 1 };   /* don't use static : performance detrimental */
    return one.c[0];
}

static inline void SNAPPY_wildCopy8(void* dstPtr, const void* srcPtr, void* dstEnd)
{
    BYTE* d = (BYTE*)dstPtr;
    const BYTE* s = (const BYTE*)srcPtr;
    BYTE* const e = (BYTE*)dstEnd;

    do { KZL_MEMCPY_8(d,s,8); d+=8; s+=8; } while (d<e);
}

static inline void SNAPPY_wildCopy16(void* dstPtr, const void* srcPtr, void* dstEnd)
{
    BYTE* d = (BYTE*)dstPtr;
    const BYTE* s = (const BYTE*)srcPtr;
    BYTE* const e = (BYTE*)dstEnd;

    do { KZL_MEMCPY_16(d,s,16); d+=16; s+=16; } while (d<e);
}


static inline void SNAPPY_writeLE16(void* memPtr, U16 value)
{
    if (SNAPPY_isLittleEndian()) {
        SNAPPY_write16(memPtr, value);
    } else {
        BYTE* p = (BYTE*)memPtr;
        p[0] = (BYTE) value;
        p[1] = (BYTE)(value>>8);
    }
}
