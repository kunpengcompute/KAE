/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy nosva compress
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */
#include <snappy_accelerater.h>
#include "kaesnappy_ctx.h"
#include "kaesnappy_comp.h"
#include "kaesnappy_log.h"
#include <xxhash.h>

__thread struct kaesnappy_async_ctrl g_async_ctrl = {0};

void kaesnappy_setstatus_v1(SNAPPY_CCtx* zc, unsigned int status)
{
    kaesnappy_ctx_t* kaesnappy_ctx = (kaesnappy_ctx_t*)zc->kaeConfig;
    if (kaesnappy_ctx) {
        kaesnappy_ctx->snappy_data.blk_type = status;
        US_DEBUG("kaesnappy set status %u", status);
    }
}

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

static const uint32_t table0_[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

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

static inline void Slow_CRC32(uint64_t* l, uint8_t** p)
{
    *l = __crc32d(*l, LE_LOAD64(*p));
    *p += 8;
}

// CRC32 API接口函数
static uint32_t KAESNAPPYCRC32(uint32_t crc, const char *data, uint64_t len)
{
    if (data == NULL) {
        return crc;
    }

    uint64_t crcResult = crc ^ 0xffffffffu;
    uint8_t *targetPtr = (uint8_t *)data;

    #define STEP1                  \
    do {                           \
        int c = (crcResult & 0xff) ^ *targetPtr++; \
        crcResult = table0_[c] ^ (crcResult >> 8); \
    } while (0)
    #define ALIGN(n, m) ((n + ((1 << m) - 1)) & ~((1 << m) - 1))

    uint8_t *targetPtrAlign = (uint8_t *)ALIGN((uintptr_t)targetPtr, 4);

    while (targetPtr != targetPtrAlign) {
        STEP1;
        len -= 1;
    }

    while (len >= 256) { // 每次计算256B
        PREFL1L2_256B(targetPtr + 704, targetPtr + 1984);
        CRC32D_64B_X4(crcResult, targetPtr);
        targetPtr += 256;
        len -= 256;
    }

    while (len >= 16) { // 每次计算16B
        Slow_CRC32(&crcResult, &targetPtr);
        Slow_CRC32(&crcResult, &targetPtr);
        len -= 16;
    }

    while (len >= 8) { // 每次计算8B
        Slow_CRC32(&crcResult, &targetPtr);
        len -= 8;
    }

    while (len >= 1) { // 每次计算1B
        STEP1;
        len -= 1;
    }
    return crcResult ^ 0xffffffffu;
}

static void kaesnappy_compress_async_callback(struct kaesnappy_compress_ctx *compress_ctx, int status)
{
    struct kaesnappy_result *result = compress_ctx->result;
    result->status = status;
    result->dst_len = compress_ctx->dst_len;
    if (result->ibuf_crc != NULL && status == KAE_SNAPPY_SUCC) {
        *result->ibuf_crc = KAESNAPPYCRC32(*result->ibuf_crc, compress_ctx->src, compress_ctx->srcSize);
    }

    if (result->obuf_crc != NULL && status == KAE_SNAPPY_SUCC) {
        *result->obuf_crc = KAESNAPPYCRC32(*result->obuf_crc, compress_ctx->dst, compress_ctx->dst_len);
    }

    if (unlikely(status != KAE_SNAPPY_SUCC)) {
        US_ERR("kae async compress fail! ret = %d\n", status);
    }

    compress_ctx->callback(compress_ctx->result);
    free(compress_ctx);
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


static int kaesnappy_triples_rebuild(struct kaesnappy_async_req *req, const void *source, void *dest)
{
    const BYTE* ip = (const BYTE*) source;
    BYTE* op = (BYTE*) dest;
    U32 offBase = 0;
    U32 litLength = 0;
    U16 mlBase = 0;
    seqDef* sequencesPtr = req->zc.seqStore.sequencesStart;
    U32 seqSum = 0;
    // special flag 表示硬件没有返回三元组，zc为空
    if (req->special_flag) {
        seqSum = 0;
    } else {
        seqSum = req->zc.seqnum;
    }

    size_t srcSize = req->src_size;
    U32 seqCount = 0;
    U32 tempLiteralLength = 0;
    U32 tempSeqNum = 0;
    BYTE* token = NULL;
    U32 len = 0;
    U32 matchCode = 0;

    while (seqCount < seqSum) {
        offBase = sequencesPtr->offBase + 1;
        litLength = sequencesPtr->litLength;
        mlBase = sequencesPtr->mlBase;
        sequencesPtr++;
        seqCount++;

        if (mlBase == 0) {
            tempLiteralLength += litLength;
            tempSeqNum++;
            continue;
        }

        litLength += tempLiteralLength + tempSeqNum * 3;
        tempSeqNum = 0;

        token = op++;
        if (litLength >= RUN_MASK) {
            len = litLength - RUN_MASK;
            *token = (RUN_MASK << ML_BITS);
            while (len >= 255) {
                *op++ = 255;
                len -= 255;
            }
            *op++ = (BYTE)len;
        } else {
            *token = (BYTE)(litLength << ML_BITS);
        }

        SNAPPY_wildCopy16(op, ip, op + litLength);
        op += litLength;
        ip += litLength + mlBase + 3;
        tempLiteralLength = 0;

        SNAPPY_writeLE16(op, (U16)(offBase));
        op += 2;
        if (unlikely(offBase > 65535)) { // 边界情况判断，硬件返回结果中，offBase不应该大于64KB
            US_ERR("Warning! offBase(%d) is larger than 64KB.\n", offBase);
            return KAE_SNAPPY_REBUILD_FAIL;
        }

        matchCode = mlBase - 1;
        if (matchCode >= ML_MASK) {
            *token += ML_MASK;
            matchCode -= ML_MASK;
            while (matchCode >= 255) {
                *op++ = 255;
                matchCode -= 255;
            }
            *op++ = (BYTE)matchCode;
        } else {
            *token += (BYTE)(matchCode);
        }
    }

    tempLiteralLength = (U32)((BYTE*)source + srcSize - ip);
    // 尾部处理
    token = op++;
    if (tempLiteralLength >= RUN_MASK) {
        len = tempLiteralLength - RUN_MASK;
        *token = (RUN_MASK << ML_BITS);
        while (len >= 255) {
            *op++ = 255;
            len -= 255;
        }
        *op++ = (BYTE)len;
    } else {
        *token = (BYTE)(tempLiteralLength << ML_BITS);
    }
    SNAPPY_memcpy(op, ip, tempLiteralLength);
    op += tempLiteralLength;

    int result = (int)(((char*)op) - ((char*)dest));

    return result;
}

// 针对场景：用户输入数据>64K且按照Block格式返回时，对各切块的尾部数据额外处理。
// 约束：分块原始数据内存连续
// 1、对于非last subblock：first new seq生成时继承prev subblock的last literal；cur subblock的尾部last literal信息更新至ctx中
// 2、对于last subblock：first new seq生成时继承prev subblock的last literal；cur subblock的尾部last literal生成last seq格式
static int kaesnappy_triples_rebuild_64Kblock(struct kaesnappy_async_req *req, const void *source, void *dest)
{
    const BYTE* ip = (const BYTE*) source;
    BYTE* op = (BYTE*) dest;
    U32 offBase = 0;
    U32 litLength = 0;
    U16 mlBase = 0;
    seqDef* sequencesPtr = req->zc.seqStore.sequencesStart;

    // special flag 表示硬件没有返回三元组，zc为空
    U32 seqSum = 0;
    if (req->special_flag) {
        seqSum = 0;
    } else {
        seqSum = req->zc.seqnum;
    }

    size_t srcSize = req->src_size;
    U32 seqCount = 0;
    U32 tempLiteralLength = 0;
    U32 tempSeqNum = 0;
    BYTE* token = NULL;
    U32 len = 0;
    U32 matchCode = 0;

    // 生成first new sequence 时，继承prev subblock的last literal
    // 如果无法生成，则本分块整体作为literal，留给后续的分块的first new sequence继承
    while (seqCount < seqSum) {
        offBase = sequencesPtr->offBase + 1;
        litLength = sequencesPtr->litLength;

        mlBase = sequencesPtr->mlBase;
        sequencesPtr++;
        seqCount++;

        if (mlBase == 0) {
            tempLiteralLength += litLength;
            tempSeqNum++;
            continue;
        }

        litLength += tempLiteralLength + tempSeqNum * 3 + req->compress_ctx->prev_last_lit_len;
        tempSeqNum = 0;

        token = op++;
        if (litLength >= RUN_MASK) {
            len = litLength - RUN_MASK;
            *token = (RUN_MASK << ML_BITS);
            while (len >= 255) {
                *op++ = 255;
                len -= 255;
            }
            *op++ = (BYTE)len;
        } else {
            *token = (BYTE)(litLength << ML_BITS);
        }

        // 满足生成first new sequence条件，继承prev subblock的last literal
        if (req->compress_ctx->prev_last_lit_ptr != NULL) {
            SNAPPY_wildCopy16(op, req->compress_ctx->prev_last_lit_ptr, op + req->compress_ctx->prev_last_lit_len);
            op += req->compress_ctx->prev_last_lit_len;
            litLength -= req->compress_ctx->prev_last_lit_len;
            req->compress_ctx->prev_last_lit_ptr = NULL;
            req->compress_ctx->prev_last_lit_len = 0;
        }

        SNAPPY_wildCopy16(op, ip, op + litLength);
        op += litLength;
        ip += litLength + mlBase + 3;
        tempLiteralLength = 0;

        SNAPPY_writeLE16(op, (U16)(offBase));
        op += 2;
        if (unlikely(offBase > 65535)) { // 边界情况判断，硬件返回结果中，offBase不应该大于64KB
            US_ERR("Warning! offBase(%d) is larger than 64KB.\n", offBase);
            return KAE_SNAPPY_REBUILD_FAIL;
        }

        matchCode = mlBase - 1;
        if (matchCode >= ML_MASK) {
            *token += ML_MASK;
            matchCode -= ML_MASK;
            while (matchCode >= 255) {
                *op++ = 255;
                matchCode -= 255;
            }
            *op++ = (BYTE)matchCode;
        } else {
            *token += (BYTE)(matchCode);
        }
        break;
    }

    while (seqCount < seqSum) {
        offBase = sequencesPtr->offBase + 1;
        litLength = sequencesPtr->litLength;
        mlBase = sequencesPtr->mlBase;
        sequencesPtr++;
        seqCount++;

        if (mlBase == 0) {
            tempLiteralLength += litLength;
            tempSeqNum++;
            continue;
        }

        litLength += tempLiteralLength + tempSeqNum * 3;
        tempSeqNum = 0;

        token = op++;
        if (litLength >= RUN_MASK) {
            len = litLength - RUN_MASK;
            *token = (RUN_MASK << ML_BITS);
            while (len >= 255) {
                *op++ = 255;
                len -= 255;
            }
            *op++ = (BYTE)len;
        } else {
            *token = (BYTE)(litLength << ML_BITS);
        }

        SNAPPY_wildCopy16(op, ip, op + litLength);
        op += litLength;
        ip += litLength + mlBase + 3;
        tempLiteralLength = 0;

        SNAPPY_writeLE16(op, (U16)(offBase));
        op += 2;
        if (unlikely(offBase > 65535)) { // 边界情况判断，硬件返回结果中，offBase不应该大于64KB
            US_ERR("Warning! offBase(%d) is larger than 64KB.\n", offBase);
            return KAE_SNAPPY_REBUILD_FAIL;
        }

        matchCode = mlBase - 1;
        if (matchCode >= ML_MASK) {
            *token += ML_MASK;
            matchCode -= ML_MASK;
            while (matchCode >= 255) {
                *op++ = 255;
                matchCode -= 255;
            }
            *op++ = (BYTE)matchCode;
        } else {
            *token += (BYTE)(matchCode);
        }
    }

    tempLiteralLength = (U32)((BYTE*)source + srcSize - ip);
    // 尾部处理
    // 非last subblock，刷新ctx中的prev subblock literal 信息
    if (req->last != 1) {
        // 本分块不满足rebuild new seq：1)subblock完全不可压，全是literal;2)三元组全是matchlen=0。本分块作为literal留给后续分块的first new seq继承，且存在跨多个分块情况
        if (unlikely(req->compress_ctx->prev_last_lit_ptr != NULL)) {
            req->compress_ctx->prev_last_lit_len += tempLiteralLength;
        } else { // 本分块满足rebuild new seq:记录尾部的literal部分信息，留给后续分块的first new seq继承
            req->compress_ctx->prev_last_lit_ptr = (void *)ip;
            req->compress_ctx->prev_last_lit_len = tempLiteralLength;
        }
    } else { // last subblock，生成last seq
        // 继承prev subblock的last literal
        tempLiteralLength += req->compress_ctx->prev_last_lit_len;

        token = op++;
        if (tempLiteralLength >= RUN_MASK) {
            len = tempLiteralLength - RUN_MASK;
            *token = (RUN_MASK << ML_BITS);
            while (len >= 255) {
                *op++ = 255;
                len -= 255;
            }
            *op++ = (BYTE)len;
        } else {
            *token = (BYTE)(tempLiteralLength << ML_BITS);
        }

        if (req->compress_ctx->prev_last_lit_ptr != NULL) {
            SNAPPY_wildCopy16(op, req->compress_ctx->prev_last_lit_ptr, op + req->compress_ctx->prev_last_lit_len);
            op += req->compress_ctx->prev_last_lit_len;
            tempLiteralLength -= req->compress_ctx->prev_last_lit_len;
            req->compress_ctx->prev_last_lit_ptr = NULL;
            req->compress_ctx->prev_last_lit_len = 0;
        }

        SNAPPY_memcpy(op, ip, tempLiteralLength);
        op += tempLiteralLength;
    }

    int result = (int)(((char*)op) - ((char*)dest));

    return result;
}

static void kaesnappy_async_compress_cb(int status, void *param)
{
    struct kaesnappy_async_req* req = param;
    SNAPPY_CCtx* zc = &req->zc;
    kaesnappy_ctx_t* kaesnappy_ctx = (kaesnappy_ctx_t*)zc->kaeConfig;
    struct wcrypto_comp_op_data *op_data = &kaesnappy_ctx->op_data;

    if (status != 0) {
        US_ERR("kaesnappy_async_compress_cb status %d !\n", status);
        req->compress_ctx->status = KAE_SNAPPY_COMP_FAIL;
        req->done = 1;
        return;
    }

    struct wcrypto_lz77_zstd_format* snappy_data = &kaesnappy_ctx->snappy_data;
    zc->seqnum = snappy_data->seq_num; // 获取硬件返回三元组数目，用于遍历解析
    US_DEBUG("frameMode = %u, flush = %d, lit_num = %u, seq_num = %u, lit_length_overflow_cnt = %u, lit_length_overflow_pos = %u\n",
        zc->kaeFrameMode, kaesnappy_ctx->flush,
        snappy_data->lit_num, snappy_data->seq_num, snappy_data->lit_length_overflow_cnt, snappy_data->lit_length_overflow_pos);

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    kaesnappy_get_output_data(kaesnappy_ctx);
    int ret = kaesnappy_data_parsing(zc, kaesnappy_ctx);

    if (ret != KAE_SNAPPY_SUCC) {
        req->compress_ctx->status = KAE_SNAPPY_COMP_FAIL;
        req->done = 1;
        return;
    }
    req->done = 1;
}

static int kaesnappy_compress_async_impl(SNAPPY_CCtx* zc, const void* src, size_t srcSize, void *usr_data)
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
    kaesnappy_ctx->callback = kaesnappy_async_compress_cb;
    kaesnappy_ctx->param = usr_data;

    kaesnappy_set_input_data(kaesnappy_ctx);
    struct wcrypto_comp_op_data *op_data = &kaesnappy_ctx->op_data;

    return wcrypto_do_comp(kaesnappy_ctx->wd_ctx, op_data, kaesnappy_ctx);   // async
}

static void kaesnappy_find_and_free_kz_ctx(kaesnappy_ctx_t *kz_ctx)
{
    for (int i = 0; i < MAX_NUM_IN_COMP; i++) {
        if (g_async_ctrl.kz_ctx[i] == kz_ctx) {
            kaesnappy_free_ctx(g_async_ctrl.kz_ctx[i]);
            g_async_ctrl.kz_ctx[i] = NULL;
        }
    }
}


static void kaesnappy_do_compress_polling(struct kaesnappy_async_req *req)
{
    if (req->special_flag != 0) {
        return;
    }

    kaesnappy_ctx_t *kaesnappy_ctx = (kaesnappy_ctx_t *)req->zc.kaeConfig;
    struct wd_queue *q = kaesnappy_ctx->q_node->kae_wd_queue;

    int ret = wcrypto_comp_poll(q, 1);
    if (unlikely(ret < 0)) {
        US_ERR("poll fail! ret = %d\n", ret);
        kaesnappy_find_and_free_kz_ctx(kaesnappy_ctx);
        req->compress_ctx->status = KAE_SNAPPY_COMP_FAIL;
        req->done = 1;
    }
    return;
}

int kaesnappy_async_is_thread_do_comp_full(void)
{
    return g_async_ctrl.cur_num_in_comp < MAX_NUM_IN_COMP ? 0 : 1;
}

void kaesnappy_async_init(volatile int *stop, sw_compress_fn sw_compress, sw_compress_frame_fn sw_compress_frame)
{
    g_async_ctrl.stop_flag = stop;
    g_async_ctrl.sw_compress_frame = sw_compress_frame;
}

static int kaesnappy_async_sw_compress(struct kaesnappy_compress_ctx *compress_ctx)
{
    int ret = -1;
    compress_ctx->status = KAE_SNAPPY_SUCC;
    if (compress_ctx->data_format == KAESNAPPY_ASYNC_FRAME && g_async_ctrl.sw_compress_frame != NULL) {
        ret = g_async_ctrl.sw_compress_frame(compress_ctx->dst, compress_ctx->dstCapacity, compress_ctx->src,
                                             compress_ctx->srcSize, &compress_ctx->preferences);
    } else if (compress_ctx->data_format <= KAESNAPPY_ASYNC_BLOCK && g_async_ctrl.sw_compress != NULL) {
        ret = g_async_ctrl.sw_compress(compress_ctx->src, compress_ctx->dst, compress_ctx->srcSize,
                                       compress_ctx->dstCapacity);
    }
    ret = (ret == 0) ? KAE_SNAPPY_SW_RETURN_0_FAIL : ret;
    return ret;
}

int kaesnappy_async_compress_polling(int budget)
{
    int cnt = 0;
    struct kaesnappy_compress_ctx *compress_ctx = g_async_ctrl.ctx_head;

    if (compress_ctx == NULL) {
        return 0;
    }
    struct kaesnappy_async_req *req = compress_ctx->req_list;
    US_DEBUG("do polling. budget = %d", budget);
    while (req && cnt < budget) {
        kaesnappy_do_compress_polling(req);
        if (!req->done) {
            return KAE_SNAPPY_PROCESS_HW_BUSY;
        }

        int ret = -1;

        if (likely(compress_ctx->status == KAE_SNAPPY_SUCC)) {
            ret = compress_ctx->kaesnappy_post_process_handle(req, req->src, compress_ctx->dst + compress_ctx->dst_len);
            if (ret < 0) {
                US_ERR("kaesnappy_post_process_handle err. ret=%d\n", ret);
            }
        }

        if (unlikely(ret < 0 && req->idx == 0 && req->last != 0 && req->compress_ctx->status != KAE_SNAPPY_HW_TIMEOUT_FAIL)) {
            US_WARN("KAESnappy async compress switch to soft");
            // 异常切软算处理
            ret = kaesnappy_async_sw_compress(compress_ctx);
        }

        if (ret >= 0 && compress_ctx->status == KAE_SNAPPY_SUCC) {
            compress_ctx->dst_len += ret;
            compress_ctx->status = KAE_SNAPPY_SUCC;
        } else {
            compress_ctx->dst_len = 0;
            if (compress_ctx->status == KAE_SNAPPY_SUCC) {
                compress_ctx->status = KAE_SNAPPY_COMP_FAIL;
            }

            US_ERR("kae post process fail! req index %d src size 0x%lx dst size 0x%lx last %d ret = %d status %d\n",
                   req->idx, req->src_size, compress_ctx->dstCapacity, req->last, ret, compress_ctx->status);
        }

        if (!req->special_flag) {
            g_async_ctrl.cur_num_in_comp--;
        }

        if (req->last) {
            g_async_ctrl.ctx_head = compress_ctx->next;
            kaesnappy_compress_async_callback(compress_ctx, compress_ctx->status);
            compress_ctx = g_async_ctrl.ctx_head;
        } else {
            compress_ctx->req_list = compress_ctx->req_list->next;
        }
        free(req);

        if (g_async_ctrl.ctx_head == NULL) {
            g_async_ctrl.tail = NULL;
            break;
        }
        req = compress_ctx->req_list;
        cnt++;
    }

    return cnt;
}

static struct timespec polling_timeout_10us = { 0, 10000 };  // 10us超时

static void kaesnappy_ctx_body_init(SNAPPY_CCtx *ctx_body)
{
    ctx_body->kaeInited = 0;
    ctx_body->kaeFrameMode = 1; // 相当于每个都强刷
    ctx_body->kaeConfig = (uintptr_t)NULL;

    ctx_body->seqStore.llCode = NULL;
    ctx_body->seqStore.mlCode = NULL;
    ctx_body->seqStore.ofCode = NULL;
    ctx_body->seqStore.lit = NULL;
    ctx_body->seqStore.litStart = NULL;
    ctx_body->seqStore.sequencesStart = NULL;
    ctx_body->seqStore.sequences = NULL;

    ctx_body->compressionLevel = 8;
    ctx_body->kaeLevel = 8;
    ctx_body->seqnum = 0;
}

static int kaesnappy_async_init_ctx(SNAPPY_CCtx *ctx_body)
{
    int enter_polling = 0;

    kaesnappy_ctx_body_init(ctx_body);

    if (unlikely(g_async_ctrl.kz_ctx[g_async_ctrl.ctx_index] == NULL)) {
        while (kaesnappy_init(ctx_body) != KAE_SNAPPY_SUCC) { // 本质来说，这个初始化函数就初始化了其中的kaeConfig，其他是没有的，所以在外面要赋值
            struct timespec timeout;
            if (enter_polling == 0) {
                get_time_out_spec(&timeout, &polling_timeout_10us);
                enter_polling = 1;
            }

            // 如果发生超时则提前退出，到polling阶段再处理切软算
            if (unlikely(*g_async_ctrl.stop_flag != 0 || check_time_out(&timeout))) {
                return KAE_SNAPPY_INIT_FAIL;
            }

            (void)kaesnappy_async_compress_polling(1);
            // 如果本线程已经idle，则使用之前已经申请到的kz_ctx
            if (g_async_ctrl.cur_num_in_comp == 0 && g_async_ctrl.kz_ctx[0] != NULL) {
                g_async_ctrl.ctx_index = 0;
                ctx_body->kaeConfig = (uintptr_t)g_async_ctrl.kz_ctx[g_async_ctrl.ctx_index];
            }
        }
        g_async_ctrl.kz_ctx[g_async_ctrl.ctx_index] = (kaesnappy_ctx_t *)ctx_body->kaeConfig;
    } else {
        while (kaesnappy_async_is_thread_do_comp_full()) {
            (void)kaesnappy_async_compress_polling(1);
            // 此分支不需要超时判断，kaesnappy_async_compress_polling本身具有超时机制，如果硬件超时，会主动释放资源
            if (unlikely(*g_async_ctrl.stop_flag != 0)) {
                return KAE_SNAPPY_INIT_FAIL;
            }

            if (g_async_ctrl.kz_ctx[g_async_ctrl.ctx_index] == NULL) {
                // polling 过程可能发生超时，kz资源可能已经释放
                return KAE_SNAPPY_INIT_FAIL;
            }
        }
        kaesnappy_init_ctx(g_async_ctrl.kz_ctx[g_async_ctrl.ctx_index]);
        ctx_body->kaeConfig = (uintptr_t)g_async_ctrl.kz_ctx[g_async_ctrl.ctx_index];
    }

    g_async_ctrl.ctx_index = (g_async_ctrl.ctx_index + 1) % MAX_NUM_IN_COMP;
    g_async_ctrl.cur_num_in_comp++;
    ctx_body->kaeInited = 1;
    return KAE_SNAPPY_SUCC;
}

void kaesnappy_ctx_clear(void)
{
    for (int i = 0; i < MAX_NUM_IN_COMP; i++) {
        if (g_async_ctrl.kz_ctx[i] != NULL) {
            kaesnappy_free_ctx(g_async_ctrl.kz_ctx[i]);
            g_async_ctrl.kz_ctx[i] = NULL;
        }
    }
}

static int kaesnappy_send_async_compress(struct kaesnappy_async_req *req)
{
    int ret;
    // 1.kae上下文初始化函数调用
    ret = kaesnappy_async_init_ctx(&req->zc);
    if (unlikely(ret != KAE_SNAPPY_SUCC)) {
        US_ERR("Get kae hw ctx failed!\n");
        return ret;
    }
    size_t compress_size = req->src_size - MFLIMIT;
    ret = kaesnappy_compress_async_impl(&req->zc, req->src, compress_size, (void *)req);
    if (unlikely(ret != KAE_SNAPPY_SUCC)) {
        kaesnappy_find_and_free_kz_ctx((kaesnappy_ctx_t *)req->zc.kaeConfig);
        g_async_ctrl.ctx_index = (g_async_ctrl.ctx_index + MAX_NUM_IN_COMP - 1) % MAX_NUM_IN_COMP;
        g_async_ctrl.cur_num_in_comp--;
        req->zc.kaeConfig = 0;
        US_ERR("Send compress cmd to kae hw failed! status %d\n", ret);
        return ret;
    }
    return ret;
}

static int kaesnappy_async_compress_process(void *arg)
{
    struct kaesnappy_compress_ctx *compress_ctx = arg;
    struct kaesnappy_async_req *tail = NULL;

    // 转换衔接
    size_t srcSize = compress_ctx->srcSize;
    size_t dstCapacity = compress_ctx->dstCapacity;
    const void* src = compress_ctx->src;

    size_t remainingLength = srcSize; // 该值用于保存剩余的待压缩数据长度

    // 针对ZSTD的Snappy的matchlength转换定义的数据结构
    US_DEBUG("INPUTSIZE:%ld, dstCapacity:%ld, maxOutputSize:%ld.", compress_ctx->srcSize, dstCapacity, compress_ctx->dstCapacity);
    // 针对ZSTD 128K remaining会覆盖CTX的问题进行的拆分(具体按64K切分，对于末尾的literal，进行src前移，放到下一轮再压)
    int idx = 0;
    while (remainingLength) {
        US_DEBUG("remainingLength:%ld, hardware:%d\n", remainingLength, HARDWARE_BLOCK_SIZE);
        struct kaesnappy_async_req *req = (struct kaesnappy_async_req *)kae_malloc(sizeof(struct kaesnappy_async_req));
        if (unlikely(req == NULL)) {
            US_ERR("Alloc kaesnappy_async_req failed!\n");
            compress_ctx->status = KAE_SNAPPY_ALLOC_FAIL;
            if (compress_ctx->req_list) {
                tail->last = 1;
                // 有已经下发的req命令，这里不能返回失败，要统一走回收流程
                return KAE_SNAPPY_SUCC;
            } else {
                return KAE_SNAPPY_ALLOC_FAIL;
            }
        }
        req->src = src;
        req->idx = idx;
        req->special_flag = 0;
        req->last = 0;
        req->done = 0;
        req->compress_ctx = compress_ctx;
        req->next = NULL;
        // 最后一块实际下发给芯片的长度是 src_size - MFLIMIT
        if (remainingLength > HARDWARE_BLOCK_SIZE + MFLIMIT) {
            // part1.基于KAE接口进行硬化压缩
            req->src_size = HARDWARE_BLOCK_SIZE;
            remainingLength -= HARDWARE_BLOCK_SIZE;
        } else {
            req->src_size = remainingLength;
            req->last = 1;
            if (remainingLength <= MFLIMIT)
                req->special_flag = 1;

            remainingLength = 0;
        }

        int ret = KAE_SNAPPY_SUCC;
        if (!req->special_flag) {
            ret = kaesnappy_send_async_compress(req);
        } else {
            // 小于12B处理，无需硬件压缩
            req->done = 1;
        }

        if (compress_ctx->req_list) {
            tail->next = req;
        } else {
            compress_ctx->req_list = req;
        }
        idx++;
        tail = req;
        if (ret != KAE_SNAPPY_SUCC) {
            req->compress_ctx->status = KAE_SNAPPY_COMP_FAIL;
            req->special_flag = 1;
            req->done = 1;
        }

        src += req->src_size;
    }

    return KAE_SNAPPY_SUCC;
}

static void kaesnappy_flush_compress(void)
{
    struct kaesnappy_compress_ctx *compress_ctx = g_async_ctrl.ctx_head;

    while (compress_ctx != NULL) {
        struct kaesnappy_async_req *req = compress_ctx->req_list;
        while (req != NULL) {
            compress_ctx->req_list = compress_ctx->req_list->next;
            free(req);
            req = compress_ctx->req_list;
        }
        g_async_ctrl.ctx_head = g_async_ctrl.ctx_head->next;
        free(compress_ctx);
        compress_ctx = g_async_ctrl.ctx_head;
    }
}

void kaesnappy_async_deinit(void)
{
    kaesnappy_flush_compress();
    kaesnappy_ctx_clear();
    kaesnappy_free_all_qps();
}

const kaesnappy_post_process_handle_t g_post_process_handle[KAESNAPPY_ASYNC_BUTT] = {
    [KAESNAPPY_ASYNC_SMALL_BLOCK] = kaesnappy_triples_rebuild,
    [KAESNAPPY_ASYNC_BLOCK] = kaesnappy_triples_rebuild_64Kblock,
};

void kaesnappy_compress_async(const void *src, void *dst,
                          snappy_async_callback callback, struct kaesnappy_result *result,
                          enum kae_snappy_async_data_format data_format, const int *ptr)
{
    struct kaesnappy_compress_ctx *compress_ctx = (struct kaesnappy_compress_ctx *)kae_malloc(sizeof(struct kaesnappy_compress_ctx));
    if (unlikely(compress_ctx == NULL)) {
        US_ERR("Alloc compress_ctx failed!\n");
        goto err_callback;
    }

    compress_ctx->dst = dst;
    compress_ctx->dstCapacity = result->dst_len;
    compress_ctx->src = src;
    compress_ctx->srcSize = result->src_size;
    compress_ctx->recv_cnt = 0;
    compress_ctx->callback = callback;
    compress_ctx->result = result;
    compress_ctx->data_format = data_format;
    compress_ctx->preferences = *ptr;
    compress_ctx->kaesnappy_post_process_handle = g_post_process_handle[data_format];
    compress_ctx->dst_len = 0;
    compress_ctx->next = NULL;
    compress_ctx->status = KAE_SNAPPY_SUCC;
    compress_ctx->req_list = NULL;
    compress_ctx->prev_last_lit_ptr = NULL;
    compress_ctx->prev_last_lit_len = 0;

    if (g_async_ctrl.ctx_head) {
        g_async_ctrl.tail->next = compress_ctx;
    } else {
        g_async_ctrl.ctx_head = compress_ctx;
    }
    g_async_ctrl.tail = compress_ctx;

    if (unlikely(kaesnappy_async_compress_process(compress_ctx) != KAE_SNAPPY_SUCC)) {
        goto free_compress_ctx;
    }

    return;

free_compress_ctx:
    g_async_ctrl.ctx_head = compress_ctx->next;
    free(compress_ctx);
    if (g_async_ctrl.ctx_head == NULL) {
        g_async_ctrl.tail = NULL;
    }

err_callback:
    result->status = KAE_SNAPPY_ALLOC_FAIL;
    result->dst_len = 0;
    callback(result);
    return;
}
