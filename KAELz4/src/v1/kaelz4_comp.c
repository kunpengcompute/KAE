/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaelz4 nosva compress
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */
#include <lz4_accelerater.h>
#include "kaelz4_ctx.h"
#include "kaelz4_comp.h"
#include "kaelz4_log.h"
#include <xxhash.h>

__thread struct kaelz4_async_ctrl g_async_ctrl = {0};

void kaelz4_setstatus_v1(LZ4_CCtx* zc, unsigned int status)
{
    kaelz4_ctx_t* kaelz4_ctx = (kaelz4_ctx_t*)zc->kaeConfig;
    if (kaelz4_ctx) {
        kaelz4_ctx->lz4_data.blk_type = status;
        US_DEBUG("kaelz4 set status %u", status);
    }
}

static int kaelz4_data_parsing(LZ4_CCtx* zc, kaelz4_ctx_t* config)
{
    if (!config->lz4_data.literals_start || !config->lz4_data.sequences_start) {
        US_ERR("lz4 literals or sequences start is NULL!\n");
        return KAE_LZ4_INVAL_PARA;
    }

    if (config->q_node->is_sgl) {
        zc->seqStore.litStart = wd_get_first_sge_buf(config->lz4_data.literals_start);
    } else {
        zc->seqStore.litStart = config->lz4_data.literals_start;
    }
    zc->seqStore.lit = zc->seqStore.litStart;
    zc->seqStore.lit += config->lz4_data.lit_num;

    if (config->q_node->is_sgl) {
        zc->seqStore.sequencesStart = wd_get_first_sge_buf(config->lz4_data.sequences_start);
    } else {
        zc->seqStore.sequencesStart = config->lz4_data.sequences_start;
    }
    zc->seqStore.sequences = zc->seqStore.sequencesStart;
    zc->seqStore.sequences += config->lz4_data.seq_num;
    return KAE_LZ4_SUCC;
}

int kaelz4_compress_v1(LZ4_CCtx* zc, const void* src, size_t srcSize)
{
    kaelz4_ctx_t* kaelz4_ctx = (kaelz4_ctx_t*)zc->kaeConfig;
    if (kaelz4_ctx == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_LZ4_INVAL_PARA;
    }

    US_INFO("kaelz4 compress srcSize : %lu", srcSize);
    kaelz4_ctx->in           = (void*)src;
    kaelz4_ctx->in_len       = srcSize;
    kaelz4_ctx->out          = NULL;
    kaelz4_ctx->consumed     = 0;
    kaelz4_ctx->produced     = 0;
    kaelz4_ctx->avail_out    = KAEZIP_STREAM_CHUNK_OUT;
    kaelz4_ctx->flush = (zc->kaeFrameMode == 1) ? WCRYPTO_FINISH :
            (srcSize & 0x3) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
    kaelz4_ctx->do_comp_len = kaelz4_ctx->in_len;

    kaelz4_set_input_data(kaelz4_ctx);
    struct wcrypto_comp_op_data *op_data = &kaelz4_ctx->op_data;

    int ret = wcrypto_do_comp(kaelz4_ctx->wd_ctx, op_data, NULL);   // sync
    if (unlikely(ret < 0)) {
        US_ERR("lz4 wcrypto_do_comp fail! ret = %d\n", ret);
        return ret;
    } else {
        struct wcrypto_lz77_zstd_format* lz4_data = &kaelz4_ctx->lz4_data;
        zc->seqnum = lz4_data->seq_num; // 获取硬件返回三元组数目，用于遍历解析
    }

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    kaelz4_get_output_data(kaelz4_ctx);
    ret = kaelz4_data_parsing(zc, kaelz4_ctx);

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

#ifdef KAE_USE_CRC32
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
#else
#define CRC32D_64B(crc, ptr) do { \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 0)); \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 1)); \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 2)); \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 3)); \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 4)); \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 5)); \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 6)); \
    (crc) = __crc32cd((crc), *(const uint64_t *)((ptr) + 8 * 7)); \
} while (0)
#endif

#define CRC32D_64B_X4(crc, ptr) do { \
    CRC32D_64B((crc), (ptr) + 0 * 64); \
    CRC32D_64B((crc), (ptr) + 1 * 64); \
    CRC32D_64B((crc), (ptr) + 2 * 64); \
    CRC32D_64B((crc), (ptr) + 3 * 64); \
} while (0)

#ifdef KAE_USE_CRC32
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
#else
static const uint32_t table0_[256] = {
    0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4,
    0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
    0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b,
    0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
    0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b,
    0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
    0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54,
    0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
    0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a,
    0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
    0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5,
    0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
    0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45,
    0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
    0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a,
    0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
    0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48,
    0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
    0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687,
    0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
    0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927,
    0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
    0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8,
    0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
    0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096,
    0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
    0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859,
    0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
    0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9,
    0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
    0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36,
    0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
    0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c,
    0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
    0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043,
    0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
    0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3,
    0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
    0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c,
    0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
    0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652,
    0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
    0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d,
    0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
    0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d,
    0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
    0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2,
    0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
    0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530,
    0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
    0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff,
    0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
    0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f,
    0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
    0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90,
    0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
    0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee,
    0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
    0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321,
    0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
    0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81,
    0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
    0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e,
    0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351
};
#endif

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
#ifdef KAE_USE_CRC32
    *l = __crc32d(*l, LE_LOAD64(*p));
#else
    *l = __crc32cd(*l, LE_LOAD64(*p));
#endif
    *p += 8;
}

// CRC32 API接口函数
static uint32_t KAELZ4CRC32(uint32_t crc, const char *data, uint64_t len)
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

    while (targetPtr != targetPtrAlign && len > 0) {
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

static void kaelz4_compress_async_callback(struct kaelz4_compress_ctx *compress_ctx, int status)
{
    struct kaelz4_result *result = compress_ctx->result;
    result->status = status;
    result->dst_len = compress_ctx->save_info.dst_len;
    if (result->ibuf_crc != NULL && status == KAE_LZ4_SUCC && compress_ctx->data_format != KAELZ4_ASYNC_LZ77_RAW) {
        for (int i = 0; i < compress_ctx->src->buf_num; i++) {
            *result->ibuf_crc = KAELZ4CRC32(*result->ibuf_crc, compress_ctx->src->buf[i].data,
                                            compress_ctx->src->buf[i].buf_len);
        }
    }

    if (result->obuf_crc != NULL && status == KAE_LZ4_SUCC && compress_ctx->data_format != KAELZ4_ASYNC_LZ77_RAW) {
        *result->obuf_crc = KAELZ4CRC32(*result->obuf_crc, compress_ctx->dst->buf[0].data, compress_ctx->save_info.dst_len);
    }

    if (unlikely(status != KAE_LZ4_SUCC)) {
        US_ERR("kae async compress fail! ret = %d\n", status);
    }

    compress_ctx->callback(compress_ctx->result);
    free(compress_ctx);
}

static int kaelz4_triples_rebuild(struct kaelz4_async_req *req, const struct wd_buf_list *source,
                                  void *dest, struct kaelz4_priv_save_info *save_info)
{
    unsigned int cur_buf_idx = 0;
    const BYTE* ip = (const BYTE*) source->buf[0].data;
    size_t ip_buf_remain = source->buf[0].buf_len;
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

    if (req->src_size + req->src_size / 255 + 16 >= save_info->dstCapacity - save_info->dst_len) {
        *save_info->status = KAE_LZ4_DST_BUF_OVERFLOW;
        return 0;
    }

    size_t total_src_bytes = req->src_size;
    U32 seqCount = 0;
    U32 tempLiteralLength = 0;
    BYTE* token = NULL;
    U32 len = 0;

    while (seqCount < seqSum) {
        offBase = sequencesPtr->offBase + 1;
        litLength = sequencesPtr->litLength;
        mlBase = sequencesPtr->mlBase;
        sequencesPtr++;
        seqCount++;

        if (mlBase == 0) {
            tempLiteralLength += litLength + 3;
            continue;
        }

        mlBase -= 1;
        litLength += tempLiteralLength;
        tempLiteralLength = 0;

        token = op++;
        if (unlikely(litLength >= RUN_MASK)) {
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

        U32 tmp_len = litLength + mlBase + 4;
        if (likely(tmp_len < ip_buf_remain)) {
            LZ4_wildCopy16(op, ip, op + litLength);
            ip += tmp_len;
            ip_buf_remain -= tmp_len;
        } else {
            wd_wild_copy16_from_buffers(source, &cur_buf_idx, &ip, &ip_buf_remain, op, litLength);
            wd_ip_add_len(source, &cur_buf_idx, &ip, &ip_buf_remain, mlBase + 4);
        }
        op += litLength;

        LZ4_writeLE16(op, (U16)(offBase));
        op += 2;
        if (unlikely(offBase > 65535)) {
            US_ERR("Warning! offBase(%d) is larger than 64KB.\n", offBase);
            return KAE_LZ4_REBUILD_FAIL;
        }

        if (unlikely(mlBase >= ML_MASK)) {
            *token += ML_MASK;
            mlBase -= ML_MASK;
            while (mlBase >= 255) {
                *op++ = 255;
                mlBase -= 255;
            }
            *op++ = (BYTE)mlBase;
        } else {
            *token += (BYTE)(mlBase);
        }
    }

    size_t processed_bytes = 0;
    for (unsigned int i = 0; i < cur_buf_idx; ++i) {
        processed_bytes += source->buf[i].buf_len;
    }
    processed_bytes += (size_t)(ip - (const BYTE*)source->buf[cur_buf_idx].data);
    tempLiteralLength = total_src_bytes > processed_bytes ? (U32)(total_src_bytes - processed_bytes) : 0;

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
    wd_copy_from_buffers(source, &cur_buf_idx, &ip, &ip_buf_remain, op, tempLiteralLength);
    op += tempLiteralLength;

    int result = (int)(((char*)op) - ((char*)dest));
    return result;
}

// 针对场景：用户输入数据>64K且按照Block格式返回时，对各切块的尾部数据额外处理。
// 约束：分块原始数据内存连续
// 1、对于非last subblock：first new seq生成时继承prev subblock的last literal；cur subblock的尾部last literal信息更新至ctx中
// 2、对于last subblock：first new seq生成时继承prev subblock的last literal；cur subblock的尾部last literal生成last seq格式
static int kaelz4_triples_rebuild_64Kblock(struct kaelz4_async_req *req, const struct wd_buf_list *source,
                                           void *dest, struct kaelz4_priv_save_info *save_info)
{
    unsigned int cur_buf_idx = 0;
    const BYTE* ip = (const BYTE*) source->buf[0].data;
    size_t ip_buf_remain = source->buf[0].buf_len;
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
    if (req->src_size + save_info->prev_last_lit_len + (req->src_size + save_info->prev_last_lit_len) / 255 + 16 >= save_info->dstCapacity - save_info->dst_len) {
        *save_info->status = KAE_LZ4_DST_BUF_OVERFLOW;
        return 0;
    }

    size_t total_src_bytes = req->src_size;
    U32 seqCount = 0;
    U32 tempLiteralLength = 0;
    BYTE* token = NULL;
    U32 len = 0;

    // 生成first new sequence 时，继承prev subblock的last literal
    // 如果无法生成，则本分块整体作为literal，留给后续的分块的first new sequence继承
    while (seqCount < seqSum) {
        offBase = sequencesPtr->offBase + 1;
        litLength = sequencesPtr->litLength;

        mlBase = sequencesPtr->mlBase;
        sequencesPtr++;
        seqCount++;

        if (mlBase == 0) {
            tempLiteralLength += litLength + 3;
            continue;
        }

        mlBase -= 1;
        litLength += tempLiteralLength + save_info->prev_last_lit_len;
        tempLiteralLength = 0;

        token = op++;
        if (unlikely(litLength >= RUN_MASK)) {
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
        if (save_info->prev_last_lit_ptr != NULL) {
            struct kaelz4_buffer *last_buf = &save_info->src->buf[save_info->prev_last_lit_buf_index];
            size_t last_buf_remain = last_buf->data + last_buf->buf_len - save_info->prev_last_lit_ptr;
            kaelz4_wild_copy16_from_buffers(save_info->src, &save_info->prev_last_lit_buf_index,
                                            (const BYTE **)&save_info->prev_last_lit_ptr, &last_buf_remain,
                                            op, save_info->prev_last_lit_len);
            op += save_info->prev_last_lit_len;
            litLength -= save_info->prev_last_lit_len;
            save_info->prev_last_lit_ptr = NULL;
            save_info->prev_last_lit_len = 0;
        }
        U32 tmp_len = litLength + mlBase + 4;
        if (likely(tmp_len < ip_buf_remain)) {
            LZ4_wildCopy16(op, ip, op + litLength);
            ip += tmp_len;
            ip_buf_remain -= tmp_len;
        } else {
            wd_wild_copy16_from_buffers(source, &cur_buf_idx, &ip, &ip_buf_remain, op, litLength);
            wd_ip_add_len(source, &cur_buf_idx, &ip, &ip_buf_remain, mlBase + 4);
        }
        op += litLength;

        LZ4_writeLE16(op, (U16)(offBase));
        op += 2;
        if (unlikely(offBase > 65535)) { // 边界情况判断，硬件返回结果中，offBase不应该大于64KB
            US_ERR("Warning! offBase(%d) is larger than 64KB.\n", offBase);
            return KAE_LZ4_REBUILD_FAIL;
        }

        if (mlBase >= ML_MASK) {
            *token += ML_MASK;
            mlBase -= ML_MASK;
            while (mlBase >= 255) {
                *op++ = 255;
                mlBase -= 255;
            }
            *op++ = (BYTE)mlBase;
        } else {
            *token += (BYTE)(mlBase);
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
            tempLiteralLength += litLength + 3;
            continue;
        }

        mlBase -= 1;
        litLength += tempLiteralLength;
        tempLiteralLength = 0;

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

        U32 tmp_len = litLength + mlBase + 4;
        if (likely(tmp_len < ip_buf_remain)) {
            LZ4_wildCopy16(op, ip, op + litLength);
            ip += tmp_len;
            ip_buf_remain -= tmp_len;
        } else {
            wd_wild_copy16_from_buffers(source, &cur_buf_idx, &ip, &ip_buf_remain, op, litLength);
            wd_ip_add_len(source, &cur_buf_idx, &ip, &ip_buf_remain, mlBase + 4);
        }
        op += litLength;

        LZ4_writeLE16(op, (U16)(offBase));
        op += 2;
        if (unlikely(offBase > 65535)) { // 边界情况判断，硬件返回结果中，offBase不应该大于64KB
            US_ERR("Warning! offBase(%d) is larger than 64KB.\n", offBase);
            return KAE_LZ4_REBUILD_FAIL;
        }

        if (mlBase >= ML_MASK) {
            *token += ML_MASK;
            mlBase -= ML_MASK;
            while (mlBase >= 255) {
                *op++ = 255;
                mlBase -= 255;
            }
            *op++ = (BYTE)mlBase;
        } else {
            *token += (BYTE)(mlBase);
        }
    }

    size_t processed_bytes = 0;
    for (unsigned int i = 0; i < cur_buf_idx; ++i) {
        processed_bytes += source->buf[i].buf_len;
    }
    processed_bytes += (size_t)(ip - (const BYTE*)source->buf[cur_buf_idx].data);
    tempLiteralLength = total_src_bytes > processed_bytes ? (U32)(total_src_bytes - processed_bytes) : 0;

    // 尾部处理
    // 非last subblock，刷新ctx中的prev subblock literal 信息
    if (req->last != 1) {
        // 本分块不满足rebuild new seq：1)subblock完全不可压，全是literal;2)三元组全是matchlen=0。本分块作为literal留给后续分块的first new seq继承，且存在跨多个分块情况
        if (unlikely(save_info->prev_last_lit_ptr != NULL)) {
            save_info->prev_last_lit_len += tempLiteralLength;
        } else { // 本分块满足rebuild new seq:记录尾部的literal部分信息，留给后续分块的first new seq继承
            save_info->prev_last_lit_ptr = (void *)ip;
            save_info->prev_last_lit_buf_index = req->buf_start_index + cur_buf_idx;
            save_info->prev_last_lit_len = tempLiteralLength;
        }
    } else { // last subblock，生成last seq
        // 继承prev subblock的last literal
        tempLiteralLength += save_info->prev_last_lit_len;

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

        if (save_info->prev_last_lit_ptr != NULL) {
            struct kaelz4_buffer *last_buf = &save_info->src->buf[save_info->prev_last_lit_buf_index];
            size_t last_buf_remain = last_buf->data + last_buf->buf_len - save_info->prev_last_lit_ptr;
            kaelz4_wild_copy16_from_buffers(save_info->src, &save_info->prev_last_lit_buf_index,
                                            (const BYTE **)&save_info->prev_last_lit_ptr, &last_buf_remain,
                                            op, save_info->prev_last_lit_len);
            op += save_info->prev_last_lit_len;
            tempLiteralLength -= save_info->prev_last_lit_len;
            save_info->prev_last_lit_ptr = NULL;
            save_info->prev_last_lit_len = 0;
        }
        wd_copy_from_buffers(source, &cur_buf_idx, &ip, &ip_buf_remain, op, tempLiteralLength);
        op += tempLiteralLength;
    }

    int result = (int)(((char*)op) - ((char*)dest));

    return result;
}

static void kaelz4_async_compress_cb(int status, void *param)
{
    struct kaelz4_async_req* req = param;
    LZ4_CCtx* zc = &req->zc;
    kaelz4_ctx_t* kaelz4_ctx = (kaelz4_ctx_t*)zc->kaeConfig;
    struct wcrypto_comp_op_data *op_data = &kaelz4_ctx->op_data;

    if (status != WCRYPTO_STATUS_NULL) {
        if (status == WD_IN_EPARA) {
            req->compress_ctx->status = KAE_LZ4_DST_BUF_OVERFLOW;
        } else {
            req->compress_ctx->status = KAE_LZ4_COMP_FAIL;
        }
        US_ERR("kaelz4_async_compress_cb status %d !\n", status);
        req->done = 1;
        return;
    }

    struct wcrypto_lz77_zstd_format* lz4_data = &kaelz4_ctx->lz4_data;
    zc->seqnum = lz4_data->seq_num; // 获取硬件返回三元组数目，用于遍历解析
    US_DEBUG("frameMode = %u, flush = %d, lit_num = %u, seq_num = %u, lit_length_overflow_cnt = %u, lit_length_overflow_pos = %u\n",
        zc->kaeFrameMode, kaelz4_ctx->flush,
        lz4_data->lit_num, lz4_data->seq_num, lz4_data->lit_length_overflow_cnt, lz4_data->lit_length_overflow_pos);

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    kaelz4_get_output_data(kaelz4_ctx);
    int ret = kaelz4_data_parsing(zc, kaelz4_ctx);

    if (ret != KAE_LZ4_SUCC) {
        req->compress_ctx->status = KAE_LZ4_COMP_FAIL;
        req->done = 1;
        return;
    }
    req->done = 1;
}

static void kaelz4_fill_sgl_buffer(kaelz4_ctx_t *kz_ctx, const struct wd_buf_list *src, struct wd_buf_list *dst)
{
    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    op_data->in_len = 0;
    kz_ctx->src_sgl = kz_ctx->src_sgl_buf;
    wd_build_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->src_sgl, src,
                 (wd_map)kz_ctx->usr_map);

    if (dst->buf_num) {
        kz_ctx->dst_sgl_usr = kz_ctx->dst_sgl_buf;
        wd_build_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->dst_sgl_usr, dst,
                     (wd_map)kz_ctx->usr_map);
        kz_ctx->output.sequence = kz_ctx->dst_sgl_usr;
        kz_ctx->output.seq_sz = dst->buf[0].buf_len;

    } else {
        kz_ctx->output.sequence = kz_ctx->dst_sgl_kernel;
        kz_ctx->output.seq_sz = COMP_BLOCK_SIZE;
    }
    op_data->in_len += kz_ctx->do_comp_len;
    op_data->avail_out = KAEZIP_STREAM_CHUNK_OUT;
    op_data->flush   = kz_ctx->flush;
    op_data->alg_type = kz_ctx->comp_alg_type;
    op_data->stream_pos = WCRYPTO_COMP_STREAM_NEW;
}

static void kaelz4_fill_flat_buffer(kaelz4_ctx_t *kz_ctx, const struct wd_buf_list *src)
{
    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    op_data->in_len = 0;
    size_t offset = 0;
    for (int i = 0; i < src->buf_num; i++) {
        LZ4_wildCopy16((uint8_t *)op_data->in + offset, src->buf[i].data, (uint8_t *)op_data->in + offset + src->buf[i].buf_len);
        offset += src->buf[i].buf_len;
    }
    op_data->in_len += kz_ctx->do_comp_len;
    op_data->avail_out = KAEZIP_STREAM_CHUNK_OUT;
    op_data->flush   = kz_ctx->flush;
    op_data->alg_type = kz_ctx->comp_alg_type;
    op_data->stream_pos = WCRYPTO_COMP_STREAM_NEW;
}

static int kaelz4_compress_async_impl(LZ4_CCtx* zc, const struct wd_buf_list *src, struct wd_buf_list *dst, size_t srcSize, void *usr_data)
{
    kaelz4_ctx_t* kaelz4_ctx = (kaelz4_ctx_t*)zc->kaeConfig;
    if (kaelz4_ctx == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_LZ4_INVAL_PARA;
    }

    US_INFO("kaelz4 compress srcSize : %lu", srcSize);
    kaelz4_ctx->in           = (void*)src;
    kaelz4_ctx->in_len       = srcSize;
    kaelz4_ctx->out          = NULL;
    kaelz4_ctx->consumed     = 0;
    kaelz4_ctx->produced     = 0;
    kaelz4_ctx->avail_out    = KAEZIP_STREAM_CHUNK_OUT;
    kaelz4_ctx->flush = (zc->kaeFrameMode == 1) ? WCRYPTO_FINISH :
            (srcSize & 0x3) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
    kaelz4_ctx->do_comp_len = kaelz4_ctx->in_len;
    kaelz4_ctx->callback = kaelz4_async_compress_cb;
    kaelz4_ctx->param = usr_data;

    if (kaelz4_ctx->q_node->is_sgl)
        kaelz4_fill_sgl_buffer(kaelz4_ctx, src, dst);
    else
        kaelz4_fill_flat_buffer(kaelz4_ctx, src);

    return wcrypto_do_comp(kaelz4_ctx->wd_ctx, &kaelz4_ctx->op_data, kaelz4_ctx);   // async
}

static void kaelz4_find_and_free_kz_ctx(struct kaelz4_async_ctrl *ctrl, kaelz4_ctx_t *kz_ctx)
{
    if (kz_ctx->q_node->is_sgl) {
        if (kz_ctx->src_sgl) {
            wd_destory_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->src_sgl);
            kz_ctx->src_sgl = NULL;
        }
        if (kz_ctx->dst_sgl_usr) {
            wd_destory_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->dst_sgl_usr);
            kz_ctx->dst_sgl_usr = NULL;
        }
    }

    for (int i = 0; i < MAX_NUM_IN_COMP; i++) {
        if (ctrl->kz_ctx[i] == kz_ctx) {
            kaelz4_free_ctx(ctrl->kz_ctx[i]);
            ctrl->kz_ctx[i] = NULL;
        }
    }
}


static void kaelz4_do_compress_polling(struct kaelz4_async_ctrl *ctrl, struct kaelz4_async_req *req)
{
    if (req->special_flag != 0 || req->zc.kaeConfig == 0) {
        return;
    }

    kaelz4_ctx_t *kaelz4_ctx = (kaelz4_ctx_t *)req->zc.kaeConfig;
    struct wd_queue *q = kaelz4_ctx->q_node->kae_wd_queue;

    int ret = wcrypto_comp_poll(q, 1);
    if (unlikely(ret < 0)) {
        US_ERR("poll fail! ret = %d\n", ret);
        kaelz4_find_and_free_kz_ctx(ctrl, kaelz4_ctx);
        req->compress_ctx->status = KAE_LZ4_COMP_FAIL;
        req->done = 1;
    }
    return;
}

static void KAELZ4F_writeLE32 (void* dst, uint32_t value32)
{
    BYTE* const dstPtr = (BYTE*)dst;
    dstPtr[0] = (BYTE)value32;
    dstPtr[1] = (BYTE)(value32 >> 8);
    dstPtr[2] = (BYTE)(value32 >> 16);
    dstPtr[3] = (BYTE)(value32 >> 24);
}

static void KAELZ4F_writeLE64 (void* dst, uint64_t value64)
{
    BYTE* const dstPtr = (BYTE*)dst;
    dstPtr[0] = (BYTE)value64;
    dstPtr[1] = (BYTE)(value64 >> 8);
    dstPtr[2] = (BYTE)(value64 >> 16);
    dstPtr[3] = (BYTE)(value64 >> 24);
    dstPtr[4] = (BYTE)(value64 >> 32);
    dstPtr[5] = (BYTE)(value64 >> 40);
    dstPtr[6] = (BYTE)(value64 >> 48);
    dstPtr[7] = (BYTE)(value64 >> 56);
}

static int KAELZ4HeaderGen(unsigned char *dstPtr, LZ4F_frameInfo_t *frameinfo_ptr)
{
    uint32_t src_len = frameinfo_ptr->contentSize;
    uint8_t flag = 0;
    if (frameinfo_ptr->blockChecksumFlag == LZ4F_blockChecksumEnabled) {
        flag |= KAELZ4_BLOCK_CHECKSUM_FLAG;
    }
    if (frameinfo_ptr->contentChecksumFlag == LZ4F_contentChecksumEnabled) {
        flag |= KAELZ4_CONTENT_CHECKSUM_FLAG;
    }
    if (src_len) {
        flag |= KAELZ4_CONTENT_SIZE_FLAG;
    }
    int dst_len = 0;
    // MAGIC NUMBER
    KAELZ4F_writeLE32(dstPtr, KAELZ4_MAGIC_NUMBER);
    dstPtr += 4;
    dst_len += 4;
    unsigned char *headerStart = dstPtr;
    // FLG
    *dstPtr++ = (BYTE)(((KAELZ4_VERSION & 0x03) << 6)
        | ((KAELZ4_BLOCK_INDEPENDENCE_FLAG & 0x01) << 5)
        | (KAELZ4_DICTIONARY_ID_FLAG & 0x01)
        | flag);
    dst_len++;
    // BD
    *dstPtr++ = (BYTE)((KAELZ4_MAX_BLK_SIZE & 0x07) << 4);
    dst_len++;
    // CONTENT SIZE
    if (src_len) {
        KAELZ4F_writeLE64(dstPtr, src_len);
        dstPtr += 8;
        dst_len += 8;
    }
    // HEADER CRC
    *dstPtr = (unsigned char)((XXH32(headerStart, (size_t)(dstPtr - headerStart), 0) >> 8) & 0xFF);
    dstPtr++;
    dst_len++;
    return dst_len;
}

static int KAELZ4FooterGen(unsigned char* dstPtr, unsigned char *srcPtr, uint32_t src_len, uint8_t checksumEnabled)
{
    int dst_len = 4;
    // ENDMARK
    KAELZ4F_writeLE32(dstPtr, 0);
    dstPtr += 4;
    // CHECKSUM(可选)
    if (checksumEnabled) {
        uint32_t xxh = XXH32(srcPtr, src_len, 0);
        KAELZ4F_writeLE32(dstPtr, xxh);
        dstPtr += 4;
        dst_len += 4;
    }
    return dst_len;
}

static int KAELZ4BlockHeaderGen(unsigned char *dstPtr, uint32_t compressed_len,
                                uint8_t stored_block_flag)
{
    int dst_len = 4;
    if (stored_block_flag) { // 场景1. 压缩异常或负压
        KAELZ4F_writeLE32(dstPtr, compressed_len | KAELZ4_STOREDBLOCK_FLAG);
    } else {
        KAELZ4F_writeLE32(dstPtr, compressed_len);
    }
    dstPtr += 4;
    return dst_len;
}

static int KAELZ4BlockFooterGen(unsigned char *dstPtr, uint32_t compressed_len)
{
    int dst_len = 0;
    uint32_t xxh = XXH32(dstPtr-compressed_len, compressed_len, 0);
    KAELZ4F_writeLE32(dstPtr, xxh);
    dstPtr += 4;
    dst_len += 4;
    return dst_len;
}

static int kaelz4_async_frame_padding(struct kaelz4_async_req *req, const struct wd_buf_list *source,
                                      void *dst_tmp, struct kaelz4_priv_save_info *save_info)
{
    int ret = 0;
    int padding_len = 0;
    void *dst_after_frameheader = dst_tmp;
    LZ4F_frameInfo_t frameinfo_ptr = save_info->preferences.frameInfo;

    // frame模式下35为对padding大小的评估
    if (req->src_size + req->src_size / 255 + 16 + 35 >= save_info->dstCapacity - save_info->dst_len) {
        *save_info->status = KAE_LZ4_DST_BUF_OVERFLOW;
        return 0;
    }

    if (save_info->src->buf_num != 1) {
        frameinfo_ptr.contentChecksumFlag = LZ4F_noContentChecksum;
    }
    // 如果是第一个block块，添加frame头部
    if (req->idx == 0) {
        int len1 = KAELZ4HeaderGen(dst_tmp, &frameinfo_ptr);
        padding_len += len1;
        dst_after_frameheader += len1;  // 记录此时的位置
        dst_tmp += len1;                // 真实dst空间直接进行偏移
    }

    dst_tmp += 4;  // 直接往后偏移4个字节(KAELZ4BlockHeaderGen 的返回值), 预留block头的空间
    // 写入真实 block 数据
    ret = kaelz4_triples_rebuild(req, source, dst_tmp, save_info);
    if (ret < 0) {
        return ret;
    }
    uint8_t stored_block_flag = 0;
    if (ret > req->src_size) { // 负压
        size_t offset = 0;
        for (int i = 0; i < source->buf_num; i++) {
            LZ4_memcpy((uint8_t *)dst_tmp + offset, source->buf[i].data, source->buf[i].buf_len);
            offset += source->buf[i].buf_len;
        }
        ret = req->src_size;
        stored_block_flag = 1;
    }

    int bloc_checksum_enabled = 0;
    if (frameinfo_ptr.blockChecksumFlag == LZ4F_blockChecksumEnabled) {
        bloc_checksum_enabled = 1;
    }
    // 使用 block 数据块的真实长度ret，在真实block数据之前写入4字节的block头
    int len2 = KAELZ4BlockHeaderGen(dst_after_frameheader, ret, stored_block_flag);
    padding_len += len2;  // 最终总数据量增加
    dst_tmp += ret;

    if (bloc_checksum_enabled == 1) {
        // block 数据尾。如果配置有block checksum，那么就填充它，否则不填充。一般是4字节
        int len3 = KAELZ4BlockFooterGen(dst_tmp, ret);
        padding_len += len3;
        dst_tmp += len3;
    }

    // 如果是最后一个block块，添加frame尾部
    if (req->last == 1) {
        int contentChecksum = frameinfo_ptr.contentChecksumFlag;
        int len4 = KAELZ4FooterGen(dst_tmp, (unsigned char *)save_info->src->buf[0].data,
                                   save_info->src->buf[0].buf_len, contentChecksum);
        padding_len += len4;
    }

    ret += padding_len;  // 计算本次一共生成的数据总量
    return ret;
}

static int kaelz4_async_lz77_post_handle(struct kaelz4_async_req *req, const struct wd_buf_list *source,
                                         void *dst_tmp, struct kaelz4_priv_save_info *save_info)
{
    struct kaelz4_seq_result *req_result = dst_tmp;

    if (req->special_flag) {
        req_result->seq_num = 0;
    } else {
        req_result->seq_num = req->zc.seqnum;
    }

    return KAE_LZ77_SEQ_DATA_SIZE_PER_64K;
}

int kaelz4_async_is_thread_do_comp_full(struct kaelz4_async_ctrl *ctrl)
{
    return ctrl->cur_num_in_comp < MAX_NUM_IN_COMP ? FALSE : TRUE;
}

struct kaelz4_async_ctrl *kaelz4_async_init(volatile int *stop, sw_compress_fn sw_compress, sw_compress_frame_fn sw_compress_frame,
                       sw_decompress_fn sw_decompress, iova_map_fn usr_map)
{
    g_async_ctrl.stop_flag = stop;
    g_async_ctrl.sw_compress = sw_compress;
    g_async_ctrl.sw_compress_frame = sw_compress_frame;
    g_async_ctrl.sw_decompress = sw_decompress;
    g_async_ctrl.usr_map = usr_map;
    g_async_ctrl.ctx_num = MAX_NUM_IN_COMP;
    return &g_async_ctrl;
}

void kaelz4_ctx_clear(struct kaelz4_async_ctrl *ctrl)
{
    for (int i = 0; i < ctrl->ctx_num; i++) {
        if (ctrl->kz_ctx[i] != NULL) {
            kaelz4_free_ctx(ctrl->kz_ctx[i]);
            ctrl->kz_ctx[i] = NULL;
        }
    }
}

int kaelz4_async_instances_init(struct kaelz4_async_ctrl **ctrl, iova_map_fn usr_map)
{
    LZ4_CCtx ctx_body;

    struct kaelz4_async_ctrl *new_ctrl = (struct kaelz4_async_ctrl *)kae_malloc(sizeof(struct kaelz4_async_ctrl));
    if (!new_ctrl)
        return KAE_LZ4_INIT_FAIL;

    memset(new_ctrl, 0, sizeof(struct kaelz4_async_ctrl));

    int is_sgl = (usr_map != NULL) ? 1 : 0;

    new_ctrl->usr_map = usr_map;
    new_ctrl->is_polling = TRUE;
    for (int i = 0; i < MAX_NUM_IN_COMP; i++) {
        if (kaelz4_init(&ctx_body, is_sgl) != KAE_LZ4_SUCC) { // 本质来说，这个初始化函数就初始化了其中的kaeConfig，其他是没有的，所以在外面要赋值
            new_ctrl->kz_ctx[i] = NULL;
            goto free_kz_ctx;
        }
        new_ctrl->kz_ctx[i] = (kaelz4_ctx_t *)ctx_body.kaeConfig;
        new_ctrl->kz_ctx[i]->usr_map = new_ctrl->usr_map;
        new_ctrl->ctx_num++;
    }
    new_ctrl->sw_compress = LZ4_compress_default;
    new_ctrl->sw_compress_frame = (sw_compress_frame_fn)LZ4F_compressFrame;

    *ctrl = new_ctrl;
    return KAE_LZ4_SUCC;

free_kz_ctx:
    kaelz4_ctx_clear(new_ctrl);
    free(new_ctrl);
    return KAE_LZ4_INIT_FAIL;
}

static void kaelz4_flush_compress(struct kaelz4_async_ctrl *ctrl)
{
    struct kaelz4_compress_ctx *compress_ctx = ctrl->ctx_head;

    while (compress_ctx != NULL) {
        struct kaelz4_async_req *req = compress_ctx->req_list;
        while (req != NULL) {
            compress_ctx->req_list = compress_ctx->req_list->next;
            free(req);
            req = compress_ctx->req_list;
        }
        ctrl->ctx_head = ctrl->ctx_head->next;
        free(compress_ctx);
        compress_ctx = ctrl->ctx_head;
    }
}

void kaelz4_async_instances_deinit(struct kaelz4_async_ctrl *ctrl)
{
    kaelz4_flush_compress(ctrl);
    kaelz4_ctx_clear(ctrl);
    free(ctrl);
}

static int kaelz4_async_sw_compress(struct kaelz4_async_ctrl *ctrl, struct kaelz4_compress_ctx *compress_ctx)
{
    int ret = -1;
    if (compress_ctx->data_format == KAELZ4_ASYNC_FRAME && ctrl->sw_compress_frame != NULL) {
        compress_ctx->status = KAE_LZ4_SUCC;
        ret = ctrl->sw_compress_frame(compress_ctx->dst->buf[0].data, compress_ctx->save_info.dstCapacity, compress_ctx->src->buf[0].data,
                                      compress_ctx->srcSize, &compress_ctx->save_info.preferences);
    } else if (compress_ctx->data_format <= KAELZ4_ASYNC_BLOCK && ctrl->sw_compress != NULL) {
        compress_ctx->status = KAE_LZ4_SUCC;
        ret = ctrl->sw_compress(compress_ctx->src->buf[0].data, compress_ctx->dst->buf[0].data, compress_ctx->srcSize,
                                compress_ctx->save_info.dstCapacity);
    }
    ret = (ret == 0) ? KAE_LZ4_SW_RETURN_0_FAIL : ret;
    return ret;
}

int kaelz4_async_compress_polling(struct kaelz4_async_ctrl *ctrl, int budget)
{
    int cnt = 0;
    struct kaelz4_compress_ctx *compress_ctx = ctrl->ctx_head;

    if (compress_ctx == NULL) {
        return 0;
    }
    struct kaelz4_async_req *req = compress_ctx->req_list;
    US_DEBUG("do polling. budget = %d", budget);
    while (req && cnt < budget) {
        kaelz4_do_compress_polling(ctrl, req);
        if (!req->done) {
            return KAE_LZ4_PROCESS_HW_BUSY;
        }

        int ret = -1;

        if (likely(compress_ctx->status == KAE_LZ4_SUCC)) {
            ret = compress_ctx->kaelz4_post_process_handle(req, &req->src,
                                                           compress_ctx->dst->buf[0].data + compress_ctx->save_info.dst_len,
                                                           &compress_ctx->save_info);
            if (ret < 0) {
                US_ERR("kaelz4_post_process_handle err. ret=%d\n", ret);
            }
        }

        if (unlikely(ret < 0 && req->idx == 0 && req->last != 0 && req->compress_ctx->status != KAE_LZ4_HW_TIMEOUT_FAIL
                     && compress_ctx->src->buf_num == 1)) {
            US_WARN("KAELz4 async compress switch to soft");
            // 异常切软算处理
            ret = kaelz4_async_sw_compress(ctrl, compress_ctx);
        }

        if (ret >= 0 && compress_ctx->status == KAE_LZ4_SUCC) {
            compress_ctx->save_info.dst_len += ret;
            compress_ctx->status = KAE_LZ4_SUCC;
        } else {
            compress_ctx->save_info.dst_len = 0;
            if (compress_ctx->status == KAE_LZ4_SUCC) {
                compress_ctx->status = KAE_LZ4_COMP_FAIL;
            }

            US_ERR("kae post process fail! req index %d src size 0x%lx dst size 0x%lx last %d ret = %d status %d\n",
                   req->idx, req->src_size, compress_ctx->save_info.dstCapacity, req->last, ret, compress_ctx->status);
        }

        if (!req->special_flag) {
            ctrl->cur_num_in_comp--;
        }

        if (req->last) {
            ctrl->ctx_head = compress_ctx->next;
            kaelz4_compress_async_callback(compress_ctx, compress_ctx->status);
            compress_ctx = ctrl->ctx_head;
        } else {
            compress_ctx->req_list = compress_ctx->req_list->next;
        }
        free(req);

        if (ctrl->ctx_head == NULL) {
            ctrl->tail = NULL;
            break;
        }
        req = compress_ctx->req_list;
        cnt++;
    }

    return cnt;
}

void kaelz4_hw_timeout_handle(struct kaelz4_async_ctrl *ctrl)
{
    struct kaelz4_compress_ctx *compress_ctx = ctrl->ctx_head;
    struct kaelz4_async_req *req = NULL;
    int is_sgl = 1;

    while (compress_ctx != NULL) {
        req = compress_ctx->req_list;
        while (req != NULL) {
            req->compress_ctx->status = KAE_LZ4_HW_TIMEOUT_FAIL;
            req->done = 1;
            req->zc.kaeConfig = 0;
            req = req->next;
        }
        compress_ctx = compress_ctx->next;
    }

    while (ctrl->ctx_head) {
        (void)kaelz4_async_compress_polling(ctrl, ctrl->ctx_num);
    }

    for (int i = 0; i < ctrl->ctx_num; i++) {
        if (ctrl->kz_ctx[i] != NULL) {
            is_sgl = ctrl->kz_ctx[i]->q_node->is_sgl;
            kaelz4_free_ctx(ctrl->kz_ctx[i]);
            ctrl->kz_ctx[i] = NULL;
        }
    }

    LZ4_CCtx ctx_body;
    for (int i = 0; i < ctrl->ctx_num; i++) {
        if (ctrl->kz_ctx[i] != NULL) {
            continue;
        }
        if (kaelz4_init(&ctx_body, is_sgl) != KAE_LZ4_SUCC) {
            return;
        }
        ctrl->kz_ctx[i] = (kaelz4_ctx_t *)ctx_body.kaeConfig;
        ctrl->kz_ctx[i]->usr_map = ctrl->usr_map;
    }
}

static struct timespec polling_timeout_10us = { 0, 10000 };  // 10us超时

static void kaelz4_ctx_body_init(LZ4_CCtx *ctx_body)
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

static int kaelz4_async_init_ctx(struct kaelz4_async_ctrl *ctrl, LZ4_CCtx *ctx_body)
{
    int enter_polling = 0;

    kaelz4_ctx_body_init(ctx_body);

    if (unlikely(ctrl->kz_ctx[ctrl->ctx_index] == NULL)) {
        int is_sgl = (ctrl->usr_map != NULL) ? 1 : 0;
        while (kaelz4_init(ctx_body, is_sgl) != KAE_LZ4_SUCC) { // 本质来说，这个初始化函数就初始化了其中的kaeConfig，其他是没有的，所以在外面要赋值
            struct timespec timeout;
            if (enter_polling == 0) {
                get_time_out_spec(&timeout, &polling_timeout_10us);
                enter_polling = 1;
            }

            // 如果发生超时则提前退出，到polling阶段再处理切软算
            if (unlikely((ctrl->stop_flag && *ctrl->stop_flag != 0) || check_time_out(&timeout))) {
                return KAE_LZ4_INIT_FAIL;
            }

            (void)kaelz4_async_compress_polling(ctrl, 1);
            // 如果本线程已经idle，则使用之前已经申请到的kz_ctx
            if (ctrl->cur_num_in_comp == 0 && ctrl->kz_ctx[0] != NULL) {
                ctrl->ctx_index = 0;
                ctx_body->kaeConfig = (uintptr_t)ctrl->kz_ctx[ctrl->ctx_index];
            }
        }
        ctrl->kz_ctx[ctrl->ctx_index] = (kaelz4_ctx_t *)ctx_body->kaeConfig;
        ctrl->kz_ctx[ctrl->ctx_index]->usr_map = ctrl->usr_map;
    } else {
        while (kaelz4_async_is_thread_do_comp_full(ctrl)) {
            (void)kaelz4_async_compress_polling(ctrl, 1);
            // 此分支不需要超时判断，kaelz4_async_compress_polling本身具有超时机制，如果硬件超时，会主动释放资源
            if (unlikely(ctrl->stop_flag && *ctrl->stop_flag != 0)) {
                return KAE_LZ4_INIT_FAIL;
            }

            if (ctrl->kz_ctx[ctrl->ctx_index] == NULL) {
                // polling 过程可能发生超时，kz资源可能已经释放
                return KAE_LZ4_INIT_FAIL;
            }
        }
        kaelz4_init_ctx(ctrl->kz_ctx[ctrl->ctx_index]);
        ctx_body->kaeConfig = (uintptr_t)ctrl->kz_ctx[ctrl->ctx_index];
    }

    ctrl->ctx_index = (ctrl->ctx_index + 1) % MAX_NUM_IN_COMP;
    ctrl->cur_num_in_comp++;
    ctx_body->kaeInited = 1;
    return KAE_LZ4_SUCC;
}

static int kaelz4_send_async_compress(struct kaelz4_async_ctrl *ctrl, struct kaelz4_async_req *req)
{
    int ret;
    // 1.kae上下文初始化函数调用
    ret = kaelz4_async_init_ctx(ctrl, &req->zc);
    if (unlikely(ret != KAE_LZ4_SUCC)) {
        US_ERR("Get kae hw ctx failed!\n");
        return ret;
    }
    size_t compress_size = req->src_size - MFLIMIT;
    ret = kaelz4_compress_async_impl(&req->zc, &req->src, &req->dst, compress_size, (void *)req);
    if (unlikely(ret != KAE_LZ4_SUCC)) {
        kaelz4_find_and_free_kz_ctx(ctrl, (kaelz4_ctx_t *)req->zc.kaeConfig);
        ctrl->ctx_index = (ctrl->ctx_index + MAX_NUM_IN_COMP - 1) % MAX_NUM_IN_COMP;
        ctrl->cur_num_in_comp--;
        req->zc.kaeConfig = 0;
        US_ERR("Send compress cmd to kae hw failed! status %d\n", ret);
        return ret;
    }
    return ret;
}

static void kaelz4_fill_hw_req_dst_buf_list(struct kaelz4_async_req *req, const struct kaelz4_buffer_list *dst,
                                            enum kae_lz4_async_data_format data_format)
{
    req->dst.buf = req->dst_buffers;
    req->dst.buf_num = 0;
    req->dst.usr_data = dst->usr_data;
    if (data_format == KAELZ4_ASYNC_LZ77_RAW) {
        req->dst.buf_num = 1;
        struct kaelz4_seq_result *seq_result = dst->buf[0].data + req->idx * KAE_LZ77_SEQ_DATA_SIZE_PER_64K;
        req->dst.buf[0].data = seq_result->seq_start;
        if (req->dst.buf[0].data >= dst->buf[0].data + dst->buf[0].buf_len) {
            req->dst.buf[0].buf_len = 0;
            return;
        }

        if (dst->buf[0].buf_len >= (req->idx + 1) * KAE_LZ77_SEQ_DATA_SIZE_PER_64K) {
            req->dst.buf[0].buf_len = KAE_LZ77_SEQ_DATA_SIZE_PER_64K - sizeof(seq_result->seq_num);
        } else {
            req->dst.buf[0].buf_len = dst->buf[0].data + dst->buf[0].buf_len - req->dst.buf[0].data;
        }
    }
    return;
}

static void kaelz4_fill_hw_req_src_buf_list(struct kaelz4_async_req *req, const struct kaelz4_buffer_list *src,
                                            unsigned int *index, size_t *offset, size_t rem_len)
{
    size_t req_size;

    req->src.buf = req->buffers;
    req->src.buf_num = 0;
    req->src_size = 0;
    req->buf_start_index = *index;
    req->src.usr_data = src->usr_data;

    // 计算当前一个下发请求可以下发的最大长度
    if (rem_len > HARDWARE_BLOCK_SIZE + MFLIMIT) {
        req_size = HARDWARE_BLOCK_SIZE;
    } else {
        req_size = rem_len;
    }

    while (req->src_size < req_size) {
        req->src.buf[req->src.buf_num].data = src->buf[*index].data + *offset;
        // buff[index] 剩余长度 > 所需长度
        if (src->buf[*index].buf_len - *offset + req->src_size > req_size) {
            req->src.buf[req->src.buf_num].buf_len = req_size - req->src_size;
            req->src_size = req_size;
            *offset += req->src.buf[req->src.buf_num].buf_len;
        } else {
            req->src.buf[req->src.buf_num].buf_len = src->buf[*index].buf_len - *offset;
            req->src_size += req->src.buf[req->src.buf_num].buf_len;
            *offset = 0;
            *index += 1;
        }

        req->src.buf_num++;
        if (req->src.buf_num >= REQ_BUFFER_MAX) {
            break;
        }
    }

    if (req->src_size <= MFLIMIT) {
        req->special_flag = 1;
    }
}

static int kaelz4_async_compress_process(struct kaelz4_async_ctrl *ctrl, void *arg)
{
    struct kaelz4_compress_ctx *compress_ctx = arg;
    struct kaelz4_async_req *tail = NULL;

    // 转换衔接
    size_t srcSize = compress_ctx->srcSize;
    unsigned int buf_index = 0;
    size_t buf_offset = 0;


    size_t remainingLength = srcSize; // 该值用于保存剩余的待压缩数据长度

    // 针对ZSTD和LZ4的matchlength转换定义的数据结构
    // 针对ZSTD 128K remaining会覆盖CTX的问题进行的拆分(具体按64K切分，对于末尾的literal，进行src前移，放到下一轮再压)
    int idx = 0;
    while (remainingLength) {
        struct kaelz4_async_req *req = (struct kaelz4_async_req *)kae_malloc(sizeof(struct kaelz4_async_req));
        if (unlikely(req == NULL)) {
            US_ERR("Alloc kaelz4_async_req failed!\n");
            compress_ctx->status = KAE_LZ4_ALLOC_FAIL;
            if (compress_ctx->req_list) {
                tail->last = 1;
                // 有已经下发的req命令，这里不能返回失败，要统一走回收流程
                return KAE_LZ4_SUCC;
            } else {
                return KAE_LZ4_ALLOC_FAIL;
            }
        }
        req->idx = idx;
        req->special_flag = 0;
        req->last = 0;
        req->done = 0;
        req->compress_ctx = compress_ctx;
        req->next = NULL;
        kaelz4_fill_hw_req_src_buf_list(req, compress_ctx->src, &buf_index, &buf_offset, remainingLength);
        kaelz4_fill_hw_req_dst_buf_list(req, compress_ctx->dst, compress_ctx->data_format);
        remainingLength -= req->src_size;
        // 最后一块实际下发给芯片的长度是 src_size - MFLIMIT
        if (remainingLength == 0) {
            req->last = 1;
        }

        int ret = KAE_LZ4_SUCC;
        if (!req->special_flag) {
            ret = kaelz4_send_async_compress(ctrl, req);
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
        if (ret != KAE_LZ4_SUCC) {
            req->compress_ctx->status = KAE_LZ4_COMP_FAIL;
            req->special_flag = 1;
            req->done = 1;
        }
    }

    return KAE_LZ4_SUCC;
}

void kaelz4_async_deinit(void)
{
    kaelz4_flush_compress(&g_async_ctrl);
    kaelz4_ctx_clear(&g_async_ctrl);
    kaelz4_free_all_qps();
}

const kaelz4_post_process_handle_t g_post_process_handle[KAELZ4_ASYNC_BUTT] = {
    [KAELZ4_ASYNC_SMALL_BLOCK] = kaelz4_triples_rebuild,
    [KAELZ4_ASYNC_BLOCK] = kaelz4_triples_rebuild_64Kblock,
    [KAELZ4_ASYNC_FRAME] = kaelz4_async_frame_padding,
    [KAELZ4_ASYNC_LZ77_RAW] = kaelz4_async_lz77_post_handle,
};

int kaelz4_compress_async(struct kaelz4_async_ctrl *ctrl, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                           lz4_async_callback callback, struct kaelz4_result *result,
                           enum kae_lz4_async_data_format data_format, const LZ4F_preferences_t *ptr)
{
    struct kaelz4_compress_ctx *compress_ctx = (struct kaelz4_compress_ctx *)kae_malloc(sizeof(struct kaelz4_compress_ctx));
    if (unlikely(compress_ctx == NULL)) {
        US_ERR("Alloc compress_ctx failed!\n");
        goto err_callback;
    }

    compress_ctx->dst = dst;
    compress_ctx->save_info.dstCapacity = result->dst_len;
    compress_ctx->src = src;
    compress_ctx->srcSize = result->src_size;
    compress_ctx->callback = callback;
    compress_ctx->result = result;
    compress_ctx->data_format = data_format;
    compress_ctx->kaelz4_post_process_handle = g_post_process_handle[data_format];
    compress_ctx->save_info.dst_len = 0;
    compress_ctx->next = NULL;
    compress_ctx->status = KAE_LZ4_SUCC;
    compress_ctx->save_info.status = &compress_ctx->status;
    compress_ctx->req_list = NULL;
    compress_ctx->save_info.preferences = *ptr;
    compress_ctx->save_info.prev_last_lit_ptr = NULL;
    compress_ctx->save_info.prev_last_lit_len = 0;
    compress_ctx->save_info.src = src;

    if (ctrl->ctx_head) {
        ctrl->tail->next = compress_ctx;
    } else {
        ctrl->ctx_head = compress_ctx;
    }
    ctrl->tail = compress_ctx;

    if (unlikely(kaelz4_async_compress_process(ctrl, compress_ctx) != KAE_LZ4_SUCC)) {
        goto free_compress_ctx;
    }

    return KAE_LZ4_SUCC;

free_compress_ctx:
    ctrl->ctx_head = compress_ctx->next;
    free(compress_ctx);
    if (ctrl->ctx_head == NULL) {
        ctrl->tail = NULL;
    }

err_callback:
    if (ctrl->is_polling) {
        return KAE_LZ4_ALLOC_FAIL;
    }
    result->status = KAE_LZ4_ALLOC_FAIL;
    result->dst_len = 0;
    callback(result);
    return KAE_LZ4_ALLOC_FAIL;
}

int kaelz4_triples_rebuild_impl(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *tuple_buf, struct kaelz4_buffer_list *dst,
                                struct kaelz4_result *result, enum kae_lz4_async_data_format data_format, const LZ4F_preferences_t *ptr)
{
    size_t remainingLength = result->src_size; // 该值用于保存剩余的待压缩数据长度
    unsigned int buf_index = 0;
    size_t buf_offset = 0;
    int idx = 0;
    struct kaelz4_seq_result *seq_result = tuple_buf->buf[0].data;
    struct kaelz4_priv_save_info save_info = {0};
    int ret;

    save_info.src = src;
    save_info.dstCapacity = dst->buf[0].buf_len;
    save_info.dst_len = 0;
    save_info.status = &result->status;
    if (ptr)
        save_info.preferences = *ptr;

    while (remainingLength) {
        struct kaelz4_async_req req;

        req.special_flag = 0;
        req.last = 0;
        req.idx = idx;
        kaelz4_fill_hw_req_src_buf_list(&req, src, &buf_index, &buf_offset, remainingLength);
        remainingLength -= req.src_size;
        // 最后一块实际下发给芯片的长度是 src_size - MFLIMIT
        if (remainingLength == 0) {
            req.last = 1;
        }
        req.zc.seqStore.sequencesStart = (seqDef *)seq_result->seq_start;
        req.zc.seqnum = seq_result->seq_num;
        ret = g_post_process_handle[data_format](&req, &req.src, dst->buf[0].data + save_info.dst_len, &save_info);
        if (ret < 0 || result->status != KAE_LZ4_SUCC) {
            result->status = KAE_LZ4_COMP_FAIL;
            return KAE_LZ4_COMP_FAIL;
        }

        idx++;
        save_info.dst_len += ret;
        seq_result = (void *)seq_result + KAE_LZ77_SEQ_DATA_SIZE_PER_64K;
    }

    if (result->ibuf_crc != NULL) {
        for (int i = 0; i < src->buf_num; i++) {
            *result->ibuf_crc = KAELZ4CRC32(*result->ibuf_crc, src->buf[i].data, src->buf[i].buf_len);
        }
    }

    if (result->obuf_crc != NULL) {
        *result->obuf_crc = KAELZ4CRC32(*result->obuf_crc, dst->buf[0].data, save_info.dst_len);
    }

    result->dst_len = save_info.dst_len;
    return KAE_LZ4_SUCC;
}
