/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezlib nosva compress
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */
#include "kaezip_ctx.h"
#include "kaezip_async_comp.h"
#include "kaezip_log.h"
#include "kaezip_init.h"
#include "kaezip_common.h"


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
static uint32_t KAEZIPCRC32(uint32_t crc, const char *data, uint64_t len)
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

static void kaezip_compress_async_callback(struct kaezip_compress_ctx *compress_ctx, int status)
{
    struct kaezip_result *result = compress_ctx->result;
    result->status = status;
    result->dst_len = compress_ctx->dst_len;
    if (result->ibuf_crc != NULL && status == KAE_ZLIB_SUCC && compress_ctx->ibuf_checksum_flag != 1) {
        for (int i = 0; i < compress_ctx->src->buf_num; i++) {
            *result->ibuf_crc = KAEZIPCRC32(*result->ibuf_crc, compress_ctx->src->buf[i].data,
                                            compress_ctx->src->buf[i].buf_len);
        }
    }

    if (result->obuf_crc != NULL && status == KAE_ZLIB_SUCC) {
        *result->obuf_crc = KAEZIPCRC32(*result->obuf_crc, compress_ctx->dst->buf[0].data, compress_ctx->dst_len);
    }

    if (unlikely(status != KAE_ZLIB_SUCC)) {
        US_ERR("kae async compress fail! ret = %d\n", status);
    }

    compress_ctx->callback(compress_ctx->result);
}

static void kaezip_async_compress_cb(int status, void *param)
{
    struct kaezip_async_req* req = param;
    kaezip_ctx_t* kz_ctx = req->kz_ctx;
    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    if (status != WCRYPTO_STATUS_NULL && status != WCRYPTO_NEGTIVE_COMP_ERR) {
        if (status == WD_IN_EPARA) {
            req->compress_ctx->status = KAE_ZLIB_DST_BUF_OVERFLOW;
        } else {
            req->compress_ctx->status = KAE_ZLIB_COMP_FAIL;
        }
        US_ERR("kaezip_async_compress_cb status %d !\n", status);
        req->done = 1;
        return;
    }

    kaezip_set_comp_status(kz_ctx);
    if (kz_ctx->status == KAEZIP_COMP_VERIFY_ERR) {
        US_ERR("kaezip_async_compress_cb status %d !\n", status);
        req->compress_ctx->status = KAE_ZLIB_COMP_FAIL;
        req->done = 1;
        return;
    }

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    req->done = 1;
}

static int kaezip_fill_sgl_buffer(kaezip_ctx_t *kz_ctx, const struct wd_buf_list *src, struct wd_buf_list *dst)
{
    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    op_data->in_len = 0;
    kz_ctx->src_sgl = kz_ctx->src_sgl_buf;
    int ret = wd_build_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->src_sgl, src,
                 (wd_map)kz_ctx->usr_map);
    if (ret != WD_SUCCESS) {
        kz_ctx->src_sgl = NULL;
        return KAE_ZLIB_INVAL_PARA;
    }

    if (dst->buf_num) {
        kz_ctx->dst_sgl_usr = kz_ctx->dst_sgl_buf;
        ret = wd_build_sgl(kz_ctx->q_node->kae_wd_queue, kz_ctx->q_node->kae_queue_mem_pool, kz_ctx->dst_sgl_usr, dst,
                     (wd_map)kz_ctx->usr_map);
        if (ret != WD_SUCCESS) {
            kz_ctx->dst_sgl_usr = NULL;
            return KAE_ZLIB_DST_BUF_OVERFLOW;
        }
    }
    op_data->in_len += kz_ctx->do_comp_len;
    op_data->avail_out = kz_ctx->avail_out;
    op_data->flush   = kz_ctx->flush;
    op_data->alg_type = kz_ctx->comp_alg_type;
    op_data->stream_pos = WCRYPTO_COMP_STREAM_NEW;
    return KAE_ZLIB_SUCC;
}

static void kaezip_fill_flat_buffer(kaezip_ctx_t *kz_ctx, const struct wd_buf_list *src)
{
    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;

    op_data->in_len = 0;
    size_t offset = 0;
    for (int i = 0; i < src->buf_num; i++) {
        ZIP_wildCopy16((uint8_t *)op_data->in + offset, src->buf[i].data, (uint8_t *)op_data->in + offset + src->buf[i].buf_len);
        offset += src->buf[i].buf_len;
    }
    op_data->in_len += kz_ctx->do_comp_len;
    op_data->avail_out = KAEZIP_STREAM_CHUNK_OUT;
    op_data->flush   = kz_ctx->flush;
    op_data->alg_type = kz_ctx->comp_alg_type;
    op_data->stream_pos = WCRYPTO_COMP_STREAM_NEW;
}

static int kaezip_compress_async_impl(kaezip_ctx_t* kz_ctx, const struct wd_buf_list *src, struct wd_buf_list *dst, size_t srcSize, size_t dst_len, void *usr_data)
{
    int ret = KAE_ZLIB_SUCC;
    if (kz_ctx == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_ZLIB_INVAL_PARA;
    }

    US_INFO("kaezlib compress srcSize : %lu", srcSize);
    kz_ctx->in           = (void*)src;
    kz_ctx->in_len       = srcSize;
    kz_ctx->out          = NULL;
    kz_ctx->consumed     = 0;
    kz_ctx->produced     = 0;
    kz_ctx->avail_out    = dst_len;
    kz_ctx->flush = WCRYPTO_FINISH;
    kz_ctx->do_comp_len = kz_ctx->in_len;
    kz_ctx->callback = kaezip_async_compress_cb;
    kz_ctx->param = usr_data;

    if (kz_ctx->q_node->is_sgl) {
        ret = kaezip_fill_sgl_buffer(kz_ctx, src, dst);
        if (ret != KAE_ZLIB_SUCC) {
            US_ERR("compress fill sgl fail! ret:%d\n", ret);
            return ret;
        }
    } else {
        kaezip_fill_flat_buffer(kz_ctx, src);
    }

    ret = wcrypto_do_comp(kz_ctx->wd_ctx, &kz_ctx->op_data, kz_ctx);   // async
    if (ret != WD_SUCCESS) {
        US_ERR("compress do comp fail! ret:%d\n", ret);
        return KAE_ZLIB_HW_TIMEOUT_FAIL;
    }
    return KAE_ZLIB_SUCC;
}

static void kaezip_find_and_free_kz_ctx(struct kaezip_async_ctrl *ctrl, kaezip_ctx_t *kz_ctx)
{
    for (int i = 0; i < MAX_NUM_IN_COMP; i++) {
        if (ctrl->kz_ctx[i] == kz_ctx) {
            kaezip_free_ctx(ctrl->kz_ctx[i]);
            ctrl->kz_ctx[i] = NULL;
        }
    }
}


static void kaezip_do_compress_polling(struct kaezip_async_ctrl *ctrl, struct kaezip_async_req *req)
{
    if (req->kz_ctx == NULL) {
        return;
    }

    kaezip_ctx_t *kz_ctx = req->kz_ctx;
    struct wd_queue *q = kz_ctx->q_node->kae_wd_queue;

    int ret = wcrypto_comp_poll(q, 1);
    if (unlikely(ret < 0)) {
        US_ERR("poll fail! ret = %d\n", ret);
        kaezip_find_and_free_kz_ctx(ctrl, kz_ctx);
        req->compress_ctx->status = KAE_ZLIB_COMP_FAIL;
        req->done = 1;
    }
    return;
}

int kaezip_async_is_thread_do_comp_full(struct kaezip_async_ctrl *ctrl)
{
    return ctrl->cur_num_in_comp < MAX_NUM_IN_COMP ? FALSE : TRUE;
}

void kaezip_ctx_clear(struct kaezip_async_ctrl *ctrl)
{
    for (int i = 0; i < ctrl->ctx_num; i++) {
        if (ctrl->kz_ctx[i] != NULL) {
            kaezip_free_ctx(ctrl->kz_ctx[i]);
            ctrl->kz_ctx[i] = NULL;
        }
    }
}

int kaezip_async_instances_init(struct kaezip_async_ctrl **ctrl, iova_map_fn usr_map, int comp_optype, 
                                int comp_algtype, const device_config_t *config)
{
    struct kaezip_async_ctrl *new_ctrl = (struct kaezip_async_ctrl *)kae_malloc(sizeof(struct kaezip_async_ctrl));
    if (!new_ctrl)
        return KAE_ZLIB_INIT_FAIL;

    memset(new_ctrl, 0, sizeof(struct kaezip_async_ctrl));

    int is_sgl = (usr_map != NULL) ? 1 : 0;

    new_ctrl->usr_map = usr_map;
    new_ctrl->is_polling = TRUE;
    new_ctrl->config = config;
    for (int i = 0; i < MAX_NUM_IN_COMP; i++) {
        new_ctrl->kz_ctx[i] = kaezip_init_v1(kaezip_get_win_size(), is_sgl, comp_optype, comp_algtype, config);
        if (new_ctrl->kz_ctx[i] == NULL) {
            goto free_kz_ctx;
        }
        new_ctrl->kz_ctx[i]->usr_map = new_ctrl->usr_map;
        new_ctrl->ctx_num++;
    }

    *ctrl = new_ctrl;
    return KAE_ZLIB_SUCC;

free_kz_ctx:
    kaezip_ctx_clear(new_ctrl);
    free(new_ctrl);
    return KAE_ZLIB_INIT_FAIL;
}

void kaezip_async_instances_deinit(struct kaezip_async_ctrl *ctrl)
{
    kaezip_ctx_clear(ctrl);
    free(ctrl);
}

int kaezip_async_compress_polling(struct kaezip_async_ctrl *ctrl, int budget)
{
    int cnt = 0;
    struct kaezip_compress_ctx *compress_ctx = ctrl->ctx_head;

    if (compress_ctx == NULL) {
        return 0;
    }
    struct kaezip_async_req *req = compress_ctx->req_list;
    US_DEBUG("do polling. budget = %d", budget);
    while (req && cnt < budget) {
        kaezip_do_compress_polling(ctrl, req);
        if (!req->done) {
            return KAE_ZLIB_PROCESS_HW_BUSY;
        }

        int ret = -1;

        if (likely(compress_ctx->status == KAE_ZLIB_SUCC)) {
            ret = compress_ctx->kaezip_post_process_handle(req, &req->src,
                                                           compress_ctx->dst->buf[0].data + compress_ctx->dst_len,
                                                           &compress_ctx->save_info);
            if (ret < 0) {
                US_ERR("kaezip_post_process_handle err. ret=%d\n", ret);
            }
        }

        if (ret >= 0 && compress_ctx->status == KAE_ZLIB_SUCC) {
            compress_ctx->dst_len += ret;
            compress_ctx->status = KAE_ZLIB_SUCC;
        } else {
            compress_ctx->dst_len = 0;
            if (compress_ctx->status == KAE_ZLIB_SUCC) {
                compress_ctx->status = KAE_ZLIB_COMP_FAIL;
            }

            US_ERR("kae post process fail! req index %d src size 0x%lx dst size 0x%lx last %d ret = %d status %d\n",
                   req->idx, req->src_size, compress_ctx->dstCapacity, req->last, ret, compress_ctx->status);
        }

        ctrl->cur_num_in_comp--;
        ctrl->ctx_head = compress_ctx->next;
        kaezip_compress_async_callback(compress_ctx, compress_ctx->status);
        compress_ctx = ctrl->ctx_head;

        if (ctrl->ctx_head == NULL) {
            ctrl->tail = NULL;
            break;
        }
        req = compress_ctx->req_list;
        cnt++;
    }

    return cnt;
}

void kaezip_hw_timeout_handle(struct kaezip_async_ctrl *ctrl, int comp_optype, int comp_algtype)
{
    struct kaezip_compress_ctx *compress_ctx = ctrl->ctx_head;
    struct kaezip_async_req *req = NULL;
    int win_size = kaezip_get_win_size();
    int is_sgl = 1;

    while (compress_ctx != NULL) {
        req = compress_ctx->req_list;
        while (req != NULL) {
            req->compress_ctx->status = KAE_ZLIB_HW_TIMEOUT_FAIL;
            req->done = 1;
            req->kz_ctx = NULL;
            req = req->next;
        }
        compress_ctx = compress_ctx->next;
    }

    while (ctrl->ctx_head) {
        (void)kaezip_async_compress_polling(ctrl, ctrl->ctx_num);
    }

    for (int i = 0; i < ctrl->ctx_num; i++) {
        if (ctrl->kz_ctx[i] != NULL) {
            is_sgl = ctrl->kz_ctx[i]->q_node->is_sgl;
            win_size = ctrl->kz_ctx[i]->q_node->win_size;
            kaezip_free_ctx(ctrl->kz_ctx[i]);
            ctrl->kz_ctx[i] = NULL;
        }
    }

    for (int i = 0; i < ctrl->ctx_num; i++) {
        if (ctrl->kz_ctx[i] != NULL) {
            continue;
        }
        kaezip_ctx_t *kz_ctx = kaezip_init_v1(win_size, is_sgl, comp_optype, comp_algtype, ctrl->config);
        if (kz_ctx == NULL) {
            return;
        }
        ctrl->kz_ctx[i] = kz_ctx;
        ctrl->kz_ctx[i]->usr_map = ctrl->usr_map;
    }
}

static struct timespec polling_timeout_10us = { 0, 10000 };  // 10us超时

static kaezip_ctx_t *kaezip_async_init_ctx(struct kaezip_async_ctrl *ctrl, int comp_optype, int comp_algtype)
{
    int enter_polling = 0;
    kaezip_ctx_t *kz_ctx = NULL;

    if (unlikely(ctrl->kz_ctx[ctrl->ctx_index] == NULL)) {
        int is_sgl = (ctrl->usr_map != NULL) ? 1 : 0;
        kz_ctx = kaezip_init_v1(kaezip_get_win_size(), is_sgl, comp_optype, comp_algtype, ctrl->config);
        while (kz_ctx == NULL) { // 本质来说，这个初始化函数就初始化了其中的kaeConfig，其他是没有的，所以在外面要赋值
            struct timespec timeout;
            if (enter_polling == 0) {
                get_time_out_spec(&timeout, &polling_timeout_10us);
                enter_polling = 1;
            }

            // 如果发生超时则提前退出，到polling阶段再处理切软算
            if (unlikely((ctrl->stop_flag && *ctrl->stop_flag != 0) || check_time_out(&timeout))) {
                return NULL;
            }

            (void)kaezip_async_compress_polling(ctrl, 1);
            kz_ctx = kaezip_init_v1(kaezip_get_win_size(), is_sgl, comp_optype, comp_algtype, ctrl->config);
        }
        ctrl->kz_ctx[ctrl->ctx_index] = kz_ctx;
        ctrl->kz_ctx[ctrl->ctx_index]->usr_map = ctrl->usr_map;
    } else {
        while (kaezip_async_is_thread_do_comp_full(ctrl)) {
            (void)kaezip_async_compress_polling(ctrl, 1);
            // 此分支不需要超时判断，kaezlib_async_compress_polling本身具有超时机制，如果硬件超时，会主动释放资源
            if (unlikely(ctrl->stop_flag && *ctrl->stop_flag != 0)) {
                return NULL;
            }

            if (ctrl->kz_ctx[ctrl->ctx_index] == NULL) {
                // polling 过程可能发生超时，kz资源可能已经释放
                return NULL;
            }
        }
        kaezip_init_ctx(ctrl->kz_ctx[ctrl->ctx_index]);
        kz_ctx = ctrl->kz_ctx[ctrl->ctx_index];
    }

    return kz_ctx;
}

static int kaezip_send_async_compress(struct kaezip_async_ctrl *ctrl, struct kaezip_async_req *req, int comp_optype, int comp_algtype)
{
    // 1.kae上下文初始化函数调用
    req->kz_ctx = kaezip_async_init_ctx(ctrl, comp_optype, comp_algtype);
    if (unlikely(req->kz_ctx == NULL)) {
        US_ERR("Get kae hw ctx failed!\n");
        return KAE_ZLIB_INIT_FAIL;
    }
    size_t compress_size = req->src_size;
    size_t dst_len = req->dst_len;
    int ret = kaezip_compress_async_impl(req->kz_ctx, &req->src, &req->dst, compress_size, dst_len, (void *)req);
    if (unlikely(ret != KAE_ZLIB_SUCC)) {
        if (ret == KAE_ZLIB_HW_TIMEOUT_FAIL) {
            kaezip_find_and_free_kz_ctx(ctrl, req->kz_ctx);
        }
        req->kz_ctx = NULL;
        US_ERR("Send compress cmd to kae hw failed! status %d\n", ret);
        return ret;
    }
    return ret;
}

static void kaezip_fill_hw_req_dst_buf_list(struct kaezip_async_ctrl *ctrl, struct kaezip_async_req *req, 
                                            const struct kaezip_buffer_list *dst)
{
    unsigned int index = 0;

    req->dst.buf = req->dst_buffers;
    req->dst.buf_num = 0;
    req->dst.usr_data = dst->usr_data;
    req->dst_len = 0;

    while (index < dst->buf_num) {
        req->dst.buf[req->dst.buf_num].data = dst->buf[index].data;
        req->dst.buf[req->dst.buf_num].buf_len = dst->buf[index].buf_len;
        req->dst_len += req->dst.buf[req->dst.buf_num].buf_len;
        index += 1;

        req->dst.buf_num++;
    }

    if (ctrl->kz_ctx[0]->comp_type == WCRYPTO_DEFLATE && ctrl->kz_ctx[0]->comp_alg_type == WCRYPTO_ZLIB) {
        // 添加2字节的 zlib header
        ((char*)req->dst.buf[0].data)[0] = ctrl->header[0];
        ((char*)req->dst.buf[0].data)[1] = ctrl->header[1];
        void* original_ptr = req->dst.buf[0].data;
        req->dst.buf[0].data = (char*)original_ptr + 2;
        req->dst.buf[0].buf_len -= 2;
        req->dst_len -= 2;
    }
}

static void kaezip_fill_hw_req_src_buf_list(struct kaezip_async_ctrl *ctrl, struct kaezip_async_req *req, 
                                            const struct kaezip_buffer_list *src)
{
    unsigned int index = 0;

    req->src.buf = req->buffers;
    req->src.buf_num = 0;
    req->src.usr_data = src->usr_data;
    req->src_size = 0;

    while (index < src->buf_num) {
        req->src.buf[req->src.buf_num].data = src->buf[index].data;
        req->src.buf[req->src.buf_num].buf_len = src->buf[index].buf_len;
        req->src_size += req->src.buf[req->src.buf_num].buf_len;
        index += 1;

        req->src.buf_num++;
    }

    if (ctrl->kz_ctx[0]->comp_alg_type == WCRYPTO_ZLIB && ctrl->kz_ctx[0]->comp_type == WCRYPTO_INFLATE) {
        // 跳过 zlib 格式压缩文件的头部字段
        void* original_ptr = req->src.buf[0].data;
        req->src.buf[0].data = (char*)original_ptr + 2;
        req->src.buf[0].buf_len -= 2;
        req->src_size -= 2;
    }
}

static void kaezip_async_compress_process(struct kaezip_async_ctrl *ctrl, void *arg, int comp_optype, int comp_algtype)
{
    struct kaezip_compress_ctx *compress_ctx = arg;

    // 转换衔接
    size_t srcSize = compress_ctx->srcSize;
    size_t remainingLength = srcSize; // 该值用于保存剩余的待压缩数据长度

    struct kaezip_async_req *req = &compress_ctx->req;
    req->done = 0;
    req->last = 1;
    req->compress_ctx = compress_ctx;
    req->next = NULL;
    req->idx = 0;
    compress_ctx->req_list = req;
    if (unlikely(remainingLength == 0)) {
        req->kz_ctx = NULL;
        req->compress_ctx->status = KAE_ZLIB_COMP_FAIL;
        req->done = 1;
        return;
    }

    kaezip_fill_hw_req_src_buf_list(ctrl, req, compress_ctx->src);
    kaezip_fill_hw_req_dst_buf_list(ctrl, req, compress_ctx->dst);

    int ret = KAE_ZLIB_SUCC;
    ret = kaezip_send_async_compress(ctrl, req, comp_optype, comp_algtype);
    if (ret != KAE_ZLIB_SUCC) {
        req->compress_ctx->status = KAE_ZLIB_COMP_FAIL;
        req->done = 1;
    }
    return;
}
#ifdef KAE_USE_CRC32
static uint32_t extract_checksum(struct kaezip_async_req *req, unsigned int output_len)
{
    if (req == NULL || output_len < 8) {
        return 0;
    }

    struct kaezip_buffer_list *dst = req->compress_ctx->dst;
    size_t start_pos = output_len - 8;
    size_t current_pos = 0;
    size_t bytes_copied = 0;
    unsigned char result[4]; // CRC32 checksum

    for (int i = 0; i < dst->buf_num && bytes_copied < 4; i++) {
        // skip the buf without checksum data
        if (current_pos + dst->buf[i].buf_len <= start_pos) {
            current_pos += dst->buf[i].buf_len;
            continue;
        }
        // get the valid starting position of the current buffer
        size_t offset_in_buf = start_pos - current_pos;
        // get bytes can be copied in current buf
        size_t bytes_available = dst->buf[i].buf_len - offset_in_buf;
        size_t bytes_needed = 4 - bytes_copied;
        size_t bytes_to_copy = (bytes_available < bytes_needed) ? 
                              bytes_available : bytes_needed;
        // read crc32 data from dst buf
        for (size_t j = 0; j < bytes_to_copy; j++) {
            result[bytes_copied++] = ((unsigned char *)dst->buf[i].data)[offset_in_buf + j];
        }
        current_pos += dst->buf[i].buf_len;
    }
    if (bytes_copied != 4) {
        return 0;
    }
    // convert the 4 bytes to CRC32 checksum
    uint32_t checksum = ((uint32_t)result[3] << 24) |
                        ((uint32_t)result[2] << 16) |
                        ((uint32_t)result[1] << 8)  |
                         (uint32_t)result[0];
    return checksum;
}
#endif

static int kaezip_async_block_padding(struct kaezip_async_req *req, const struct wd_buf_list *source,
                                         void *dst_tmp, struct kaezip_priv_save_info *save_info)
{
    kaezip_ctx_t* kz_ctx = req->kz_ctx;

    struct wcrypto_comp_op_data *op_data = &kz_ctx->op_data;
    unsigned int output_len = op_data->produced;
    if (req->kz_ctx[0].comp_type == WCRYPTO_DEFLATE && req->kz_ctx[0].comp_alg_type == WCRYPTO_GZIP) {
        // extract checksum from dst buffer
#ifdef KAE_USE_CRC32
        if (req->compress_ctx->result->ibuf_crc != NULL) {
            *req->compress_ctx->result->ibuf_crc = extract_checksum(req, output_len);
            req->compress_ctx->ibuf_checksum_flag = 1;
        }
#endif
        // remove checksum (4 Bytes) and isize (4 Bytes) in dst buffer
        output_len -= 8;
    } else if (req->kz_ctx[0].comp_type == WCRYPTO_DEFLATE && req->kz_ctx[0].comp_alg_type == WCRYPTO_ZLIB) {
        // 2 bytes header
        output_len += 2;
    }
    return output_len;
}

const kaezip_post_process_handle_t g_post_process_handle[KAEZIP_ASYNC_BUTT] = {
    [KAEZIP_ASYNC_BLOCK] = kaezip_async_block_padding,
};

int kaezip_compress_async(struct kaezip_async_ctrl *ctrl, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                           kaezip_async_callback callback, struct kaezip_result *result,
                           enum kaezip_async_data_format data_format, int comp_optype, int comp_algtype)
{
    struct kaezip_compress_ctx *compress_ctx = &ctrl->ctx[ctrl->ctx_index];

    compress_ctx->dst = dst;
    compress_ctx->dstCapacity = result->dst_len;
    compress_ctx->src = src;
    compress_ctx->srcSize = result->src_size;
    compress_ctx->callback = callback;
    compress_ctx->result = result;
    compress_ctx->data_format = data_format;
    compress_ctx->kaezip_post_process_handle = g_post_process_handle[data_format];
    compress_ctx->dst_len = 0;
    compress_ctx->next = NULL;
    compress_ctx->status = KAE_ZLIB_SUCC;
    compress_ctx->req_list = NULL;
    compress_ctx->save_info.prev_last_lit_ptr = NULL;
    compress_ctx->save_info.prev_last_lit_len = 0;
    compress_ctx->save_info.src = src;
    compress_ctx->ibuf_checksum_flag = 0;

    if (ctrl->ctx_head) {
        ctrl->tail->next = compress_ctx;
    } else {
        ctrl->ctx_head = compress_ctx;
    }
    ctrl->tail = compress_ctx;

    kaezip_async_compress_process(ctrl, compress_ctx, comp_optype, comp_algtype);

    ctrl->ctx_index = (ctrl->ctx_index + 1) % MAX_NUM_IN_COMP;
    ctrl->cur_num_in_comp++;
    return KAE_ZLIB_SUCC;
}

void kaezip_set_zlib_header(struct kaezip_async_ctrl *ctrl, int level, int windowBits)
{
    ctrl->header = kaezip_get_fmt_header_zlib(level, windowBits);
}

static int parse_hw_id(const char *name, unsigned int *hw_id)
{
    const char *p = name + strlen(ZIP_PREFIX);
    char *endptr;
    long val;

    if (*p == '\0') {
        return -1;
    }

    errno = 0;
    val = strtol(p, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || val < 0 || val > UINT_MAX) {
        return -1;
    }
    *hw_id = (unsigned int)val;
    return 0;
}

static int compare_devs(const void *a, const void *b)
{
    unsigned int id1 = ((const struct zip_dev *)a)->hw_id;
    unsigned int id2 = ((const struct zip_dev *)b)->hw_id;
    if (id1 < id2) return -1;
    if (id1 > id2) return 1;
    return 0;
}

static int read_numa_node(const char *dev_path)
{
    char node_path[MAX_STR_SIZE + 16];
    FILE *fp;
    int numa_id = -1;

    // 构建 node_id 文件路径
    snprintf(node_path, MAX_STR_SIZE + 16, "%s/node_id", dev_path);

    fp = fopen(node_path, "r");
    if (!fp) {
        return -1;
    }

    // 读取一个整数
    if (fscanf(fp, "%d", &numa_id) != 1) {
        numa_id = -1; // 读取失败
    }

    fclose(fp);
    return numa_id;
}

int scan_hisi_zip_devices(struct zip_dev *g_devices, unsigned int *g_dev_count)
{
    DIR *dir = opendir(UACCE_CLASS_PATH);
    if (!dir) {
        fprintf(stderr, "[hisi_zip] Failed to open %s: %s\n", 
                UACCE_CLASS_PATH, strerror(errno));
        return -1;
    }

    struct zip_dev temp_devs[MAX_DEVICES];
    unsigned int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        // 跳过 "." 和 ".."
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' ||
             (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }

        // 检查是否以 "hisi_zip-" 开头
        if (strncmp(entry->d_name, ZIP_PREFIX, strlen(ZIP_PREFIX)) != 0) {
            continue;
        }

        // 解析数字 ID
        unsigned int hw_id;
        if (parse_hw_id(entry->d_name, &hw_id) != 0) {
            continue; // 跳过非法名称
        }
        temp_devs[count].hw_id = hw_id;

        // 保存设备名称及完整路径
        snprintf(temp_devs[count].dev_name, MAX_STR_SIZE, "%s", entry->d_name);
        snprintf(temp_devs[count].dev_root, MAX_STR_SIZE, "%s/%s", UACCE_CLASS_PATH, entry->d_name);

        // 保存设备 numa_id
        char dev_path[MAX_STR_SIZE];
        snprintf(dev_path, MAX_STR_SIZE, "%s/%s", UACCE_CLASS_PATH, entry->d_name);
        temp_devs[count].numa_id = read_numa_node(dev_path);

        count++;
    }

    closedir(dir);

    // 按 hw_id 升序排序
    qsort(temp_devs, count, sizeof(struct zip_dev), compare_devs);
    // 写入全局缓存
    for (unsigned int i = 0; i < count; i++) {
        g_devices[i] = temp_devs[i];
        g_devices[i].dev_id = i; // 分配逻辑 dev_id
    }
    *g_dev_count = count;
    return 0;
}