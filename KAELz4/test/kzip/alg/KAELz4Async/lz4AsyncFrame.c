#include "../manage.h"
#include <stdio.h>
#include <lz4.h>
#include <lz4frame.h>

static int g_has_custom_frameinfo_config = 0; // 是否 自定义 frameinfo 格式

static int lz4_async_frame_compress(const unsigned char *src, unsigned char *dst, lz4_async_callback cb, struct kaelz4_result *result)
{
    int ret;
    if (g_has_custom_frameinfo_config == 0) {
        ret = LZ4F_compressFrame_async(src, dst, cb, result, NULL);
    } else {
        // 初始化LZ4F压缩的参数
        LZ4F_preferences_t preferences = {0};
        preferences.frameInfo.blockSizeID = LZ4F_max64KB;  // 设定块大小
        preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
        preferences.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
        preferences.frameInfo.contentSize = result->src_size;
        ret = LZ4F_compressFrame_async(src, dst, cb, result, &preferences);
    }
    return ret;
}

// 单个 LZ4 frame 格式文件的解压实现
static int lz4_async_frame_decompress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    LZ4F_decompressionContext_t dctx;
    LZ4F_createDecompressionContext(&dctx, 100);
    size_t tmp_src_len = *src_len;
    size_t tmp_dst_len = *dst_len;
    int ret = LZ4F_decompress(dctx, dst, &tmp_dst_len, src, &tmp_src_len, NULL);
    LZ4F_freeDecompressionContext(dctx);
    *src_len = tmp_src_len;
    *dst_len = tmp_dst_len;
    return ret > 0 ? 0 : ret;
}
static int lz4_frame_bound(int src_len) {
    // if (g_has_custom_frameinfo_config == 1) {
    //     return LZ4F_compressFrameBound(src_len, NULL) * 1.2;
    // }
    return LZ4F_compressFrameBound(src_len, NULL);
}
// LZ4 frame 初始化
static int lz4_frame_init() {
    printf("Initializing LZ4...\n");
    return 0;
}

// LZ4 frame 算法实例
compression_algorithm_t lz4_async_frame_algorithm = {
    .name = "kaelz4async_frame",
    .bound = lz4_frame_bound,
    .async_compress = lz4_async_frame_compress,
    .decompress = lz4_async_frame_decompress,
    .init = lz4_frame_init
};

// 注册 LZ4 frame 算法
void register_lz4async_frame_algorithm(void)
{
    register_algorithm(&lz4_async_frame_algorithm);
}