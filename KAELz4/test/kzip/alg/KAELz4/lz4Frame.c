#include "../manage.h"
#include <stdio.h>
#include <lz4.h>
#include <lz4frame.h>

static int g_custom_frameinfo_config = 0; // 是否 自定义 frameinfo 格式

// 单个 LZ4 frame 格式文件的压缩实现
static int lz4_frame_compress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    int ret;
    if (g_custom_frameinfo_config == 0) {
        ret = LZ4F_compressFrame(dst, *dst_len, src, *src_len, NULL);
    } else {
        LZ4F_preferences_t preferences = {0};
        preferences.frameInfo.blockSizeID = LZ4F_max64KB;  // 设定块大小
        preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
        preferences.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
        preferences.frameInfo.contentSize = *src_len;
        ret = LZ4F_compressFrame(dst, *dst_len, src, *src_len,  &preferences);
    }

    *dst_len = ret;  // lz4 LZ4_compress_default的返回值才是压缩后的空间大小。
    return ret > 0 ? 0 : ret;
}

// 单个 LZ4 frame 格式文件的解压实现
static int lz4_frame_decompress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
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
    int needlen = LZ4F_compressFrameBound(src_len, NULL);
    if (g_custom_frameinfo_config == 1) {
        needlen += 1024;
    }
    return  needlen;
}
// LZ4 frame 初始化
static int lz4_frame_init(struct compress_ctx *ctx) {
    return 0;
}

// LZ4 frame 算法实例
compression_algorithm_t lz4_frame_algorithm = {
    .name = "kaelz4_frame",
    .bound = lz4_frame_bound,
    .compress = lz4_frame_compress,
    .decompress = lz4_frame_decompress,
    .init = lz4_frame_init
};

// 注册 LZ4 frame 算法
void register_lz4_frame_algorithm(void)
{
    register_algorithm(&lz4_frame_algorithm);
}