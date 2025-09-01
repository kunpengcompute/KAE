#include "manage.h"
#include "compress_ctx.h"
#include <stdio.h>
#include <lz4.h>
#include <lz4frame.h>
#include "lz4Async.h"

static int g_custom_frameinfo_config = 0; // 是否 自定义 frameinfo 格式

// 单个 LZ4 frame 格式文件的压缩实现
static int lz4_frame_compress(struct compress_param *param)
{
    int ret;
    if (g_custom_frameinfo_config == 0) {
        ret = LZ4F_compressFrame(param->dst_buf, param->dst_len, param->src_buf + param->src_buf_offset, param->src_len, NULL);
    } else {
        LZ4F_preferences_t preferences = {0};
        preferences.frameInfo.blockSizeID = LZ4F_max64KB;  // 设定块大小
        preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
        preferences.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
        preferences.frameInfo.contentSize = param->src_len;
        ret = LZ4F_compressFrame(param->dst_buf, param->dst_len, param->src_buf + param->src_buf_offset, param->src_len,  &preferences);
    }

    param->dst_len = ret > 0 ? ret : 0;
    param->done = 1;
    return ret > 0 ? 0 : ret;
}

// 单个 LZ4 frame 格式文件的解压实现
static int lz4_frame_decompress(struct compress_param *param)
{
    LZ4F_decompressionContext_t dctx;
    LZ4F_createDecompressionContext(&dctx, 100);
    size_t tmp_src_len = param->src_len;
    size_t tmp_dst_len = param->dst_len;
    int ret = LZ4F_decompress(dctx, param->dst_buf, &tmp_dst_len, param->src_buf + param->src_buf_offset, &tmp_src_len, NULL);
    LZ4F_freeDecompressionContext(dctx);
    param->dst_len = tmp_dst_len > 0 ? tmp_dst_len : 0;
    param->done = 1;
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
    .prepare_param = lz4_prepare_param_from_ctx,
    .prepare_outbuf = lz4_prepre_out_buf,
    .init = lz4_frame_init
};

// 注册 LZ4 frame 算法
void register_lz4_frame_algorithm(void)
{
    register_algorithm(&lz4_frame_algorithm);
}
