#include <stdio.h>
#include <lz4.h>
#include <lz4frame.h>
#include "manage.h"
#include "compress_ctx.h"
#include "lz4Async.h"

static int g_has_custom_frameinfo_config = 0; // 是否 自定义 frameinfo 格式

static int lz4_async_frame_compress(struct compress_session *sess, struct compress_param *params)
{
    int ret;
    kaelz4_param *param = &params->kaelz4_param;

    const struct kaelz4_buffer_list *src = &param->src;
    struct kaelz4_buffer_list *dst = param->dst_buf_list;
    struct kaelz4_result *result =  &param->result;

    if (g_has_custom_frameinfo_config == 0) {
        if (sess->kae_sess)
            return KAELZ4_compress_frame_async_in_session(sess->kae_sess, src, dst, lz4_compress_async_callback, result, NULL);

        ret = LZ4F_compressFrame_async(src, dst, lz4_compress_async_callback, result, NULL);
    } else {
        // 初始化LZ4F压缩的参数
        LZ4F_preferences_t preferences = {0};
        preferences.frameInfo.blockSizeID = LZ4F_max64KB;  // 设定块大小
        preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
        preferences.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
        preferences.frameInfo.contentSize = result->src_size;
        if (sess->kae_sess)
            return KAELZ4_compress_frame_async_in_session(sess->kae_sess, src, dst, lz4_compress_async_callback, result, &preferences);

        ret = LZ4F_compressFrame_async(src, dst, lz4_compress_async_callback, result, &preferences);
    }
    return ret;
}

// 单个 LZ4 frame 格式文件的解压实现
static int lz4_async_frame_decompress(struct compress_session *sess, struct compress_param *params)
{
    kaelz4_param *param = &params->kaelz4_param;

    const struct kaelz4_buffer_list *src = &param->src;
    struct kaelz4_buffer_list *dst = param->dst_buf_list;
    struct kaelz4_result *result =  &param->result;
    int ret = LZ4F_decompress_async(src, dst, lz4_compress_async_callback, result, NULL);
    return ret;
}

static int lz4_frame_bound(int src_len) {
    return LZ4F_compressFrameBound(src_len, NULL) * 1.2;
}

// LZ4 frame 算法实例
compression_algorithm_t lz4_async_frame_algorithm = {
    .name = "kaelz4async_frame",
    .bound = lz4_frame_bound,
    .poll = lz4_async_polling,
    .async_compress = lz4_async_frame_compress,
    .async_decompress = lz4_async_frame_decompress,
    .init = lz4_async_init,
    .prepare_param = lz4_prepare_param_from_ctx,
    .prepare_outbuf = lz4_prepre_out_buf,
    .cleanup = lz4_async_cleanup
};

// 注册 LZ4 frame 算法
void register_lz4async_frame_algorithm(void)
{
    register_algorithm(&lz4_async_frame_algorithm);
}