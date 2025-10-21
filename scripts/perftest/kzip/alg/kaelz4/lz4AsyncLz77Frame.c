#include "manage.h"
#include "compress_ctx.h"
#include <stdio.h>
#include <lz4.h>
#include <lz4frame.h>
#include "lz4Async.h"

// LZ4 压缩实现
static int lz4async_block_compress(struct compress_session *sess, struct compress_param *params)
{
    kaelz4_param *param = &params->kaelz4_param;

    const struct kaelz4_buffer_list *src = &param->src;
    struct kaelz4_buffer_list *dst = param->dst_buf_list;
    struct kaelz4_result *result =  &param->result;
    return KAELZ4_compress_lz77_async_in_session(sess->kae_sess, src, dst, lz4_compress_async_callback, result);
}

// static int lz4async_block_decompress(struct compress_session *sess, struct compress_param *params)
// {
//     kaelz4_param *param = &params->kaelz4_param;

//     const struct kaelz4_buffer_list *src = &param->src;
//     struct kaelz4_buffer_list *dst = param->dst_buf_list;
//     struct kaelz4_result *result =  &param->result;
//     int ret = LZ4F_decompress_async(src, dst, lz4_compress_async_callback, result, NULL);
//     return ret;
// }

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

static int lz4_bound(int src_len) {
    return LZ4F_compressFrameBound(src_len, NULL) * 1.2;
}

// LZ4 算法实例
compression_algorithm_t lz4async_lz77_frame_algorithm = {
    .name = "kaelz4async_lz77_frame",
    .async_compress = lz4async_block_compress,
    .poll = lz4_async_polling,
    .bound = lz4_bound,
    .decompress = lz4_frame_decompress,
    .init = lz4_async_init,
    .prepare_param = lz4_prepare_param_from_ctx,
    .prepare_outbuf = lz4_prepre_out_buf,
    .cleanup = lz4_async_cleanup,
};

// 注册 LZ4 算法
void register_lz4async_lz77_frame_algorithm(void)
{
    register_algorithm(&lz4async_lz77_frame_algorithm);
}