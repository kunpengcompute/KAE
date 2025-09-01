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

static int lz4async_block_decompress(struct compress_session *sess, struct compress_param *params)
{
    kaelz4_param *param = &params->kaelz4_param;

    const struct kaelz4_buffer_list *src = &param->src;
    struct kaelz4_buffer_list *dst = param->dst_buf_list;
    struct kaelz4_result *result =  &param->result;
    int ret = LZ4F_decompress_async(src, dst, lz4_compress_async_callback, result, NULL);
    return ret;
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
    .async_decompress = lz4async_block_decompress,
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