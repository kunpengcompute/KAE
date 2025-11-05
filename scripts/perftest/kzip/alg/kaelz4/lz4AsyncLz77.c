#include "manage.h"
#include "compress_ctx.h"
#include <stdio.h>
#include <lz4.h>
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

// LZ4 解压实现
static int lz4async_block_decompress(struct compress_session *sess, struct compress_param *params)
{
    kaelz4_param *param = &params->kaelz4_param;

    const struct kaelz4_buffer_list *src = &param->src;
    struct kaelz4_buffer_list *dst = param->dst_buf_list;
    struct kaelz4_result *result =  &param->result;
    int ret = LZ4_decompress_async(src, dst, lz4_compress_async_callback, result);
    return ret;
}

static int lz4_bound(int src_len) {
    return LZ4_compressBound(src_len);
}

// LZ4 算法实例
compression_algorithm_t lz4async_lz77_algorithm = {
    .name = "kaelz4async_lz77",
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
void register_lz4async_lz77_algorithm(void)
{
    register_algorithm(&lz4async_lz77_algorithm);
}