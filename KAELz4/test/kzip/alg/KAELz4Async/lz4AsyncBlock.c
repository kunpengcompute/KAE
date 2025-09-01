#include "../manage.h"
#include "../../compress_ctx.h"
#include <stdio.h>
#include <lz4.h>

// LZ4 压缩实现
static int lz4async_block_compress(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback cb, struct kaelz4_result *result)
{
    if (sess == NULL)
        return LZ4_compress_async(src, dst, cb, result);

    return KAELZ4_compress_async_in_session(sess, src, dst, cb, result);
}

// LZ4 解压实现
static int lz4async_block_decompress(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback cb, struct kaelz4_result *result)
{
    int ret = LZ4_decompress_async(src, dst, cb, result);
    return ret;
}

static int lz4_bound(int src_len)
{
    return LZ4_compressBound(src_len);
}
// LZ4 初始化
static int lz4_async_block_init(struct compress_ctx *ctx)
{
    if (ctx->is_polling && ctx->compress_or_decompress) {
        ctx->sess = KAELZ4_create_async_compress_session(ctx->usr_map);
    } else {
        LZ4_async_compress_init(ctx->usr_map);
    }
    return 0;
}

static void lz4_async_block_cleanup(struct compress_ctx *ctx)
{
    if (ctx->sess)
        KAELZ4_destroy_async_compress_session(ctx->sess);
    else
        LZ4_teardown_async_compress();
}

// LZ4 算法实例
compression_algorithm_t lz4async_block_algorithm = {
    .name = "kaelz4async_block",
    .async_compress = lz4async_block_compress,
    .poll = KAELZ4_async_polling_in_session,
    .bound = lz4_bound,
    .async_decompress = lz4async_block_decompress,
    .init = lz4_async_block_init,
    .cleanup = lz4_async_block_cleanup
};

// 注册 LZ4 算法
void register_lz4async_block_algorithm(void)
{
    register_algorithm(&lz4async_block_algorithm);
}