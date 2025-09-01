#include "manage.h"
#include "compress_ctx.h"
#include <stdio.h>
#include <lz4.h>
#include "lz4Async.h"

// LZ4 压缩实现
static int lz4_compress(struct compress_param *param)
{
    int ret = LZ4_compress_default((const char *)param->src_buf + param->src_buf_offset, (char *)param->dst_buf, param->src_len, param->dst_len);
    param->dst_len = ret > 0 ? ret : 0;
    param->done = 1;
    return ret > 0 ? 0 : ret;
}

// LZ4 解压实现
static int lz4_decompress(struct compress_param *param)
{
    int ret =  LZ4_decompress_safe((const char *)param->src_buf + param->src_buf_offset, (char *)param->dst_buf, param->src_len, param->dst_len);
    param->dst_len = ret > 0 ? ret : 0;
    param->done = 1;
    return ret > 0 ? 0 : ret;
}

static int lz4_bound(int src_len) {
    return LZ4_compressBound(src_len);
}

// LZ4 初始化
static int lz4_init(struct compress_ctx *ctx) {
    return 0;
}

// LZ4 算法实例
compression_algorithm_t lz4_algorithm = {
    .name = "kaelz4",
    .bound = lz4_bound,
    .compress = lz4_compress,
    .decompress = lz4_decompress,
    .prepare_param = lz4_prepare_param_from_ctx,
    .prepare_outbuf = lz4_prepre_out_buf,
    .init = lz4_init
};

// 注册 LZ4 算法
void register_lz4_algorithm(void)
{
    register_algorithm(&lz4_algorithm);
}