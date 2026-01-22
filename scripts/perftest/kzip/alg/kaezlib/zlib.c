#include "manage.h"
#include "compress_ctx.h"
#include <stdio.h>
#include <zlib.h>
#include "zlibAsync.h"

static int g_level = 6;

// LZ4 压缩实现
static int zlib_compress(struct compress_param *param)
{
    int ret = compress2(param->dst_buf, (unsigned long *)&param->dst_len, param->src_buf, param->src_len, g_level);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:compress2 failed, ret is:%d. (dst_len = %d; src_len = %d.)\n", ret, param->dst_len, param->src_len);
    }
    param->done = 1;
    return ret > 0 ? 0 : ret;
}

// LZ4 解压实现
static int zlib_decompress(struct compress_param *param)
{
    int ret = uncompress2(param->dst_buf, (unsigned long *)&param->dst_len, param->src_buf, (unsigned long *)&param->src_len);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
    }
    param->done = 1;
    return ret > 0 ? 0 : ret;
}

static int zlib_bound(int src_len) {
    return compressBound(src_len);
}

// LZ4 初始化
static int zlib_init(struct compress_ctx *ctx) {
    return 0;
}

// LZ4 算法实例
compression_algorithm_t zlib_algorithm = {
    .name = "kaezlib",
    .bound = zlib_bound,
    .compress = zlib_compress,
    .decompress = zlib_decompress,
    .prepare_param = zlib_prepare_ctx,
    .prepare_outbuf = zlib_prepre_out_buf,
    .init = zlib_init
};

void register_zlib_algorithm(void)
{
    register_algorithm(&zlib_algorithm);
}
