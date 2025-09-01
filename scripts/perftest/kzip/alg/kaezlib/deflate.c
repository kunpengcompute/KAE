#include "manage.h"
#include "compress_ctx.h"
#include <stdio.h>
#include <zlib.h>
#include "zlibAsync.h"

static int g_level = 6;
static int g_windowBits = -15;

static int zlib_bound(int src_len) {
    return compressBound(src_len);
}

// LZ4 压缩实现
static int zlib_compress(struct compress_param *param)
{
    z_stream strm;
    strm.zalloc   = (alloc_func)0;
    strm.zfree    = (free_func)0;
    strm.opaque   = (voidpf)0;
    (void)deflateInit2_(&strm, g_level, Z_DEFLATED, g_windowBits, 8, Z_DEFAULT_STRATEGY, "1.2.11", sizeof(z_stream));

    strm.next_in  = (z_const Bytef*)param->src_buf + param->src_buf_offset;
    strm.next_out = (void *)param->dst_buf;
    strm.avail_in  = param->src_len;
    strm.avail_out = param->dst_len;
    int ret = deflate(&strm, Z_FINISH);

    (void)deflateEnd(&strm);
    if (ret < Z_OK) {
        printf("[KAE_ERR]:compress2 failed, ret is:%d. (dst_len = %d; src_len = %d.)\n", ret, param->dst_len, param->src_len);
    }
    param->dst_len = strm.total_out > 0 ? strm.total_out : 0;
    param->done = 1;
    return ret > 0 ? 0 : ret;
}

// LZ4 解压实现
static int zlib_decompress(struct compress_param *param)
{
    z_stream strm;
    strm.zalloc = (alloc_func)0;
    strm.zfree = (free_func)0;
    strm.opaque = (voidpf)0;
    (void)inflateInit2_(&strm, g_windowBits, "1.2.11", sizeof(z_stream));
    strm.next_in  = (z_const Bytef*)param->src_buf + param->src_buf_offset;
    strm.next_out = (void *)param->dst_buf;
    strm.avail_in  = param->src_len;
    strm.avail_out = param->dst_len;
    int ret = inflate(&strm, Z_FINISH);

    (void)inflateEnd(&strm);
    if (ret < Z_OK) {
        printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
    }
    param->dst_len = strm.total_out > 0 ? strm.total_out : 0;
    param->done = 1;
    return ret > 0 ? 0 : ret;
}

// LZ4 初始化
static int zlib_init(struct compress_ctx *ctx) {
    return 0;
}

// LZ4 算法实例
compression_algorithm_t zlib_deflate_algorithm = {
    .name = "kaezlib_deflate",
    .bound = zlib_bound,
    .compress = zlib_compress,
    .decompress = zlib_decompress,
    .prepare_param = zlib_prepare_ctx,
    .prepare_outbuf = zlib_prepre_out_buf,
    .init = zlib_init
};

void register_zlib_deflate_algorithm(void)
{
    register_algorithm(&zlib_deflate_algorithm);
}
