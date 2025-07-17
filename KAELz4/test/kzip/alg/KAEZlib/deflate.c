#include "../manage.h"
#include <stdio.h>
#include <zlib.h>

static int g_level = 6;
static int g_windowBits = -15;

static int zlib_bound(int src_len) {
    return compressBound(src_len);
}

// LZ4 压缩实现
static int zlib_compress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    z_stream strm;
    strm.zalloc   = (alloc_func)0;
    strm.zfree    = (free_func)0;
    strm.opaque   = (voidpf)0;
    (void)deflateInit2_(&strm, g_level, Z_DEFLATED, g_windowBits, 8, Z_DEFAULT_STRATEGY, "1.2.11", sizeof(z_stream));

    strm.next_in  = (z_const Bytef*) src;
    strm.next_out = (void *)dst;
    strm.avail_in  = *src_len;
    strm.avail_out = zlib_bound(*src_len);
    // strm.avail_out = *dst_len;
    int ret = deflate(&strm, Z_FINISH);

    *dst_len = strm.total_out;
    // deflateReset(&strm);
    (void)deflateEnd(&strm);
    if (ret < Z_OK) {
        printf("[KAE_ERR]:compress2 failed, ret is:%d. (dst_len = %d; src_len = %d.)\n", ret, *dst_len, *src_len);
    }
    return ret > 0 ? 0 : ret;
}

// LZ4 解压实现
static int zlib_decompress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    z_stream strm;
    strm.zalloc = (alloc_func)0;
    strm.zfree = (free_func)0;
    strm.opaque = (voidpf)0;
    (void)inflateInit2_(&strm, g_windowBits, "1.2.11", sizeof(z_stream));
    strm.next_in = (z_const Bytef *)src;
    strm.next_out = dst;
    strm.avail_in = *src_len;
    strm.avail_out = *dst_len;
    int ret = inflate(&strm, Z_FINISH);

    *dst_len = strm.total_out;
    // inflateReset(&strm);
    (void)inflateEnd(&strm);
    if (ret < Z_OK) {
        printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
    }
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
    .init = zlib_init
};

void register_zlib_deflate_algorithm(void)
{
    register_algorithm(&zlib_deflate_algorithm);
}