#include "../manage.h"
#include <stdio.h>
#include <zlib.h>

static int g_level = 6;

// LZ4 压缩实现
static int zlib_compress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    int ret = compress2(dst, (unsigned long *)dst_len, src, *src_len, g_level);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:compress2 failed, ret is:%d. (dst_len = %d; src_len = %d.)\n", ret, *dst_len, *src_len);
    }
    return ret > 0 ? 0 : ret;
}

// LZ4 解压实现
static int zlib_decompress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    int ret = uncompress2(dst, (unsigned long *)dst_len, src, (unsigned long *)src_len);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
    }
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
    .init = zlib_init
};

void register_zlib_algorithm(void)
{
    register_algorithm(&zlib_algorithm);
}