#include "../manage.h"
#include <stdio.h>
#include <lz4.h>

// LZ4 压缩实现
static int lz4_compress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    int ret = LZ4_compress_default((const char *)src, (char *)dst, *src_len, *dst_len);
    *dst_len = ret;  // lz4 LZ4_compress_default的返回值才是压缩后的空间大小。
    return ret > 0 ? 0 : ret;
}

// LZ4 解压实现
static int lz4_decompress(const unsigned char *src, unsigned int *src_len, unsigned char *dst, unsigned int *dst_len)
{
    int ret =  LZ4_decompress_safe((const char *)src, (char *)dst, *src_len, *dst_len);
    *dst_len = ret;  // lz4 LZ4_decompress_safe 的返回值才是解压的空间大小。
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
    .init = lz4_init
};

// 注册 LZ4 算法
void register_lz4_algorithm(void)
{
    register_algorithm(&lz4_algorithm);
}