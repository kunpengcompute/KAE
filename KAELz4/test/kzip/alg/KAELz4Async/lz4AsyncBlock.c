#include "../manage.h"
#include <stdio.h>
#include <lz4.h>

// LZ4 压缩实现
static int lz4async_block_compress(const unsigned char *src, unsigned char *dst, lz4_async_callback cb, struct kaelz4_result *result)
{
    int ret = LZ4_compress_async(src, dst, cb, result);
    return ret;
}

// LZ4 解压实现
static int lz4async_block_decompress(const unsigned char *src, unsigned char *dst, lz4_async_callback cb, struct kaelz4_result *result)
{
    int ret = LZ4_decompress_async(src, dst, cb, result);
    return ret;
}

static int lz4_bound(int src_len) {
    return LZ4_compressBound(src_len);
}
// LZ4 初始化
static int lz4_async_block_init() {
    printf("Initializing LZ4...\n");
    return 0;
}

// LZ4 算法实例
compression_algorithm_t lz4async_block_algorithm = {
    .name = "kaelz4async_block",
    .async_compress = lz4async_block_compress,
    .bound = lz4_bound,
    .async_decompress = lz4async_block_decompress,
    .init = lz4_async_block_init
};

// 注册 LZ4 算法
void register_lz4async_block_algorithm(void)
{
    register_algorithm(&lz4async_block_algorithm);
}