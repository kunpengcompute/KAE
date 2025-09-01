#include "../manage.h"
#include "../../compress_ctx.h"
#include <stdio.h>
#include <zlib.h>
#include <kaelz4.h>
#include <kaezip.h>
static int g_windowBits = -15;

// Zlib 压缩实现
static int zlibasync_deflate_compress(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback cb, struct kaelz4_result *result)
{
    return KAEZIP_compress_async_in_session(sess, (const struct kaezip_buffer_list *)src, (struct kaezip_buffer_list *)dst, (kaezip_async_callback)cb, (struct kaezip_result *)result);
}

static int zlibasync_deflate_decompress(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback cb, struct kaelz4_result *result)
{
    int ret = KAEZIP_decompress_async_in_session(sess, (const struct kaezip_buffer_list *)src, (struct kaezip_buffer_list *)dst, (kaezip_async_callback)cb, (struct kaezip_result *)result);
    return ret;
}
// Zlib 同步解压实现
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

static int zlib_bound(int src_len) {
    return compressBound(src_len);
}
// Zlib 初始化
static int zlib_async_deflate_init(struct compress_ctx *ctx) {
    if(ctx->sess_count > 1) {
        for (int i = 0; i < ctx->sess_count; ++i) {
            if(ctx->compress_or_decompress == 1) {
                ctx->sess_array[i] = KAEZIP_create_async_compress_session(ctx->usr_map);
            } else {
                ctx->sess_array[i] = KAEZIP_create_async_decompress_session(ctx->usr_map);
            }
            if (!ctx->sess_array[i]) {
                fprintf(stderr, "Failed to create session %d\n", i);
            }
        }
    } else {
        if(ctx->compress_or_decompress == 1) {
            ctx->sess = KAEZIP_create_async_compress_session(ctx->usr_map);
        } else {
            ctx->sess = KAEZIP_create_async_decompress_session(ctx->usr_map);
        }
    }
    return 0;
}

static void zlib_async_deflate_cleanup(struct compress_ctx *ctx)
{
    if(ctx->sess_count > 1) {
        for (int i = 0; i < ctx->sess_count; ++i) {
            if (ctx->sess_array[i]) {
                KAEZIP_destroy_async_compress_session(ctx->sess_array[i]);
            }
        }
    } else {
        KAEZIP_destroy_async_compress_session(ctx->sess);
    }
}

// Zlib 算法实例
compression_algorithm_t zlibasync_block_algorithm = {
    .name = "kaezlibasync_deflate",
    .async_compress = zlibasync_deflate_compress,
    .poll = KAEZIP_async_polling_in_session,
    .bound = zlib_bound,
    .async_decompress = zlibasync_deflate_decompress,
    .decompress = zlib_decompress,
    .init = zlib_async_deflate_init,
    .cleanup = zlib_async_deflate_cleanup,
};

// 注册 Zlib 算法
void register_zlibasync_block_algorithm(void)
{
    register_algorithm(&zlibasync_block_algorithm);
}