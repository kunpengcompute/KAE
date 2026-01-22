#include "manage.h"
#include "compress_ctx.h"
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <kaelz4.h>
#include <kaezip.h>
#include "delayRecord.h"

extern int g_log_level;

static void compress_async_callback(struct kaezip_result *result)
{
    if (unlikely(result->status != 0)) {
        printf("[user]回调压缩异常 : %d\n", result->status);
    }
    struct compress_param *param = (struct compress_param *)result->user_data;

    param->dst_len = result->dst_len;

    if (g_log_level == 1) {
        uint64_t end = get_ns();
        uint64_t timeonce = end - param->start_time;
        if(timeonce > 0) {
            record_latency(param->ctx->all_delays, timeonce, param->sn);
        }
    }
    param->done = 1;
    return;
}

static void comp_and_decomp_fill_buffer_list(struct kaezip_buffer_list *buf_list, size_t sge_len, size_t rem_len, void *start_addr, size_t offset)
{
    size_t tmp_offset = 0;
    unsigned int i = 0;
    unsigned int tmp_size;

    while (rem_len) {
        tmp_size = MIN(sge_len, rem_len);
        buf_list->buf[i].data = start_addr + offset + tmp_offset;
        if (((offset + tmp_offset) % HPAGE_SIZE) + tmp_size <= HPAGE_SIZE) {
            buf_list->buf[i].buf_len = tmp_size;
        } else {
            buf_list->buf[i].buf_len = HPAGE_SIZE - ((offset + tmp_offset) % HPAGE_SIZE);
        }
        tmp_offset += buf_list->buf[i].buf_len;
        rem_len -= buf_list->buf[i].buf_len;
        i++;
        buf_list->buf_num = i;
    }
}

static void comp_and_decomp_fill_src_buf(struct compress_param *param)
{
    struct compress_ctx *ctx = param->ctx;
    size_t src_len = param->src_len;
    void *start_addr = param->src_buf;
    size_t offset = param->src_buf_offset;

    kaezip_param *now_alg_params = &param->kaezip_param;

    now_alg_params->src.buf = now_alg_params->src_buf;
    now_alg_params->src.usr_data = ctx->page_info;
    unsigned int tmp_size = src_len / ctx->src_buf_num;
    comp_and_decomp_fill_buffer_list(&now_alg_params->src, tmp_size, src_len, start_addr, offset);

    param->src_len = src_len;
    now_alg_params->result.src_size = src_len;
}

static void comp_and_decomp_fill_dst_buf(struct compress_param *param)
{
    struct compress_ctx *ctx = param->ctx;
    void *start_addr = param->dst_buf;
    size_t dst_len = param->dst_len;

    kaezip_param *now_alg_params = &param->kaezip_param;

    now_alg_params->dst.buf_num = 1;
    now_alg_params->dst.buf = now_alg_params->dst_buf;
    now_alg_params->dst.buf[0].data = start_addr;
    now_alg_params->dst.buf[0].buf_len = dst_len;
    now_alg_params->tuple.buf = now_alg_params->tuple_buf;
    now_alg_params->tuple.usr_data = ctx->tuple_page_info;
    now_alg_params->result.dst_len = dst_len;

    unsigned int tmp_size = MIN(dst_len, HW_MAX_SGE_LEN);   // HW_MAX_SGE_LEN: hisi_zip约束sge len不超过8M
    comp_and_decomp_fill_buffer_list(&now_alg_params->tuple, tmp_size, dst_len, ctx->tuple_buf, ctx->tuple_buf_offset);
    ctx->tuple_buf_offset += dst_len;
    if (ctx->tuple_buf_offset > ctx->tuple_buf_len) {
        printf("ctx->tuple_buf_offset[0x%lx] > ctx->tuple_buf_len[0x%lx]\n", ctx->tuple_buf_offset, ctx->tuple_buf_len);
        exit(1);
    }
    now_alg_params->dst_buf_list = &now_alg_params->tuple;
}

// Zlib 压缩实现
static int zlibasync_deflate_compress(struct compress_session *sess, struct compress_param *params)
{
    kaezip_param *param = &params->kaezip_param;

    const struct kaezip_buffer_list *src = &param->src;
    struct kaezip_buffer_list *dst = param->dst_buf_list;
    struct kaezip_result *result =  &param->result;

    return KAEZIP_compress_async_in_session(sess->kae_sess, src, dst, compress_async_callback, result);
}

static int zlibasync_deflate_decompress(struct compress_session *sess, struct compress_param *params)
{
    kaezip_param *param = &params->kaezip_param;
    const struct kaezip_buffer_list *src =  &param->src;
    struct kaezip_buffer_list *dst = param->dst_buf_list;
    struct kaezip_result *result =  &param->result;
    int ret = KAEZIP_decompress_async_in_session(sess->kae_sess, src, dst, compress_async_callback, result);
    return ret;
}

static int zlib_bound(int src_len) {
    return compressBound(src_len);
}

// Zlib 初始化
static int zlib_async_deflate_init(struct compress_ctx *ctx) {
    iova_map_fn map_func = ctx->enable_huge_page ? get_physical_address_wrapper : NULL;
    if(ctx->sess_count > 1) {
        for (int i = 0; i < ctx->sess_count; ++i) {
            if(ctx->compress_or_decompress == 1) {
                ctx->sess_array[i].kae_sess = KAEZIP_create_async_compress_session(map_func, NULL);
            } else {
                ctx->sess_array[i].kae_sess = KAEZIP_create_async_decompress_session(map_func, NULL);
            }
            if (!ctx->sess_array[i].kae_sess) {
                fprintf(stderr, "Failed to create session %d\n", i);
            }
        }
    } else {
        if(ctx->compress_or_decompress == 1) {
            ctx->sess.kae_sess = KAEZIP_create_async_compress_session(map_func, NULL);
        } else {
            ctx->sess.kae_sess = KAEZIP_create_async_decompress_session(map_func, NULL);
        }
    }
    return 0;
}

static void zlib_async_deflate_cleanup(struct compress_ctx *ctx)
{
    if(ctx->sess_count > 1) {
        for (int i = 0; i < ctx->sess_count; ++i) {
            if (ctx->sess_array[i].kae_sess) {
                KAEZIP_destroy_async_compress_session(ctx->sess_array[i].kae_sess);
            }
        }
    } else {
        KAEZIP_destroy_async_compress_session(ctx->sess.kae_sess);
    }
}
void zlib_prepare_ctx(struct compress_ctx *ctx, struct compress_param *params)
{
    params->ibuf_crc = 0;
    params->obuf_crc = 0;

    kaezip_param *param = &params->kaezip_param;
    if (ctx->with_crc == 1) {
        param->result.ibuf_crc = &params->ibuf_crc;
        param->result.obuf_crc = &params->obuf_crc;
    } else {
        param->result.ibuf_crc = NULL;
        param->result.obuf_crc = NULL;
    }
    param->result.user_data = params;
    comp_and_decomp_fill_src_buf(params);
    comp_and_decomp_fill_dst_buf(params);
};
void zlib_prepre_out_buf(struct compress_ctx *ctx, struct compress_out_buf *out_buf, struct compress_param *params)
{
    out_buf->src_len = params->src_len;
    out_buf->len = params->dst_len;
    out_buf->sn = params->sn;
    out_buf->ibuf_crc = params->ibuf_crc;
    out_buf->obuf_crc = params->obuf_crc;
    ctx->out_total_len += params->dst_len;

    kaezip_param *param = &params->kaezip_param;

    if (ctx->is_zlib)
        out_buf->buf_addr = param->tuple.buf[0].data;
    else
        out_buf->buf_addr = param->dst.buf[0].data;
    out_buf->src = param->src.buf[0].data;
    out_buf->next = NULL;


    if (ctx->out_buf_tail) {
        ctx->out_buf_tail->next = out_buf;
    } else {
        ctx->out_buf_list = out_buf;
    }
    ctx->out_buf_tail = out_buf;
};

static void zlib_polling(struct compress_session *sess, int budget)
{
    KAEZIP_async_polling_in_session(sess->kae_sess, budget);
}

// Zlib 算法实例
compression_algorithm_t zlibasync_block_algorithm = {
    .name = "kaezlibasync_deflate",
    .alg_type = ALG_KAE_ZLIB,
    .async_compress = zlibasync_deflate_compress,
    .poll = zlib_polling,
    .bound = zlib_bound,
    .async_decompress = zlibasync_deflate_decompress,
    .prepare_param = zlib_prepare_ctx,
    .prepare_outbuf = zlib_prepre_out_buf,
    .init = zlib_async_deflate_init,
    .cleanup = zlib_async_deflate_cleanup,
};

// 注册 Zlib 算法
void register_zlibasync_block_algorithm(void)
{
    register_algorithm(&zlibasync_block_algorithm);
}
