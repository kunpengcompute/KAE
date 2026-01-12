#include "manage.h"
#include "compress_ctx.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <lz4.h>
#include "delayRecord.h"

extern int g_log_level;

void lz4_compress_async_callback(struct kaelz4_result *result)
{
    // printf("[user]异步 callback 了！！\n");
    if (unlikely(result->status != 0)) {
        printf("[user]回调压缩异常 : %d\n", result->status);
    }
    struct compress_param *param = (struct compress_param *)result->user_data;

    if (unlikely(param->ctx->is_lz77_mode)) {
        const char *alg_name = param->ctx->algorithm->name;
        if(strcmp(alg_name, "kaelz4async_lz77_frame") == 0) {
            if (KAELZ4_rebuild_lz77_to_frame(&param->kaelz4_param.src, &param->kaelz4_param.tuple, &param->kaelz4_param.dst, result, NULL) != 0) {
                printf("[user]KAELZ4_rebuild_lz77_to_frame : %d\n", result->status);
            }
        } else {
            if (KAELZ4_rebuild_lz77_to_block(&param->kaelz4_param.src, &param->kaelz4_param.tuple, &param->kaelz4_param.dst, result) != 0) {
                printf("[user]KAELZ4_rebuild_lz77_to_block : %d\n", result->status);
            }
        }
    }

    param->dst_len = result->dst_len;
    if ((!param->ctx->is_polling) && ((param->ctx->algorithm->async_compress != NULL && param->ctx->compress_or_decompress != 0) ||
        ((param->ctx->algorithm->async_decompress != NULL && param->ctx->compress_or_decompress == 0)))) {
        wmb();
    }

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

static void comp_and_decomp_fill_buffer_list(struct kaelz4_buffer_list *buf_list, size_t sge_len, size_t rem_len, void *start_addr, size_t offset)
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

    kaelz4_param *now_alg_params = &param->kaelz4_param;

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

    kaelz4_param *now_alg_params = &param->kaelz4_param;

    now_alg_params->dst.buf_num = 1;
    now_alg_params->dst.buf = now_alg_params->dst_buf;
    now_alg_params->dst.buf[0].data = start_addr;
    now_alg_params->dst.buf[0].buf_len = dst_len;
    now_alg_params->tuple.buf = now_alg_params->tuple_buf;
    now_alg_params->tuple.usr_data = ctx->tuple_page_info;
    now_alg_params->result.dst_len = dst_len;

    if ((ctx->is_lz77_mode && ctx->compress_or_decompress) || ctx->is_zlib) {
        if (ctx->is_lz77_mode) {
            dst_len = param->src_len * 2;
        }
        unsigned int tmp_size = MIN(dst_len, HW_MAX_SGE_LEN);   // HW_MAX_SGE_LEN: hisi_zip约束sge len不超过8M
        comp_and_decomp_fill_buffer_list(&now_alg_params->tuple, tmp_size, dst_len, ctx->tuple_buf, ctx->tuple_buf_offset);
        ctx->tuple_buf_offset += dst_len;
        if (ctx->tuple_buf_offset > ctx->tuple_buf_len) {
            printf("ctx->tuple_buf_offset[0x%lx] > ctx->tuple_buf_len[0x%lx]\n", ctx->tuple_buf_offset, ctx->tuple_buf_len);
            exit(-1);
        }
        now_alg_params->dst_buf_list = &now_alg_params->tuple;
    } else {
        now_alg_params->dst_buf_list = &now_alg_params->dst;
    }
}
// LZ4 压缩实现
static int lz4async_block_compress(struct compress_session *sess, struct compress_param *params)
{
    kaelz4_param *param = &params->kaelz4_param;

    const struct kaelz4_buffer_list *src = &param->src;
    struct kaelz4_buffer_list *dst = param->dst_buf_list;
    struct kaelz4_result *result =  &param->result;
    if (sess->kae_sess == NULL)
        return LZ4_compress_async(src, dst, lz4_compress_async_callback, result);

    return KAELZ4_compress_async_in_session(sess->kae_sess, src, dst, lz4_compress_async_callback, result);
}

// LZ4 解压实现
static int lz4async_block_decompress(struct compress_session *sess, struct compress_param *params)
{
    kaelz4_param *param = &params->kaelz4_param;
    const struct kaelz4_buffer_list *src =  &param->src;
    struct kaelz4_buffer_list *dst = param->dst_buf_list;
    struct kaelz4_result *result =  &param->result;
    int ret = LZ4_decompress_async(src, dst, lz4_compress_async_callback, result);
    return ret;
}

static int lz4_bound(int src_len)
{
    return LZ4_compressBound(src_len);
}
// LZ4 初始化
int lz4_async_init(struct compress_ctx *ctx)
{
    iova_map_fn map_func = ctx->enable_huge_page ? get_physical_address_wrapper : NULL;
    if (ctx->is_polling && ctx->compress_or_decompress) {
        ctx->sess.kae_sess = KAELZ4_create_async_compress_session(map_func, &conf_numa);
    } else {
        LZ4_async_compress_init(map_func);
    }
    return 0;
}

void lz4_async_cleanup(struct compress_ctx *ctx)
{
    if (ctx->sess.kae_sess)
        KAELZ4_destroy_async_compress_session(ctx->sess.kae_sess);
    else
        LZ4_teardown_async_compress();
}

void lz4_prepare_param_from_ctx(struct compress_ctx *ctx, struct compress_param *params)
{
    params->ibuf_crc = 0;
    params->obuf_crc = 0;

    kaelz4_param *param = &params->kaelz4_param;
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

void lz4_prepre_out_buf(struct compress_ctx *ctx, struct compress_out_buf *out_buf, struct compress_param *params)
{
    out_buf->src_len = params->src_len;
    out_buf->len = params->dst_len;
    out_buf->sn = params->sn;
    out_buf->ibuf_crc = params->ibuf_crc;
    out_buf->obuf_crc = params->obuf_crc;
    ctx->out_total_len += params->dst_len;

    kaelz4_param *param = &params->kaelz4_param;

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

void lz4_async_polling(struct compress_session *sess, int budget)
{
    KAELZ4_async_polling_in_session(sess->kae_sess, budget);
}

// LZ4 算法实例
compression_algorithm_t lz4async_block_algorithm = {
    .name = "kaelz4async_block",
    .alg_type = ALG_KAE_LZ4,
    .async_compress = lz4async_block_compress,
    .poll = lz4_async_polling,
    .bound = lz4_bound,
    .async_decompress = lz4async_block_decompress,
    .init = lz4_async_init,
    .prepare_param = lz4_prepare_param_from_ctx,
    .prepare_outbuf = lz4_prepre_out_buf,
    .cleanup = lz4_async_cleanup
};

// 注册 LZ4 算法
void register_lz4async_block_algorithm(void)
{
    register_algorithm(&lz4async_block_algorithm);
}