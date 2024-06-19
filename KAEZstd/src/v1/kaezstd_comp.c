/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd nosva compress
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */
#include "kaezstd_ctx.h"
#include "kaezstd_comp.h"
#include "kaezstd_log.h"

void kaezstd_setstatus_v1(ZSTD_CCtx* zc, unsigned int status)
{
    kaezip_ctx_t* kaezip_ctx = (kaezip_ctx_t*)zc->kaeConfig;
    if (kaezip_ctx) {
        kaezip_ctx->zstd_data.blk_type = status;
        US_DEBUG("kaezstd set status %u", status);
    }
}

static int kaezstd_data_parsing(ZSTD_CCtx* zc, kaezip_ctx_t* config)
{
    if (!config->zstd_data.literals_start || !config->zstd_data.sequences_start) {
        US_ERR("zstd literals or sequences start is NULL!\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    memcpy(zc->seqStore.litStart, config->zstd_data.literals_start, config->zstd_data.lit_num);
    zc->seqStore.lit += config->zstd_data.lit_num;

    memcpy((unsigned char*)zc->seqStore.sequencesStart, config->zstd_data.sequences_start,
        config->zstd_data.seq_num * sizeof(seqDef));
    zc->seqStore.sequences += config->zstd_data.seq_num;

    // if (config->tuple.longLengthType != ZSTD_llt_none) {
    //     zc->seqStore.longLengthType = config->tuple.longLengthType;
    //     zc->seqStore.longLengthPos = config->tuple.longLengthPos;
    // }

    return KAE_ZSTD_SUCC;
}

int kaezstd_compress_v1(ZSTD_CCtx* zc, const void* src, size_t srcSize)
{
    kaezip_ctx_t* kaezip_ctx = (kaezip_ctx_t*)zc->kaeConfig;
    if (kaezip_ctx == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    US_DEBUG("kaezstd compress srcSize : %lu", srcSize);
    kaezip_ctx->in           = (void*)src;
    kaezip_ctx->in_len       = srcSize;
    kaezip_ctx->out          = NULL;
    kaezip_ctx->consumed     = 0;
    kaezip_ctx->produced     = 0;
    kaezip_ctx->avail_out    = KAEZIP_STREAM_CHUNK_OUT;
    kaezip_ctx->flush = (zc->kaeFrameMode == 1) ? WCRYPTO_FINISH :
            (srcSize & 0x3) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
    kaezip_ctx->do_comp_len = kaezip_ctx->in_len;

    kaezip_set_input_data(kaezip_ctx);
    struct wcrypto_comp_op_data *op_data = &kaezip_ctx->op_data;

    int ret = wcrypto_do_comp(kaezip_ctx->wd_ctx, op_data, NULL);   // sync
    if (unlikely(ret < 0)) {
        US_ERR("zstd wcrypto_do_comp fail! ret = %d\n", ret);
        return ret;
    } else {
        struct wcrypto_lz77_zstd_format* zstd_data = &kaezip_ctx->zstd_data;
        US_INFO("lit_num = %u, seq_num = %u, lit_length_overflow_cnt = %u, lit_length_overflow_pos = %u\n",
            zstd_data->lit_num, zstd_data->seq_num,
            zstd_data->lit_length_overflow_cnt, zstd_data->lit_length_overflow_pos);
    }

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    kaezip_get_output_data(kaezip_ctx);
    ret = kaezstd_data_parsing(zc, kaezip_ctx);

    return ret;
}
