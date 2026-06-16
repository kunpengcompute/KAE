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
    kaezstd_ctx_t* kaezstd_ctx = (kaezstd_ctx_t*)zc->kaeConfig;
    if (kaezstd_ctx) {
        kaezstd_ctx->zstd_data.blk_type = status;
        US_DEBUG("kaezstd set status %u", status);
    }
}

static int kaezstd_data_parsing(ZSTD_CCtx* zc, kaezstd_ctx_t* config)
{
    if (!config->zstd_data.literals_start || !config->zstd_data.sequences_start) {
        US_ERR("zstd literals or sequences start is NULL!\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    unsigned int lit_num = config->zstd_data.lit_num;
    unsigned int seq_num = config->zstd_data.seq_num;
    size_t seq_size = (size_t)seq_num * sizeof(seqDef);

    if (unlikely(lit_num > zc->seqStore.maxNbLit || seq_num > zc->seqStore.maxNbSeq)) {
        US_ERR("zstd hw output invalid, lit_num = %u, maxNbLit = %lu, seq_num = %u, maxNbSeq = %lu\n",
            lit_num, (unsigned long)zc->seqStore.maxNbLit,
            seq_num, (unsigned long)zc->seqStore.maxNbSeq);
        return KAE_ZSTD_INVAL_PARA;
    }

    memcpy(zc->seqStore.litStart, config->zstd_data.literals_start, lit_num);
    zc->seqStore.lit += lit_num;

    memcpy((unsigned char*)zc->seqStore.sequencesStart, config->zstd_data.sequences_start,
        seq_size);
    zc->seqStore.sequences += seq_num;

    if (config->zstd_data.lit_length_overflow_cnt  == 1) {
        zc->seqStore.longLengthType = ZSTD_llt_literalLength;
        zc->seqStore.longLengthPos = config->zstd_data.lit_length_overflow_pos;
    }

    // if (config->tuple.longLengthType != ZSTD_llt_none) {
    //     zc->seqStore.longLengthType = config->tuple.longLengthType;
    //     zc->seqStore.longLengthPos = config->tuple.longLengthPos;
    // }

    return KAE_ZSTD_SUCC;
}

int kaezstd_compress_v1(ZSTD_CCtx* zc, const void* src, size_t srcSize)
{
    if (zc == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    if (srcSize > COMP_BLOCK_SIZE) {
        US_ERR("compress srcSize %lu exceeds max block size %u\n", srcSize, (unsigned int)COMP_BLOCK_SIZE);
        return KAE_ZSTD_INVAL_PARA;
    }

    kaezstd_ctx_t* kaezstd_ctx = (kaezstd_ctx_t*)zc->kaeConfig;
    if (kaezstd_ctx == NULL) {
        US_ERR("compress parameter invalid\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    US_INFO("kaezstd compress srcSize : %lu", srcSize);
    kaezstd_ctx->in           = (void*)src;
    kaezstd_ctx->in_len       = (unsigned int)srcSize;
    kaezstd_ctx->out          = NULL;
    kaezstd_ctx->consumed     = 0;
    kaezstd_ctx->produced     = 0;
    kaezstd_ctx->avail_out    = KAEZIP_STREAM_CHUNK_OUT;
    kaezstd_ctx->flush = (zc->kaeFrameMode == 1) ? WCRYPTO_FINISH :
            (srcSize & 0x3) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
    kaezstd_ctx->do_comp_len = kaezstd_ctx->in_len;

    kaezstd_set_input_data(kaezstd_ctx);
    struct wcrypto_comp_op_data *op_data = &kaezstd_ctx->op_data;

    int ret = wcrypto_do_comp(kaezstd_ctx->wd_ctx, op_data, NULL);   // sync
    if (unlikely(ret < 0)) {
        US_ERR("zstd wcrypto_do_comp fail! ret = %d\n", ret);
        return ret;
    } else {
        struct wcrypto_lz77_zstd_format* zstd_data = &kaezstd_ctx->zstd_data;
        US_DEBUG("frameMode = %u, flush = %d, lit_num = %u, seq_num = %u, lit_length_overflow_cnt = %u, lit_length_overflow_pos = %u\n",
            zc->kaeFrameMode, kaezstd_ctx->flush,
            zstd_data->lit_num, zstd_data->seq_num, zstd_data->lit_length_overflow_cnt, zstd_data->lit_length_overflow_pos);
    }

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    kaezstd_get_output_data(kaezstd_ctx);
    ret = kaezstd_data_parsing(zc, kaezstd_ctx);

    return ret;
}
