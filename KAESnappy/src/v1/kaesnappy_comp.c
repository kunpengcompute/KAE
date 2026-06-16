/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kaesnappy_ctx.h"
#include "kaesnappy_comp.h"
#include "kaesnappy_log.h"

#define KZL_MEMCPY_8(dst, src, size) vst1_u8((dst), vld1_u8(src))
#define KZL_MEMCPY_16(dst, src, size) vst1q_u8((dst), vld1q_u8(src))

static int kaesnappy_data_parsing(SNAPPY_CCtx* zc, kaesnappy_ctx_t* config)
{
    if (!config->snappy_data.literals_start || !config->snappy_data.sequences_start) {
        US_ERR("snappy literals or sequences start is NULL!\n");
        return KAE_SNAPPY_INVAL_PARA;
    }

    zc->seqStore.litStart = config->snappy_data.literals_start;
    zc->seqStore.lit = zc->seqStore.litStart;
    zc->seqStore.lit += config->snappy_data.lit_num;

    zc->seqStore.sequencesStart = config->snappy_data.sequences_start;
    zc->seqStore.sequences = zc->seqStore.sequencesStart;
    zc->seqStore.sequences += config->snappy_data.seq_num;
    return KAE_SNAPPY_SUCC;
}

int kaesnappy_compress_v1(SNAPPY_CCtx* zc, const void* src, size_t srcSize)
{
    kaesnappy_ctx_t* kaesnappy_ctx = (kaesnappy_ctx_t*)zc->kaeConfig;
    if (kaesnappy_ctx == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_SNAPPY_INVAL_PARA;
    }

    if (srcSize > COMP_BLOCK_SIZE) {
        US_ERR("compress srcSize %lu exceeds max block size %u\n", srcSize, (unsigned int)COMP_BLOCK_SIZE);
        return KAE_SNAPPY_INVAL_PARA;
    }

    US_INFO("kaesnappy compress srcSize : %lu", srcSize);
    kaesnappy_ctx->in           = (void*)src;
    kaesnappy_ctx->in_len       = (unsigned int)srcSize;
    kaesnappy_ctx->out          = NULL;
    kaesnappy_ctx->consumed     = 0;
    kaesnappy_ctx->produced     = 0;
    kaesnappy_ctx->avail_out    = KAEZIP_STREAM_CHUNK_OUT;
    kaesnappy_ctx->flush = (zc->kaeFrameMode == 1) ? WCRYPTO_FINISH :
            (srcSize & 0x3) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
    kaesnappy_ctx->do_comp_len = kaesnappy_ctx->in_len;

    kaesnappy_set_input_data(kaesnappy_ctx);
    struct wcrypto_comp_op_data *op_data = &kaesnappy_ctx->op_data;

    int ret = wcrypto_do_comp(kaesnappy_ctx->wd_ctx, op_data, NULL);   // sync
    if (unlikely(ret < 0)) {
        US_ERR("snappy wcrypto_do_comp fail! ret = %d\n", ret);
        return ret;
    } else {
        struct wcrypto_lz77_zstd_format* snappy_data = &kaesnappy_ctx->snappy_data;
        zc->seqnum = snappy_data->seq_num; // 获取硬件返回三元组数目，用于遍历解析
    }

    if (op_data->stream_pos == WCRYPTO_COMP_STREAM_NEW) {
        op_data->stream_pos = WCRYPTO_COMP_STREAM_OLD;
    }
    kaesnappy_get_output_data(kaesnappy_ctx);
    ret = kaesnappy_data_parsing(zc, kaesnappy_ctx);

    return ret;
}

#define PLATFORM_IS_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)