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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "uadk/wd_alg_common.h"
#include "uadk/wd.h"
#include "uadk/wd_comp.h"
#include "uadk/uacce.h"

#include "kaezstd_common.h"
#include "kaezstd_config.h"
#include "kaezstd_log.h"

void kaezstd_setstatus_v2(ZSTD_CCtx* zc, unsigned int status)
{
    KaeZstdConfig *config;
    config = kaezstd_get_config(zc);
    if (config)
        config->tuple.bstatus = status;
}

static int kaezstd_data_parsing(ZSTD_CCtx* zc, KaeZstdConfig* config)
{
    if (config->tuple.litStart == NULL || config->tuple.sequencesStart == NULL) {
        US_ERR("config parameter invalid\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    memcpy(zc->seqStore.litStart, config->tuple.litStart, config->tuple.litlen);
    zc->seqStore.lit += config->tuple.litlen;

    memcpy((unsigned char*)zc->seqStore.sequencesStart, config->tuple.sequencesStart,
        config->tuple.seqnum*sizeof(seqDef));
    zc->seqStore.sequences += config->tuple.seqnum;

    if (config->tuple.longLengthType != ZSTD_llt_none) {
        zc->seqStore.longLengthType = config->tuple.longLengthType;
        zc->seqStore.longLengthPos = config->tuple.longLengthPos;
    }

    return 0;
}

int kaezstd_compress_v2(ZSTD_CCtx* zc, const void* src, size_t srcSize)
{
    KaeZstdConfig *config = NULL;
    int ret;

    US_INFO("KAE zstd compress, srcSize is %lu", srcSize);
    if (zc == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    config = kaezstd_get_config(zc);

    config->req.src = (void*)src;
    config->req.src_len = srcSize;
    config->req.dst_len = REQ_DSTBUFF_LEN;
    config->req.last = (zc->kaeFrameMode == 1) ? 1 : (srcSize & 0x3) ? 1 : 0;

    ret = wd_do_comp_strm(config->sess, &(config->req));
    if (ret) {
        US_ERR("wd_do_comp_strm = %d\n", ret);
        return ret;
    } else {
        US_DEBUG("lit_num = %u, seq_num = %u, lit_length_overflow_type = %d, lit_length_overflow_pos = %u\n",
            config->tuple.litlen, config->tuple.seqnum, config->tuple.longLengthType, config->tuple.longLengthPos);
    }

    return kaezstd_data_parsing(zc, config);
}
