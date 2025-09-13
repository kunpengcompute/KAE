/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2024. All rights reserved.
 * Description: contain kae compress functions
 * Author: songchao
 * Create: 2021-7-19
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "uadk/wd_alg_common.h"
#include "uadk/wd.h"
#include "uadk/wd_comp.h"
#include "uadk/uacce.h"

#include "kaesnappy_common.h"
#include "kaesnappy_config.h"
#include "kaesnappy_log.h"

void kaesnappy_setstatus_v2(SNAPPY_CCtx* zc, unsigned int status)
{
    KaeSnappyConfig *config;
    config = kaesnappy_get_config(zc);
    config->tuple.bstatus = status;
}

static int kaesnappy_data_parsing(SNAPPY_CCtx* zc, KaeSnappyConfig* config)
{
    if (config->tuple.litStart == NULL || config->tuple.sequencesStart == NULL) {
        US_ERR("config parameter invalid\n");
        return KAE_SNAPPY_INVAL_PARA;
    }

    memcpy(zc->seqStore.litStart, config->tuple.litStart, config->tuple.litlen);
    zc->seqStore.lit += config->tuple.litlen;

    memcpy((unsigned char*)zc->seqStore.sequencesStart, config->tuple.sequencesStart,
        config->tuple.seqnum*sizeof(seqDef));
    zc->seqStore.sequences += config->tuple.seqnum;

    if (config->tuple.longLengthType != SNAPPY_llt_none) {
        zc->seqStore.longLengthType = config->tuple.longLengthType;
        zc->seqStore.longLengthPos = config->tuple.longLengthPos;
    }

    return 0;
}

int kaesnappy_compress_v2(SNAPPY_CCtx* zc, const void* src, size_t srcSize)
{
    KaeSnappyConfig *config = NULL;
    int ret;

    US_INFO("KAE snappy compress, srcSize is %lu", srcSize);
    if (zc == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_SNAPPY_INVAL_PARA;
    }

    config = kaesnappy_get_config(zc);

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

    return kaesnappy_data_parsing(zc, config);
}
