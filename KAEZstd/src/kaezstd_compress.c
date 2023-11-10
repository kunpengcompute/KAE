/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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

#include "kaezstd_common.h"
#include "kaezstd_config.h"
#include "kaezstd_log.h"

void kaezstd_setstatus(ZSTD_CCtx* zc, unsigned int status)
{
    KaeZstdConfig *config;
    config = kaezstd_get_config(zc);
    config->tuple.bstatus = status;
}

int kaezstd_data_parsing(ZSTD_CCtx* zc, KaeZstdConfig* config)
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

int kaezstd_compress(ZSTD_CCtx* zc, const void* src, size_t srcSize)
{
    KaeZstdConfig *config = NULL;
    int ret;

    US_DEBUG("KAE zstd compress.");
    if (zc == NULL || src == NULL || srcSize == 0) {
        US_ERR("compress parameter invalid\n");
        return KAE_ZSTD_INVAL_PARA;
    }

    config = kaezstd_get_config(zc);

    config->req.src = (void*)src;
    config->req.src_len = srcSize;
    config->req.dst_len = REQ_DSTBUFF_LEN;
    config->req.last = zc->kaeFrameMode;

    ret = wd_do_comp_strm(config->sess, &(config->req));
    if (ret) {
        US_ERR("wd_do_comp_strm = %d\n", ret);
        return ret;
    }

    ret = kaezstd_data_parsing(zc, config);
    if (ret) {
        US_ERR("data_parsing = %d\n", ret);
        return ret;
    }

    return ret;
}