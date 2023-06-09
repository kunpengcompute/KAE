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

// 海思当前只支持了level 8\9 win 0-4
static void Compression_level_conversion(int reqlevel, int* kae_lev, int* kae_win)
{
    if (reqlevel >= 0 && reqlevel <=3) {
        * kae_lev = 8;
        * kae_win = 0;
        return;
    } else if (reqlevel >= 4 && reqlevel<=5) {
        * kae_lev = 8;
        * kae_win = 1;
        return;
    } else if (reqlevel >= 6 && reqlevel<=7) {
        * kae_lev = 8;
        * kae_win = 2;
        return;
    } else if (reqlevel >= 8 && reqlevel<=9) {
        * kae_lev = 8;
        * kae_win = 3;
        return;
    } else if (reqlevel >= 10 && reqlevel<=11) {
        * kae_lev = 8;
        * kae_win = 4;
        return;
    } else if (reqlevel >= 12 && reqlevel<=13) {
        * kae_lev = 9;
        * kae_win = 0;
        return;
    } else if (reqlevel >= 14 && reqlevel<=15) {
        * kae_lev = 9;
        * kae_win = 1;
        return;
    } else if (reqlevel >= 16 && reqlevel<=17) {
        * kae_lev = 9;
        * kae_win = 2;
        return;
    } else if (reqlevel >= 18 && reqlevel<=19) {
        * kae_lev = 9;
        * kae_win = 3;
        return;
    } else {
        * kae_lev = 9;
        * kae_win = 4;
        return;
    }
}

static int kae_do_alloc_sess(KaeZstdConfig *config, int kaeLev, int kaeWin)
{
    if (config->sess == (handle_t)0) {
        // 第一次申请
        US_DEBUG("[kae-sess] firse alloc sess kaelev is %d kaewin is %d!\n", kaeLev, kaeWin);
        config->setup.win_sz  = kaeWin;
        config->setup.comp_lv = kaeLev;
        config->sess = wd_comp_alloc_sess(&(config->setup));
        if (!(config->sess)) {
            US_ERR("failed to alloc comp sess!\n");
            return KAE_ZSTD_ALLOC_FAIL;
        }
    } else if (config->sess != (handle_t)0 && config->setup.comp_lv == kaeLev && config->setup.win_sz == kaeWin) {
         // 已经申请并且申请的level不变
        US_DEBUG("[kae-sess] has alloc sess and level not changed!\n");
    } else if (config->sess != (handle_t)0 && (config->setup.comp_lv != kaeLev || config->setup.win_sz != kaeWin)) {
        // 已经申请并且申请的level发生改变 则重新申请
        US_DEBUG("[kae-sess] has alloc sess bug level has changed, sess is 0x%lx, old lev is %d, old win is %d, new lev is %d, new win is %d!\n",
            config->sess, config->setup.comp_lv, config->setup.win_sz, kaeLev, kaeWin);
        wd_comp_free_sess(config->sess);
        config->setup.win_sz  = kaeWin;
        config->setup.comp_lv = kaeLev;
        config->sess = wd_comp_alloc_sess(&(config->setup));
        if (!(config->sess)) {
            US_ERR("failed to alloc comp sess!\n");
            return KAE_ZSTD_ALLOC_FAIL;
        }
    }
    return KAE_ZSTD_SUCC;
}


int kaezstd_compress(ZSTD_CCtx* zc, const void* src, size_t srcSize)
{
    KaeZstdConfig *config = NULL;
    int ret;
    int kaeLev;
    int kaeWin;
    int reqlevel = zc->requestedParams.compressionLevel;

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
    Compression_level_conversion(reqlevel, &kaeLev, &kaeWin);

    ret = kae_do_alloc_sess(config, kaeLev, kaeWin);
    if (ret != KAE_ZSTD_SUCC) {
        US_ERR("kae_do_alloc_sess = %d\n", ret);
        return ret;
    }

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

    US_DEBUG("[DEBUG] level is : %d; win is %d, algtype is %d.", config->setup.comp_lv, config->setup.win_sz, config->setup.alg_type);

    return ret;
}
