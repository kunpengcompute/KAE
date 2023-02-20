/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae config defines
 * Author: songchao
 * Create: 2021-7-19
 */

#ifndef KAEZSTD_CTX_H
#define KAEZSTD_CTX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uadk/wd_alg_common.h"
#include "uadk/wd.h"
#include "uadk/wd_comp.h"
#include "uadk/uacce.h"

#include "kaezstd_sched.h"

typedef struct Comp4Tuple_S {
    unsigned char* litStart;    /* literal address start */
    seqDef* sequencesStart;     /* sequences address start */
    unsigned int litlen;        /* literal lens */
    unsigned int seqnum;        /* sequences lens */
    ZSTD_longLengthType_e longLengthType;  /* litlen overflow flag */
    unsigned int longLengthPos; /* litlen overflow position */
    char* additional_p;         /* addition data ptr */
    /*
     * block compress status:
     * Raw_Block=0 (this is an uncompressed block)
     * RLE_Block=1
     * Compressed_Block=0
     * Reserved=3
     */
    unsigned int bstatus;
} Comp4Tuple;

typedef struct Options_S {
    unsigned int thread_num;
    unsigned int ctx_num;
} Options;

typedef struct Info_S {
    struct uacce_dev_list *list;
    struct wd_sched *sched;
    struct wd_ctx_config ctx_config;
} Info;

typedef struct KaeZstdConfig_S {
    Info info;
    Options opts;

    handle_t sess;
    struct wd_comp_sess_setup setup;
    struct wd_comp_req req;

    Comp4Tuple tuple;
} KaeZstdConfig;

#define KAEZSTD_DEFAULT_CTX_NUM		1
#define KAEZSTD_DEFAULT_THREAD_NUM	1
#define REQ_SRCBUFF_LEN (128 * 1024)
#define REQ_DSTBUFF_LEN (128 * 1024 * 10)
#define REQ_WINDOW_SIZE 2
#define REQ_COMPRESS_LEVEL 8

KaeZstdConfig* kaezstd_get_config(ZSTD_CCtx* zc);
void kaezstd_set_config(ZSTD_CCtx* zc, KaeZstdConfig* config);

#endif
