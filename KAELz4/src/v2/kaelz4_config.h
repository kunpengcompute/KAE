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

#ifndef KAELZ4_CTX_H
#define KAELZ4_CTX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uadk/wd_alg_common.h"
#include "uadk/wd.h"
#include "uadk/wd_comp.h"
#include "uadk/uacce.h"

typedef struct Comp4Tuple_S {
    unsigned char* litStart;    /* literal address start */
    seqDef* sequencesStart;     /* sequences address start */
    unsigned int litlen;        /* literal lens */
    unsigned int seqnum;        /* sequences lens */
    LZ4_longLengthType_e longLengthType;  /* litlen overflow flag */
    unsigned int longLengthPos; /* litlen overflow position */
    char* additional_p;         /* addition data ptr */
    /*
     * block compress status:
     * Raw_Block=0 (this is an uncompressed block)
     * RLE_Block=1
     * Compressed_Block=2
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

typedef struct KaeLz4Config_S {
    Info info;
    Options opts;

    handle_t sess;
    struct wd_comp_sess_setup setup;
    struct wd_comp_req req;

    Comp4Tuple tuple;
} KaeLz4Config;

#define KAELZ4_DEFAULT_CTX_NUM		1
#define KAELZ4_DEFAULT_THREAD_NUM	1
#define REQ_SRCBUFF_LEN (128 * 1024)
#define REQ_DSTBUFF_LEN (128 * 1024 * 10)
#define REQ_WINDOW_SIZE 2
#define REQ_COMPRESS_LEVEL 8

KaeLz4Config* kaelz4_get_config(LZ4_CCtx* zc);
void kaelz4_set_config(LZ4_CCtx* zc, KaeLz4Config* config);

#endif
