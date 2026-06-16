/*
 * Copyright (C) 2019. Huawei Technologies Co., Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the zlib License.
 * You may obtain a copy of the License at
 *
 *     https://www.zlib.net/zlib_license.html
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * zlib License for more details.
 */

/*****************************************************************************
 * @file kaezip_ctx.h
 *
 * This file provides kaezip ctx control and driver compress funtion;
 *
 *****************************************************************************/

#ifndef KAEZIP_CTX_H
#define KAEZIP_CTX_H
#include <sys/time.h>
#include "wd_queue_memory.h"
#include "uadk/v1/wd_comp.h"
#include "kaezip_dev.h"

enum kaezip_comp_status {
    KAEZIP_COMP_INIT = 0,
    KAEZIP_COMP_DOING,
    KAEZIP_COMP_CRC_UNCHECK,
    KAEZIP_COMP_END_BUT_DATAREMAIN,
    KAEZIP_COMP_END,
    KAEZIP_COMP_VERIFY_ERR,
};

enum kaezip_decomp_status {
    KAEZIP_DECOMP_INIT = 0,
    KAEZIP_DECOMP_DOING,
    KAEZIP_DECOMP_NO_CRC,
    KAEZIP_DECOMP_NO_CRC_BUT_DATAREMAIN,
    KAEZIP_DECOMP_END_BUT_DATAREMAIN,
    KAEZIP_DECOMP_BLK_NOSTART,
    KAEZIP_DECOMP_BLK_NOSTART_BUT_DATAREMAIN,
    KAEZIP_DECOMP_END,
    KAEZIP_DECOMP_VERIFY_ERR,
};

struct wcrypto_end_block {
    char             buffer[32];
    unsigned int     data_len;
    unsigned int     remain;
    unsigned int     b_set;
};

#define MAX_KAE_CTX_DEPTH 64
#define REQ_BUFFER_MAX 255   // uadk支持最大的sgl buf数量
#define REQ_BUFFER_MAX_SIZE (8*1024*1024) // uadk支持最大sge的大小
#define REQ_BUFFER_MIN_SIZE 2   // zlib-format 存在2字节头部
#define KAE_ASYNC_MAX_RECV_TIMES (2000000)
#define FLAG_NUM (10)
struct kaezip_async_sleep_info {
    struct timespec ns_sleep;
    int flag[FLAG_NUM];
    int index;
};

struct kaezip_ctx {
    void*            in;
    unsigned int     in_len;
    void*            out;
    unsigned int     avail_out;
    unsigned int     consumed;
    unsigned int     produced;
    unsigned int     remain;        // data produced by warpdrive but haven't been take away for not enough avail out buf

    const char*      header;        // compress data header
    unsigned int     header_pos;    // the format header pos
    /*
     * Inflate skips zlib/gzip wrapper headers before submitting raw deflate
     * payload to hardware. Gzip headers may arrive split across inflate()
     * calls, so keep a small parser state in the context instead of treating
     * each input buffer as a complete C string.
     */
    unsigned char    fmt_header_done;
    unsigned char    gzip_flags;
    unsigned int     gzip_header_pos;
    unsigned char    gzip_header[10];
    int              flush;         // WCRYPTO_SYNC_FLUSH / WCRYPTO_FINISH
    int              zflush;        // zlib flush value
    int              comp_alg_type; // WCRYPTO_ZLIB / WCRYPTO_GZIP
    int              comp_type;     // WCRYPTO_DEFLATE / WCRYPTO_INFLATE
    unsigned int     do_comp_len;   // a compress proccess cost len
    unsigned int     buffer_len;    // input data length in buffer
    unsigned int     buffer_remain; // remain data in buffer which not send to driver for 4Byte alignment
    int              status;        // enum kaezip_comp_status
    unsigned int     index;

    struct wcrypto_end_block        end_block;
    KAE_QUEUE_DATA_NODE_S*          q_node;
    struct wcrypto_comp_ctx_setup   setup;
    struct wcrypto_comp_op_data     op_data;
    void*                           wd_ctx;
    wd_map                          usr_map;
    unsigned char                   src_sgl_buf[32 + (32 * (REQ_BUFFER_MAX + 1))];   // 32: sizeof(struct wd_sgl) + sizeof(struct wd_sge) * 60 + 1 * sizeof(struct wd_sge) for hisi_sge
    unsigned char                   dst_sgl_buf[32 + (32 * (REQ_BUFFER_MAX + 1))];   // 32: sizeof(struct wd_sgl) + sizeof(struct wd_sge) * 60 + 1 * sizeof(struct wd_sge) for hisi_sge
    void                            *src_sgl;
    void                            *dst_sgl_usr;
    void                            *dst_sgl_kernel;
    void (*callback)(int status, void *param);
    void* param;
};

struct kaezip_instance {
    KAE_QUEUE_DATA_NODE_S *q_node;
    void *wd_ctx;
    struct kaezip_ctx *kz_ctx[MAX_KAE_CTX_DEPTH];
    struct wcrypto_comp_ctx_setup setup;
    unsigned int total_num;
    unsigned int cur_idx;
    unsigned int free_num;
};

typedef struct kaezip_ctx   kaezip_ctx_t;

kaezip_ctx_t* kaezip_get_ctx(int alg_comp_type, int comp_optype, int win_size, int is_sgl, const device_config_t *config, operation_mode mode);
void          kaezip_put_ctx(kaezip_ctx_t* kz_ctx);
void          kaezip_init_ctx(kaezip_ctx_t* kz_ctx);
void          kaezip_free_ctx(kaezip_ctx_t* kz_ctx);

int           kaezip_get_remain_data(kaezip_ctx_t *kz_ctx);
int           kaezip_driver_do_comp(kaezip_ctx_t *kaezip_ctx);
int           kaezip_driver_do_decomp(kaezip_ctx_t *kaezip_ctx);
void          kaezip_set_comp_status(kaezip_ctx_t *kz_ctx);

int kaezip_get_win_size(void);
#endif
