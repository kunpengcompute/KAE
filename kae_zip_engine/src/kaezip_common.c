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
 * @file kaezip_common.c
 *
 * This file provides the common implemenation for ZIP engine dealing with wrapdrive
 *
 *****************************************************************************/
#include <unistd.h>
#include <dirent.h>
#include "kaezip_common.h"
#include "kaezip_ctx.h"
#include "kaezip_log.h"
#include "wd.h"
#include "wd_comp.h"

#define __swab32(x)                \
      ((((x)&0x000000ff) << 24) |  \
        (((x)&0x0000ff00) << 8) |  \
        (((x)&0x00ff0000) >> 8) |  \
        (((x)&0xff000000) >> 24))
#define __cpu_to_be32(x)       __swab32(x)

static unsigned int inline __kaezip_checksum_reverse(unsigned int x)
{
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));

    return ((x >> 16) | (x << 16));
}

int kz_get_devices(void)
{
    DIR *uacce_dev = NULL;
    struct dirent *device;
    int found = 0;
    static const char* zipdev = "hisi_zip";
    static int get_devices_flag = 0;

    if (get_devices_flag) {
        return 1;
    }

    kaezip_debug_init_log();
    uacce_dev = opendir("/sys/class/uacce");
    if (!uacce_dev) {
        US_WARN("No /sys/class/uacce directory or it cannot be opened");
        return 0;
    }

    while ((device = readdir(uacce_dev))) {
        if(strstr(device->d_name, zipdev)) {
            US_DEBUG("find device %s", device->d_name);
            found = 1;
            break;
        }
    }
    closedir(uacce_dev);

    if (!found) {
        US_WARN("No running hisi_zip devices found");
        return 0;
    }
    get_devices_flag = 1;
    return 1;
}

int kaezip_winbits2algtype(int windowbits)
{
    static const int ZLIB_MAX_WBITS    = 15;
    static const int ZLIB_MIN_WBITS    = 8;
    static const int GZIP_MAX_WBITS    = 31;
    static const int GZIP_MIN_WBITS    = 24;
    static const int DEFLATE_MAX_WBITS = -8;
    static const int DEFLATE_MIN_WBITS = -15;

    int alg_type = WCRYPTO_NONE;
    if ((windowbits >= ZLIB_MIN_WBITS) && (windowbits <= ZLIB_MAX_WBITS)) {
        alg_type = WCRYPTO_ZLIB;
    } else if ((windowbits >= GZIP_MIN_WBITS) && (windowbits <= GZIP_MAX_WBITS)) {
        alg_type = WCRYPTO_GZIP;
    } else if ((windowbits >= DEFLATE_MIN_WBITS) && (windowbits <= DEFLATE_MAX_WBITS)) {
        alg_type = WCRYPTO_RAW_DEFLATE;
    } else {
        alg_type = WCRYPTO_NONE;
    }

    return alg_type;
}

const uint32_t kaezip_fmt_header_sz(int comp_alg_type)
{
    switch (comp_alg_type) {
    case WCRYPTO_ZLIB:
        return 2U;
    case WCRYPTO_GZIP:
        return 10U;
    default:
        US_WARN("not support alg comp type!");
        return 0U;
    }
}

const char* kaezip_get_fmt_header(int comp_alg_type)
{
    static const char zlib_head[] = {0x78, 0x9c};
    static const char gzip_head[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

    switch (comp_alg_type) {
    case WCRYPTO_ZLIB:
        return zlib_head;
    case WCRYPTO_GZIP:
        return gzip_head;
    default:
        US_WARN("not support alg comp type!");
        return NULL;
    }
}

static void kaezip_append_fmt_tail(kaezip_ctx_t *kz_ctx)
{
#define KAEZIP_APPEND_BLOCK(kz_ctx, offset, block, block_sz) \
    do { \
        memcpy(kz_ctx->end_block.buffer + offset, block, block_sz); \
        kz_ctx->end_block.data_len += block_sz; \
    } while (0)

    US_DEBUG("kaezip append fmt tail!");

    kz_ctx->end_block.data_len = 0;

    int alg_type   = kz_ctx->comp_alg_type;
    uint32_t checksum = kz_ctx->op_data.checksum;
    uint32_t isize    = kz_ctx->op_data.isize;

    const char wd_deflate_end_block[] = {0x1, 0x0, 0x0, 0xff, 0xff};
    KAEZIP_APPEND_BLOCK(kz_ctx, 0, wd_deflate_end_block, sizeof(wd_deflate_end_block));

    if (alg_type == WCRYPTO_ZLIB) {
        checksum = (uint32_t)__cpu_to_be32(checksum);
        KAEZIP_APPEND_BLOCK(kz_ctx, sizeof(wd_deflate_end_block), &checksum, sizeof(checksum));
    } 
    
    if (alg_type == WCRYPTO_GZIP) {
        checksum = ~checksum;
        checksum = __kaezip_checksum_reverse(checksum);
        KAEZIP_APPEND_BLOCK(kz_ctx, sizeof(wd_deflate_end_block), &checksum, sizeof(checksum));
        KAEZIP_APPEND_BLOCK(kz_ctx, sizeof(wd_deflate_end_block) + sizeof(checksum), &isize, sizeof(isize));
    }

    kz_ctx->end_block.b_set = 1;
    kz_ctx->end_block.remain = kz_ctx->end_block.data_len;
}

void kaezip_set_fmt_tail(kaezip_ctx_t *kaezip_ctx)
{
    if (kaezip_ctx->status == KAEZIP_COMP_END) {
        return;
    }

    if (kaezip_ctx->end_block.b_set == 0) {           
        kaezip_append_fmt_tail(kaezip_ctx);
    } 

    int data_begin = kaezip_ctx->end_block.data_len - kaezip_ctx->end_block.remain;
    if (kaezip_ctx->end_block.remain <= kaezip_ctx->avail_out) {
        kaezip_ctx->produced = kaezip_ctx->end_block.remain;
        kaezip_ctx->end_block.remain = 0;
    } else {
        kaezip_ctx->produced = kaezip_ctx->avail_out;
        kaezip_ctx->end_block.remain -= kaezip_ctx->produced;
    }

    memcpy(kaezip_ctx->out, kaezip_ctx->end_block.buffer + data_begin, kaezip_ctx->produced);
    kaezip_ctx->status = (kaezip_ctx->end_block.remain == 0 ? KAEZIP_COMP_END : KAEZIP_COMP_END_BUT_DATAREMAIN);
    kaezip_ctx->end_block.b_set = (kaezip_ctx->end_block.remain == 0 ? 0 : 1);
}

void kaezip_deflate_addcrc(kaezip_ctx_t *kz_ctx)
{
    if (kz_ctx->status != KAEZIP_COMP_CRC_UNCHECK) {
        US_DEBUG("kaezip status wrong, not crc uncheck");
        return;
    }

    kaezip_append_fmt_tail(kz_ctx);

    int data_begin = kz_ctx->end_block.data_len - kz_ctx->end_block.remain;
    int end_produced = 0;
    if (kz_ctx->end_block.remain <= kz_ctx->avail_out - kz_ctx->produced) {
        end_produced = kz_ctx->end_block.remain;
        kz_ctx->end_block.remain = 0;
    } else {
        end_produced = kz_ctx->avail_out - kz_ctx->produced;
        kz_ctx->end_block.remain -= end_produced;
    }

    memcpy(kz_ctx->out + kz_ctx->produced, kz_ctx->end_block.buffer + data_begin, end_produced);
    kz_ctx->produced += end_produced;
    kz_ctx->status = (kz_ctx->end_block.remain == 0 ? KAEZIP_COMP_END : KAEZIP_COMP_END_BUT_DATAREMAIN);
}

