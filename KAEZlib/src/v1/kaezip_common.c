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
#include <string.h>
#include "kaezip_common.h"
#include "kaezip_ctx.h"
#include "kaezip_log.h"
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_comp.h"

#define __swab32(x)                \
      ((((x)&0x000000ff) << 24) |  \
        (((x)&0x0000ff00) << 8) |  \
        (((x)&0x00ff0000) >> 8) |  \
        (((x)&0xff000000) >> 24))
#define __cpu_to_be32(x)       __swab32(x)
#define KAEZIP_ZLIB_HEADER_SIZE 2U
#define KAEZIP_GZIP_HEADER_SIZE 10U
#define KAEZIP_GZIP_ID1 0x1FU
#define KAEZIP_GZIP_ID2 0x8BU
#define KAEZIP_GZIP_CM_DEFLATE 8U
#define KAEZIP_GZIP_FHCRC 0x02U
#define KAEZIP_GZIP_FEXTRA 0x04U
#define KAEZIP_GZIP_FNAME 0x08U
#define KAEZIP_GZIP_FCOMMENT 0x10U
#define KAEZIP_GZIP_RESERVED_FLAGS 0xE0U
#define KAEZIP_GZIP_UNSUPPORTED_FLAGS \
    (KAEZIP_GZIP_FHCRC | KAEZIP_GZIP_FEXTRA | KAEZIP_GZIP_FCOMMENT | KAEZIP_GZIP_RESERVED_FLAGS)

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

static uint32_t kaezip_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

const uint32_t kaezip_fmt_header_sz(int comp_alg_type, int comp_optype, const void* src)
{
    (void)comp_optype;
    (void)src;

    if (comp_alg_type == WCRYPTO_ZLIB) {
        return KAEZIP_ZLIB_HEADER_SIZE;
    } else if (comp_alg_type == WCRYPTO_GZIP) {
        return KAEZIP_GZIP_HEADER_SIZE;
    } else if (comp_alg_type == WCRYPTO_RAW_DEFLATE) {
        return 0U;
    }

    US_WARN("not support alg comp type!");
    return 0U;
}

static int kaezip_parse_zlib_header(kaezip_ctx_t *kz_ctx, uint32_t *skip_len)
{
    uint32_t remain = KAEZIP_ZLIB_HEADER_SIZE - kz_ctx->header_pos;
    uint32_t consumed = kaezip_min_u32(kz_ctx->in_len, remain);

    kz_ctx->header_pos += consumed;
    *skip_len = consumed;
    if (kz_ctx->header_pos < KAEZIP_ZLIB_HEADER_SIZE) {
        return KAEZIP_FMT_HEADER_INCOMPLETE;
    }

    kz_ctx->fmt_header_done = 1;
    kz_ctx->header_pos = 0;
    return KAEZIP_FMT_HEADER_DONE;
}

static int kaezip_parse_gzip_header(kaezip_ctx_t *kz_ctx, uint32_t *skip_len)
{
    const unsigned char *in = (const unsigned char *)kz_ctx->in;
    /* Bytes consumed from this input chunk only. The caller will skip them. */
    uint32_t offset = 0;

    /*
     * The fixed gzip header is 10 bytes. It can be split by the caller, so copy
     * only the bytes available in this input chunk and wait for the next chunk
     * before reading flags or validating magic fields.
     */
    if (kz_ctx->gzip_header_pos < KAEZIP_GZIP_HEADER_SIZE) {
        uint32_t remain = KAEZIP_GZIP_HEADER_SIZE - kz_ctx->gzip_header_pos;
        uint32_t consumed = kaezip_min_u32(kz_ctx->in_len, remain);

        /*
         * Cache the fixed header because later chunks may not contain the
         * earlier bytes; validation and flag parsing require the full 10 bytes.
         */
        memcpy(kz_ctx->gzip_header + kz_ctx->gzip_header_pos, in, consumed);
        kz_ctx->gzip_header_pos += consumed; /* Total fixed-header bytes collected across calls. */
        offset += consumed;                  /* Bytes consumed from the current input buffer. */
        if (kz_ctx->gzip_header_pos < KAEZIP_GZIP_HEADER_SIZE) {
            *skip_len = kz_ctx->in_len;      /* The whole current chunk is a fixed-header fragment. */
            return KAEZIP_FMT_HEADER_INCOMPLETE;
        }

        /*
         * Reaching here means the fixed 10-byte gzip header has been collected.
         * Reject malformed gzip input before reading any optional fields.
         */
        if (kz_ctx->gzip_header[0] != KAEZIP_GZIP_ID1 || kz_ctx->gzip_header[1] != KAEZIP_GZIP_ID2 ||
            kz_ctx->gzip_header[2] != KAEZIP_GZIP_CM_DEFLATE) {
            US_ERR("invalid gzip header");
            return KAEZIP_FMT_HEADER_ERROR;
        }

        kz_ctx->gzip_flags = kz_ctx->gzip_header[3]; /* Safe after all 10 fixed header bytes are cached. */
        /*
         * This implementation only supports the optional FNAME field for now.
         * FEXTRA, FCOMMENT, FHCRC, and reserved flags are rejected here instead
         * of being parsed with incomplete boundary rules.
         */
        if (kz_ctx->gzip_flags & KAEZIP_GZIP_UNSUPPORTED_FLAGS) {
            US_ERR("unsupported gzip header flags: 0x%x", kz_ctx->gzip_flags);
            return KAEZIP_FMT_HEADER_ERROR;
        }
    }

    if (kz_ctx->gzip_flags & KAEZIP_GZIP_FNAME) {
        const unsigned char *fname_end = NULL;
        uint32_t remain;

        /*
         * FNAME is a NUL-terminated byte string in the gzip stream, but the
         * current input buffer is not guaranteed to contain the terminator.
         * Search only within in_len and consume another chunk if it is absent.
         */
        if (offset == kz_ctx->in_len) {
            *skip_len = kz_ctx->in_len; /* This chunk ended exactly after the fixed header; FNAME starts later. */
            return KAEZIP_FMT_HEADER_INCOMPLETE;
        }

        remain = kz_ctx->in_len - offset;
        fname_end = memchr(in + offset, '\0', remain);
        if (fname_end == NULL) {
            *skip_len = kz_ctx->in_len; /* Consume all available FNAME bytes and wait for NUL. */
            return KAEZIP_FMT_HEADER_INCOMPLETE;
        }
        offset = (uint32_t)(fname_end - in) + 1U; /* Include the terminating NUL in the skipped header. */
    }

    kz_ctx->fmt_header_done = 1;
    kz_ctx->header_pos = 0;
    *skip_len = offset; /* Bytes to remove before sending the remaining payload to hardware. */
    return KAEZIP_FMT_HEADER_DONE;
}

int kaezip_parse_fmt_header(kaezip_ctx_t *kz_ctx, uint32_t *skip_len)
{
    if (kz_ctx == NULL || skip_len == NULL) {
        return KAEZIP_FMT_HEADER_ERROR;
    }

    *skip_len = 0;
    if (kz_ctx->fmt_header_done) {
        return KAEZIP_FMT_HEADER_DONE;
    }

    if (kz_ctx->comp_alg_type == WCRYPTO_ZLIB) {
        return kaezip_parse_zlib_header(kz_ctx, skip_len);
    } else if (kz_ctx->comp_alg_type == WCRYPTO_GZIP) {
        return kaezip_parse_gzip_header(kz_ctx, skip_len);
    } else if (kz_ctx->comp_alg_type == WCRYPTO_RAW_DEFLATE) {
        kz_ctx->fmt_header_done = 1;
        return KAEZIP_FMT_HEADER_DONE;
    }

    US_WARN("not support alg comp type!");
    return KAEZIP_FMT_HEADER_ERROR;
}

// 参考deflate函数中获取header的逻辑 rfc-1950
#define Z_DEFLATED   8
char* kaezip_get_fmt_header_zlib(int level, int windowBits)
{
        /* zlib header */
        static char zlib_head[2];
        if (windowBits == 8) {
            windowBits = 9; // 参考zlib初始化逻辑, 避免出现窗长为256的情况
        }
        uint32_t header = (Z_DEFLATED + ((windowBits-8)<<4)) << 8;
        uint32_t level_flags;

        if (level < 2)
            level_flags = 0;
        else if (level < 6)
            level_flags = 1;
        else if (level == 6)
            level_flags = 2;
        else
            level_flags = 3;
        header |= (level_flags << 6);
        // if (s->strstart != 0) header |= PRESET_DICT; 暂不支持字典模式
        header += 31 - (header % 31);

        zlib_head[1] = (char)(header & 0xFF); //CM
        zlib_head[0] = (char)((header >> 8) & 0xFF); //MINFO
        return zlib_head;
}

const char* kaezip_get_fmt_header(int alg_comp_type, int level, int windowBits)
{
    static const char gzip_head[10] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

    if (alg_comp_type == WCRYPTO_ZLIB) {
        return kaezip_get_fmt_header_zlib(level, windowBits);
    } else if (alg_comp_type == WCRYPTO_GZIP) {
        return gzip_head;
    } else if (alg_comp_type == WCRYPTO_RAW_DEFLATE) {
        return NULL;
    }
    US_WARN("not support alg comp type!");
    return NULL;
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
    const char wd_deflate_zeroInput_end_block[] = {0x3, 0x0};
    // 当第一次输入亦是最后一次, 且avail_in为0, flush为Z_FINISH时
    // 此时append的尾部需要特殊处理(极特殊情况, spark场景下发现)
    if (unlikely(kz_ctx->status == KAEZIP_COMP_INIT)) {
        KAEZIP_APPEND_BLOCK(kz_ctx, 0, wd_deflate_zeroInput_end_block, sizeof(wd_deflate_zeroInput_end_block));
    } else if (alg_type != WCRYPTO_RAW_DEFLATE) {
        KAEZIP_APPEND_BLOCK(kz_ctx, 0, wd_deflate_end_block, sizeof(wd_deflate_end_block));
    }

    if (alg_type == WCRYPTO_ZLIB) {
        if (unlikely(kz_ctx->status == KAEZIP_COMP_INIT)) {
            checksum = 0x01000000;  // adler32初始值
        } else {
            checksum = (uint32_t)__cpu_to_be32(checksum);
        }
        KAEZIP_APPEND_BLOCK(kz_ctx, kz_ctx->end_block.data_len, &checksum, sizeof(checksum));
    }

    if (alg_type == WCRYPTO_GZIP) {
        if (unlikely(kz_ctx->status == KAEZIP_COMP_INIT)) {
            checksum = isize = 0;
        } else {
            checksum = ~checksum;
            checksum = __kaezip_checksum_reverse(checksum);
        }
        KAEZIP_APPEND_BLOCK(kz_ctx, kz_ctx->end_block.data_len, &checksum, sizeof(checksum));
        KAEZIP_APPEND_BLOCK(kz_ctx, kz_ctx->end_block.data_len, &isize, sizeof(isize));
    }

    kz_ctx->end_block.b_set = 1;
    kz_ctx->end_block.remain = kz_ctx->end_block.data_len;
}

void kaezip_set_fmt_tail(kaezip_ctx_t *kaezip_ctx)
{
    if (kaezip_ctx->status == KAEZIP_COMP_END || kaezip_ctx->comp_alg_type == WCRYPTO_RAW_DEFLATE) {
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
    if ((kz_ctx->status != KAEZIP_COMP_CRC_UNCHECK) || (kz_ctx->comp_alg_type == WCRYPTO_RAW_DEFLATE)) {
        US_DEBUG("kaezip status wrong or its RAW_DEFLATE, not crc uncheck");
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
