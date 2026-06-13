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
 * @file kaezip_inflate.h
 *
 * This file provides inflate function
 *
 *****************************************************************************/
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include "zlib.h"
#include "kaezip_inflate.h"
#include "kaezip_ctx.h"
#include "kaezip_common.h"
#include "kaezip_utils.h"
#include "kaezip_cpucheck.h"
#include "kaezip_log.h"

#include "zutil.h"
#include "inftrees.h"
#include "inflate.h"

#define KAEZIP_UPDATE_ZSTREAM_IN(zstrm, in_len) \
    do { \
        zstrm->next_in  += in_len;   \
        zstrm->avail_in -= in_len;   \
        zstrm->total_in += in_len;   \
    } while (0)

#define KAEZIP_UPDATE_ZSTREAM_OUT(zstrm, out_len) \
    do { \
        zstrm->next_out  += out_len;   \
        zstrm->avail_out -= out_len;   \
        zstrm->total_out += out_len;   \
    } while (0)

static int kaezip_check_strm_truely_end(z_streamp strm);
static int kaezip_do_inflate(z_streamp strm, int flush);

int ZEXPORT kz_inflateInit2_v1(z_streamp strm, int windowBits, const char *version, int stream_size)
{
    static const int GZIP_INFLATE_MAX_AUTO_WBITS = 47;
    static const int GZIP_INFLATE_MIN_AUTO_WBITS = 32;

    setInflateKaezipCtx(strm, (unsigned long)0);
    if (windowBits >= GZIP_INFLATE_MIN_AUTO_WBITS && windowBits <= GZIP_INFLATE_MAX_AUTO_WBITS) {
        return Z_OK;
    }
    US_DEBUG("kz_inflate_init windowBits %d", windowBits);

    int alg_comp_type = kaezip_winbits2algtype(windowBits);
    return kz_do_inflateInit(strm, alg_comp_type);
}

static int kaezip_check_strm_truely_end(z_streamp strm)
{
    KAEZIP_RETURN_FAIL_IF(strm == NULL, "strm is NULL.", Z_ERRNO);
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", Z_ERRNO);

    if (strm->avail_in == 1 && kaezip_ctx->status == KAEZIP_DECOMP_END) {
        strm->avail_in = 0;
    }

    if (strm->avail_in == 0 && kaezip_ctx->status == KAEZIP_DECOMP_END_BUT_DATAREMAIN) {
        strm->avail_in = 1;
    }

    return KAEZIP_SUCCESS;
}

static inline int kaezip_inflate_need_append_loop(z_streamp strm, const kaezip_ctx_t *kaezip_ctx)
{   
    /*
    * KAEZIP_DECOMP_NO_CRC indicates that the payload has ended, but the trailer
    * CRC bytes still need to be transferred to the hardware. In this case, we
    * should continue when avail_in != 0, even if avail_out is 0.
    * KAEZIP_DECOMP_BLK_NOSTART indicates that the current block has not started
    * on the hardware yet, so inflate needs another append-loop iteration to
    * submit data to the UADK driver again.
    */
    return (kaezip_ctx->status == KAEZIP_DECOMP_NO_CRC && strm->avail_in != 0) || kaezip_ctx->status == KAEZIP_DECOMP_BLK_NOSTART;
}

int ZEXPORT kz_inflate_v1(z_streamp strm, int flush)
{
    int ret = -1;
    KAEZIP_RETURN_FAIL_IF(strm == NULL, "strm is NULL.", Z_ERRNO);

    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", Z_ERRNO);

    do {
        ret = kaezip_do_inflate(strm, flush);
        if (ret != KAEZIP_SUCCESS) {
            US_ERR("kaezip failed to do inflate, flush %d", flush);
            return Z_ERRNO;
        }

        KAEZIP_UPDATE_ZSTREAM_IN(strm, kaezip_ctx->consumed);
        KAEZIP_UPDATE_ZSTREAM_OUT(strm, kaezip_ctx->produced);

        if (kaezip_ctx->status == KAEZIP_DECOMP_VERIFY_ERR) {
            return Z_DATA_ERROR;
        }

        if (kaezip_ctx->status == KAEZIP_DECOMP_END) {
            (void)kaezip_check_strm_truely_end(strm);
            return Z_STREAM_END;
        }
    } while ((strm->avail_out != 0 && strm->avail_in != 0) || kaezip_inflate_need_append_loop(strm, kaezip_ctx));

    // when test on rpm -i src.rpm, the strm may end with not true ended
    (void)kaezip_check_strm_truely_end(strm);

    if (flush == Z_FINISH && strm->avail_in == 0 && kaezip_ctx->remain == 0) {
        return Z_STREAM_END;
    } else {
        return Z_OK;
    }
}

int kz_inflateEnd_v1(z_streamp strm)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    if (kaezip_ctx != NULL) {
        US_DEBUG("kaezip inflate end");
        kaezip_put_ctx(kaezip_ctx);
    }

    setInflateKaezipCtx(strm, 0);
    return Z_OK;
}

int ZEXPORT kz_inflateReset_v1(z_streamp strm)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    if (kaezip_ctx != NULL) {
        US_DEBUG("kaezip inflate reset");
        kaezip_init_ctx(kaezip_ctx);
    }

    return Z_OK;
}

static int kaezip_do_inflate(z_streamp strm, int flush)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    uint32_t fmt_header_skip = 0;
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx->comp_alg_type != WCRYPTO_ZLIB && kaezip_ctx->comp_alg_type != WCRYPTO_GZIP &&
        kaezip_ctx->comp_alg_type != WCRYPTO_RAW_DEFLATE, "not support alg comp type!", KAEZIP_FAILED);

    kaezip_ctx->in           = strm->next_in;
    kaezip_ctx->in_len       = (strm->avail_in < KAEZIP_STREAM_CHUNK_IN) ? strm->avail_in : KAEZIP_STREAM_CHUNK_IN;
    kaezip_ctx->out          = strm->next_out;
    kaezip_ctx->consumed     = 0;
    kaezip_ctx->produced     = 0;
    kaezip_ctx->avail_out    = strm->avail_out;
    if (flush == Z_FINISH) {
        kaezip_ctx->flush = (strm->avail_in <= KAEZIP_STREAM_CHUNK_IN) ? WCRYPTO_FINISH : WCRYPTO_SYNC_FLUSH;
    } else {
        kaezip_ctx->flush = WCRYPTO_SYNC_FLUSH;
    }

    /*
     * UADK handles the raw deflate payload, so the software wrapper consumes
     * zlib/gzip headers first. If the header is incomplete, report the bytes
     * consumed and wait for the next inflate() call instead of sending header
     * bytes to hardware.
     */
    if ((kaezip_ctx->comp_alg_type != WCRYPTO_RAW_DEFLATE) && (kaezip_ctx->status == KAEZIP_DECOMP_INIT)) {
        /* fmt_header_skip is the number of wrapper-header bytes found in this input chunk. */
        int header_status = kaezip_parse_fmt_header(kaezip_ctx, &fmt_header_skip);
        if (header_status == KAEZIP_FMT_HEADER_ERROR || fmt_header_skip > kaezip_ctx->in_len) {
            US_ERR("invalid z stream format header");
            return KAEZIP_FAILED;
        }

        /* Drop parsed wrapper bytes so op_data.in starts at raw deflate payload. */
        kaezip_ctx->in       = (uint8_t *)kaezip_ctx->in + fmt_header_skip;
        kaezip_ctx->in_len  -= fmt_header_skip;
        if (header_status == KAEZIP_FMT_HEADER_INCOMPLETE || kaezip_ctx->in_len == 0) {
            /* No payload is available yet; let the outer inflate loop advance next_in. */
            kaezip_ctx->consumed = fmt_header_skip;
            kaezip_ctx->produced = 0;
            US_WARN("the z stream avail len is less than format header, skip!");
            return KAEZIP_SUCCESS;
        }
    }

    int ret = kaezip_driver_do_decomp(kaezip_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_ERR("kae zip do inflate impl fail!");
        return KAEZIP_FAILED;
    }
    /* Add the skipped wrapper bytes to the payload bytes consumed by hardware. */
    kaezip_ctx->consumed += fmt_header_skip;

    US_DEBUG("kaezip do inflate avail_in %u, avail_out %u, consumed %u, produced %u, remain %u, status %d, zflush %d",
        strm->avail_in, strm->avail_out, kaezip_ctx->consumed, kaezip_ctx->produced,
        kaezip_ctx->remain, kaezip_ctx->status, flush);

    return KAEZIP_SUCCESS;
}

int kz_do_inflateInit(z_streamp strm, int alg_comp_type)
{
    unsigned long kaezip_ctx_value = getInflateKaezipCtx(strm);
    if (kaezip_ctx_value != 0) {
        return Z_OK;
    }

    if ((alg_comp_type == WCRYPTO_NONE) || (alg_comp_type == WCRYPTO_RAW_DEFLATE && !kaezip_check_support_deflate())) {
        US_WARN("unsupport alg_comp_type %d!", alg_comp_type);
        setInflateKaezipCtx(strm, 0);
        return Z_OK;
    }

    int win_size, alg;
    (void)kz_zlib_analy_alg(-15, &alg, &win_size, -1);
    kaezip_ctx_t* kaezip_ctx = kaezip_get_ctx(alg_comp_type, WCRYPTO_INFLATE, win_size, 0, NULL, SYNC_MODE);
    if (kaezip_ctx == NULL) {
        US_ERR("failed to get kaezip ctx, alg_comp_type %d!", alg_comp_type);
        setInflateKaezipCtx(strm, 0);
        return Z_OK;
    }

    kaezip_ctx->status = KAEZIP_DECOMP_INIT;
    setInflateKaezipCtx(strm, (uLong)kaezip_ctx);

    US_DEBUG("kaezip inflate init success, kaezip_ctx %p, kaezip_ctx->comp_alg_type %s!",
        kaezip_ctx, kaezip_ctx->comp_alg_type == WCRYPTO_ZLIB ? "zlib" :
        (kaezip_ctx->comp_alg_type == WCRYPTO_GZIP ? "gzip" : "deflate-raw"));

    return Z_OK;
}

static int kz_check_ifzlib(z_streamp strm)
{
    static const char zlib_head[][2] = {
        {0x18, 0x1d},	{0x18, 0x5b},	{0x18, 0x99},	{0x18, 0xd7},
        {0x18, 0x19},	{0x18, 0x57},	{0x18, 0x95},	{0x18, 0xd3},
        {0x28, 0x15},	{0x28, 0x53},	{0x28, 0x91},	{0x28, 0xcf},
        {0x38, 0x11},	{0x38, 0x4f},	{0x38, 0x8d},	{0x38, 0xcb},
        {0x48, 0x0d},	{0x48, 0x4b},	{0x48, 0x89},	{0x48, 0xc7},
        {0x58, 0x09},	{0x58, 0x47},	{0x58, 0x85},	{0x58, 0xc3},
        {0x68, 0x05},	{0x68, 0x43},	{0x68, 0x81},	{0x68, 0xde},
        {0x78, 0x01},	{0x78, 0x5e},	{0x78, 0x9c},	{0x78, 0xda}
    };

    for (int i = 0; i < 32; ++i) {
        if (strm->next_in[0] == zlib_head[i][0] && strm->next_in[1] == zlib_head[i][1]) {
            return 1;
        }
    }
    return 0;
}

int kz_getAutoInflateAlgType(z_streamp strm)
{
    if (strm->next_in == NULL || strm->avail_in < 2) {
        return WCRYPTO_NONE;
    }

    int wrap = getInflateStateWrap(strm);
    // wrap bit 0 true for zlib, bit 1 true for gzip, bit 2 true to validate check value
    if ((wrap & 0x7) == 0x7) {
        // gzip head
        if (strm->next_in[0] == 0x1F && strm->next_in[1] == 0x8B) {
            return WCRYPTO_GZIP;
        } else if (kz_check_ifzlib(strm)) {
            return WCRYPTO_ZLIB;
        } else {
            return WCRYPTO_RAW_DEFLATE;
        }
    }
    return WCRYPTO_NONE;
}

int getInflateStateWrap(z_streamp strm)
{
    struct inflate_state FAR *state;
    
    if (strm == Z_NULL) {
        return 0;
    }
    state = (struct inflate_state FAR *)strm->state;

    if (state == Z_NULL) {
        return 0;
    }

    return state->wrap;
}

unsigned long getInflateKaezipCtx(z_streamp strm)
{
    struct inflate_state FAR *state;
    
    if (strm == Z_NULL) {
        return (unsigned long)0;
    }
    
    state = (struct inflate_state FAR *)strm->state;
    if (state == Z_NULL) {
        return (unsigned long)0;
    }

    return state->kaezip_ctx;
}

void setInflateKaezipCtx(z_streamp strm, unsigned long kaezip_ctx)
{
    struct inflate_state FAR *state;
    
    if (strm == Z_NULL) {
        return;
    }
    state = (struct inflate_state FAR *)strm->state;

    if (state == Z_NULL) {
        return;
    }

    state->kaezip_ctx = kaezip_ctx;
    return;
}
