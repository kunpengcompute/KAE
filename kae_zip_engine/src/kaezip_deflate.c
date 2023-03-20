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
 * @file kaezip_deflate.h
 *
 * This file provides inflate function
 *
 *****************************************************************************/

#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include "zlib.h"
#include "kaezip_deflate.h"
#include "kaezip_ctx.h"
#include "kaezip_common.h"
#include "kaezip_utils.h"
#include "kaezip_log.h"

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

static int  kaezip_do_deflate(z_streamp strm, int flush);
static void kaezip_deflate_set_fmt_header(z_streamp strm, int comp_alg_type);

int kz_deflateInit2_(z_streamp strm, int level,
                      int method, int windowBits,
                      int memLevel, int strategy,
                      const char *version,
                      int stream_size)
{
    int ret = lz_deflateInit2_(strm, level, method, windowBits, memLevel, strategy, version, stream_size);
    if (ret != Z_OK) {
        US_ERR("zlib deflate init failed windowbits %d!", windowBits);
        return Z_ERRNO;
    }

    int alg_comp_type = kaezip_winbits2algtype(windowBits);
    if (alg_comp_type != WCRYPTO_ZLIB && alg_comp_type != WCRYPTO_GZIP) {
        US_WARN("unsupport windowbits %d!", windowBits);
        setDeflateKaezipCtx(strm, 0);
        return Z_OK;
    }

    kaezip_ctx_t* kaezip_ctx = kaezip_get_ctx(alg_comp_type, WCRYPTO_DEFLATE);
    if (kaezip_ctx == NULL) {
        US_ERR("failed to get kaezip ctx, windowbits %d!", windowBits);
        setDeflateKaezipCtx(strm, 0);
        return Z_OK;
    }

    kaezip_ctx->status = KAEZIP_COMP_INIT;
    setDeflateKaezipCtx(strm, (uLong)kaezip_ctx);

    US_DEBUG("kae zip deflate init success, kaezip_ctx %p, kaezip_ctx->comp_alg_type %s!",
        kaezip_ctx, kaezip_ctx->comp_alg_type == WCRYPTO_ZLIB ? "zlib" : "gzip");
    return Z_OK;
}

static int kz_deflate_check_strm_avail(z_streamp strm, int flush)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getDeflateKaezipCtx(strm);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", 0);

    //z stream finished and outbuf == 0, but there is still some data that needs to be taken
    if (strm->avail_out == 0 && flush == Z_FINISH && kaezip_ctx->remain != 0) {
        US_WARN("kz deflate warning, no enough output buff, kaezip_ctx->remain %d", kaezip_ctx->remain);
        return 0;
    }

    //z stream not finished but inbuf == 0 and no data remained, so we consider that it has reached the end of data
    if (strm->avail_in == 0 && flush != Z_FINISH && kaezip_ctx->remain == 0) {
        US_WARN("kz deflate warning, no more input buff, kaezip_ctx->remain %d", kaezip_ctx->remain);
        return 0;
    }

    return 1;
}

int kz_deflate(z_streamp strm, int flush)
{
    int ret = -1;
    KAEZIP_RETURN_FAIL_IF(strm == NULL, "strm is NULL.", Z_ERRNO);

    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getDeflateKaezipCtx(strm);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", Z_ERRNO);

    if (!kz_deflate_check_strm_avail(strm, flush)) {
        return Z_BUF_ERROR;
    }

    //wcrypto deflate need to add output format header
    const uint32_t fmt_header_sz = kaezip_fmt_header_sz(kaezip_ctx->comp_alg_type);
    if (kaezip_ctx->header_pos != fmt_header_sz) {
        kaezip_deflate_set_fmt_header(strm, kaezip_ctx->comp_alg_type);
        if (kaezip_ctx->header_pos != fmt_header_sz) {
            return Z_OK;
        }
    }
    
    do {
        ret = kaezip_do_deflate(strm, flush);
        if (ret != KAEZIP_SUCCESS) {
            US_ERR("kaezip failed to do deflate, flush %d", flush);
            return Z_ERRNO;
        }
        
        KAEZIP_UPDATE_ZSTREAM_IN(strm, kaezip_ctx->consumed);
        KAEZIP_UPDATE_ZSTREAM_OUT(strm, kaezip_ctx->produced);
        if (kaezip_ctx->status == KAEZIP_COMP_END) {
            break;
        }
    } while (strm->avail_out != 0 && strm->avail_in != 0) ;

    if (kaezip_ctx->status == KAEZIP_COMP_END 
            && flush == Z_FINISH 
            && strm->avail_in == 0 
            && kaezip_ctx->remain == 0) {
        return Z_STREAM_END;
    } else {
        return Z_OK;
    }
}

int kz_deflateEnd(z_streamp strm)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getDeflateKaezipCtx(strm);
    if (kaezip_ctx != NULL) {
        US_DEBUG("kaezip deflate end");
        kaezip_put_ctx(kaezip_ctx);
    }

    setDeflateKaezipCtx(strm, 0);
    return lz_deflateEnd(strm);
}

int ZEXPORT kz_deflateReset(z_streamp strm)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getDeflateKaezipCtx(strm);
    if (kaezip_ctx != NULL) {
        US_DEBUG("kaezip deflate reset");
        kaezip_init_ctx(kaezip_ctx);
    }

    return lz_deflateReset(strm);
}

static void kaezip_deflate_set_fmt_header(z_streamp strm, int comp_alg_type)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getDeflateKaezipCtx(strm);
    const uint32_t fmt_header_sz = kaezip_fmt_header_sz(comp_alg_type);
    const char*    fmt_header    = kaezip_get_fmt_header(comp_alg_type);

    //that means the outout avail buf is even not enough for a header
    if (strm->avail_out < fmt_header_sz - kaezip_ctx->header_pos) {
        kaezip_ctx->header_pos += strm->avail_out;
        return;
    }

    memcpy(strm->next_out, fmt_header, fmt_header_sz);
    KAEZIP_UPDATE_ZSTREAM_OUT(strm, fmt_header_sz);

    kaezip_ctx->header_pos = fmt_header_sz;
}

static int kaezip_do_deflate(z_streamp strm, int flush)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getDeflateKaezipCtx(strm);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", KAEZIP_FAILED);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx->comp_alg_type != WCRYPTO_ZLIB && kaezip_ctx->comp_alg_type != WCRYPTO_GZIP, 
        "not support alg comp type!", KAEZIP_FAILED);

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

    //if last stream(Z_FINISH) input len is zero, add a format tail for output, unlikely go here
    if (kaezip_ctx->status != KAEZIP_COMP_END
            && flush == Z_FINISH 
            && strm->avail_in == 0 
            && kaezip_ctx->remain == 0)  {
        kaezip_set_fmt_tail(kaezip_ctx);
        return KAEZIP_SUCCESS;
    }

    int ret = kaezip_driver_do_comp(kaezip_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_ERR("kae zip do deflate impl fail!");
        return KAEZIP_FAILED;
    }

    US_DEBUG("kaezip do deflate avail_in %u, avail_out %u, consumed %u, produced %u, remain %u, status %d, flush %d", 
        strm->avail_in, strm->avail_out, kaezip_ctx->consumed, kaezip_ctx->produced, 
        kaezip_ctx->remain, kaezip_ctx->status, flush);

    return KAEZIP_SUCCESS;
}
