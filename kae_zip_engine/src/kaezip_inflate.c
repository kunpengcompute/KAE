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

static int kaezip_check_strm_truely_end(z_streamp strm);
static int kaezip_do_inflate(z_streamp strm, int flush);

int ZEXPORT kz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size)
{
    static const int GZIP_INFLATE_MAX_AUTO_WBITS    = 47;
    static const int GZIP_INFLATE_MIN_AUTO_WBITS    = 32;
    
    int ret = lz_inflateInit2_(strm, windowBits, version, stream_size);
    if (unlikely(ret != Z_OK)) {
        US_ERR("lz_inflateInit2_ error, windowBits %d!", windowBits);
        return Z_ERRNO;
    }

    setInflateKaezipCtx(strm, (unsigned long)0);    
    if (windowBits >= GZIP_INFLATE_MIN_AUTO_WBITS && windowBits <= GZIP_INFLATE_MAX_AUTO_WBITS) {
        return Z_OK;
    } else {
        int alg_comp_type = kaezip_winbits2algtype(windowBits);
        return kz_do_inflateInit(strm, alg_comp_type);
    }

    return Z_OK;
}

static int kaezip_check_strm_truely_end(z_streamp strm)
{
    KAEZIP_RETURN_FAIL_IF(strm == NULL, "strm is NULL.", Z_ERRNO);
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    KAEZIP_RETURN_FAIL_IF(kaezip_ctx == NULL, "kaezip ctx is NULL.", Z_ERRNO);

    if (strm->avail_in == 1 
        && kaezip_ctx->status == KAEZIP_DECOMP_END) {
        strm->avail_in = 0;
    }

    if (strm->avail_in == 0 
        && kaezip_ctx->status == KAEZIP_DECOMP_END_BUT_DATAREMAIN) {
        strm->avail_in = 1;
    }

    return KAEZIP_SUCCESS;
}

int ZEXPORT kz_inflate(z_streamp strm, int flush)
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
    } while (strm->avail_out != 0 && strm->avail_in != 0);

    // when test on rpm -i src.rpm, the strm may end with not true ended
    (void)kaezip_check_strm_truely_end(strm);  

    if (flush == Z_FINISH && strm->avail_in == 0 && kaezip_ctx->remain == 0) {
        return Z_STREAM_END;
    } else {
        return Z_OK;
    }
}

int kz_inflateEnd(z_streamp strm)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    if (kaezip_ctx != NULL) {
        US_DEBUG("kaezip inflate end");
        kaezip_put_ctx(kaezip_ctx);
    }

    setInflateKaezipCtx(strm, 0);
    return lz_inflateEnd(strm);
}

int ZEXPORT kz_inflateReset(z_streamp strm)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
    if (kaezip_ctx != NULL) {
        US_DEBUG("kaezip inflate reset");
        kaezip_init_ctx(kaezip_ctx);
    }

    return lz_inflateReset(strm);
}

static int kaezip_do_inflate(z_streamp strm, int flush)
{
    kaezip_ctx_t *kaezip_ctx = (kaezip_ctx_t *)getInflateKaezipCtx(strm);
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

    //the firsh input z stream, should skip the format header, for hardware incompatible
    if (kaezip_ctx->status == KAEZIP_DECOMP_INIT) {
        const uint32_t fmt_header_sz = kaezip_fmt_header_sz(kaezip_ctx->comp_alg_type);
        if (kaezip_ctx->header_pos + kaezip_ctx->in_len <= fmt_header_sz) {
            kaezip_ctx->header_pos += kaezip_ctx->in_len;
            kaezip_ctx->consumed   = kaezip_ctx->in_len;
            kaezip_ctx->produced   = 0;
            US_WARN("the z stream avail len is less then format header, skip!");
            return KAEZIP_SUCCESS;
        } else {
            kaezip_ctx->in        += fmt_header_sz - kaezip_ctx->header_pos;
            kaezip_ctx->in_len    -= fmt_header_sz - kaezip_ctx->header_pos;
            kaezip_ctx->consumed  = fmt_header_sz - kaezip_ctx->header_pos;
            kaezip_ctx->produced  = fmt_header_sz;
            KAEZIP_UPDATE_ZSTREAM_IN(strm, kaezip_ctx->consumed);  //skip the strm format header here
            kaezip_ctx->header_pos = 0;
        }
    }

    int ret = kaezip_driver_do_comp(kaezip_ctx);
    if (ret != KAEZIP_SUCCESS) {
        US_ERR("kae zip do inflate impl fail!");
        return KAEZIP_FAILED;
    }
    
    US_DEBUG("kaezip do inflate avail_in %u, avail_out %u, consumed %u, produced %u, remain %u, status %d, flush %d", 
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

    if (alg_comp_type != WCRYPTO_ZLIB && alg_comp_type != WCRYPTO_GZIP) {
        US_WARN("unsupport alg_comp_type %d!", alg_comp_type);
        setInflateKaezipCtx(strm, 0);
        return Z_OK;
    }

    kaezip_ctx_t* kaezip_ctx = kaezip_get_ctx(alg_comp_type, WCRYPTO_INFLATE);
    if (kaezip_ctx == NULL) {
        US_ERR("failed to get kaezip ctx, alg_comp_type %d!", alg_comp_type);
        setInflateKaezipCtx(strm, 0);
        return Z_OK;
    }
    
    kaezip_ctx->status = KAEZIP_DECOMP_INIT;
    setInflateKaezipCtx(strm, (uLong)kaezip_ctx);

    US_DEBUG("kae zip inflate init success, kaezip_ctx %p, kaezip_ctx->comp_alg_type %s!",
        kaezip_ctx, kaezip_ctx->comp_alg_type == WCRYPTO_ZLIB ? "zlib" : "gzip"); 

    return Z_OK;
}

int kz_getAutoInflateAlgType(z_streamp strm)
{
    if (strm->next_in == NULL || strm->avail_in == 0) {
        return WCRYPTO_NONE;
    }
        
    int wrap = getInflateStateWrap(strm);
    // wrap bit 0 true for zlib, bit 1 true for gzip, bit 2 true to validate check value
    if ((wrap & 0x7) == 0x7) {
        // gzip head
        if (strm->next_in[0] == 0x1F && strm->next_in[1] == 0x8B) {
            return WCRYPTO_GZIP;
        } else {
            return WCRYPTO_ZLIB;
        }
    } else {
        return WCRYPTO_NONE;
    }
}

