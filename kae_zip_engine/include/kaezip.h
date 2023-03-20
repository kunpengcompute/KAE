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
 * @file kaezip.h
 *
 * This file provides the interface for zlib;
 *
 *****************************************************************************/

#ifndef KAEZIP_H
#define KAEZIP_H
#include "zlib.h"

extern int kz_get_devices(void);
extern int kz_deflate(z_streamp strm, int flush);
extern int kz_inflate(z_streamp strm, int flush);
extern int kz_inflateEnd(z_streamp strm);
extern int kz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                       const char *version, int stream_size);
extern int kz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
extern int kz_deflateEnd(z_streamp strm);
extern int kz_inflateReset(z_streamp strm);
extern int kz_deflateReset(z_streamp strm);
extern int kz_getAutoInflateAlgType(z_streamp strm);
extern int kz_do_inflateInit(z_streamp strm, int alg_comp_type);

extern int lz_deflateEnd(z_streamp strm);
extern int lz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                      const char *version, int stream_size);
extern int lz_deflateReset(z_streamp strm);

extern int lz_inflateEnd(z_streamp strm);
extern int lz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
extern int lz_inflateReset(z_streamp strm);

extern int getInflateStateWrap(z_streamp strm);
extern unsigned long getInflateKaezipCtx(z_streamp strm);
extern void setInflateKaezipCtx(z_streamp strm, unsigned long kaezip_ctx);
extern unsigned long getDeflateKaezipCtx(z_streamp strm);
extern void setDeflateKaezipCtx(z_streamp strm, unsigned long kaezip_ctx);
#endif

