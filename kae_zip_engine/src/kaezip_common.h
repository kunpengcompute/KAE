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
 * @file kaezip_common.h
 *
 * This file provides the common interface for ZIP engine dealing with wrapdrive
 *
 *****************************************************************************/

#ifndef KAEZIP_COMMON_H
#define KAEZIP_COMMON_H
#include "kaezip_ctx.h"

#define KAEZIP_STREAM_CHUNK_IN         ((COMP_BLOCK_SIZE) >> 3)  // change the input size would change the performace
#define KAEZIP_STREAM_CHUNK_OUT        (COMP_BLOCK_SIZE)

#define WCRYPTO_NONE            (-1)
#define WCRYPTO_RAW_DEFLATE     2

int kz_get_devices(void);
int kaezip_winbits2algtype(int windowBits);

const uint32_t kaezip_fmt_header_sz(int comp_alg_type);
const char*    kaezip_get_fmt_header(int comp_alg_type);
void           kaezip_set_fmt_tail(kaezip_ctx_t *kz_ctx);
void           kaezip_deflate_addcrc(kaezip_ctx_t *kz_ctx);
#endif


