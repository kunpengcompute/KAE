/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae api defines
 * Author: songchao
 * Create: 2021-7-19
 */

#ifndef KAEZSTD_H
#define KAEZSTD_H

#include "zstd.h"
#ifdef BUILD_KAEZSTD
#include "zstd_internal.h"
#include "zstd_compress_internal.h"
#endif

#define TUPLE_STATUS_COMPRESS 2
#define TUPLE_STATUS_RLEBLOCK 1
#define TUPLE_STATUS_NOCOMPRESS 0

extern int kaezstd_init(ZSTD_CCtx* zc);
extern void kaezstd_release(ZSTD_CCtx* zc);
extern void kaezstd_setstatus(ZSTD_CCtx* zc, unsigned int status);
extern int kaezstd_compress(ZSTD_CCtx* zc, const void* src, size_t srcSize);

#endif
