/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae common defines
 * Author: songchao
 * Create: 2021-7-19
 */

#ifndef KAEZSTD_COMMON_H
#define KAEZSTD_COMMON_H

#define CONF_KAEZSTD

#define KAE_ZSTD_SUCC 0
#define KAE_ZSTD_INVAL_PARA 1
#define KAE_ZSTD_INIT_FAIL 2
#define KAE_ZSTD_COMP_FAIL 3
#define KAE_ZSTD_RELEASE_FAIL 4
#define KAE_ZSTD_ALLOC_FAIL 5
#define KAE_ZSTD_SET_FAIL 6

#include "kaezstd.h"

#include "zstd.h"
#include "zstd_internal.h"
#include "zstd_compress_internal.h"
#endif
