/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae common defines
 * Author: DSA
 * Create: 2024-7-6
 */

#ifndef KAELZ4_COMMON_H
#define KAELZ4_COMMON_H

#define CONF_KAELZ4

#define KAE_LZ4_PROCESS_IDLE 0
#define KAE_LZ4_PROCESS_HW_BUSY -1

enum kae_lz4_async_data_format {
    KAELZ4_ASYNC_SMALL_BLOCK = 0,
    KAELZ4_ASYNC_BLOCK,
    KAELZ4_ASYNC_FRAME,
    KAELZ4_ASYNC_BUTT,
};

#include "kaelz4.h"

#endif
