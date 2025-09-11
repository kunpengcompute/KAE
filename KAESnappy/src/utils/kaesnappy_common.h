/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae common defines
 * Author: DSA
 * Create: 2024-7-6
 */

#ifndef KAESNAPPY_COMMON_H
#define KAESNAPPY_COMMON_H

#define CONF_KAESNAPPY

#define KAE_SNAPPY_PROCESS_IDLE 0
#define KAE_SNAPPY_PROCESS_HW_BUSY -1

enum kae_snappy_async_data_format {
    KAESNAPPY_ASYNC_SMALL_BLOCK = 0,
    KAESNAPPY_ASYNC_BLOCK,
    KAESNAPPY_ASYNC_FRAME,
    KAESNAPPY_ASYNC_BUTT,
};

#include "kaesnappy.h"

#endif
