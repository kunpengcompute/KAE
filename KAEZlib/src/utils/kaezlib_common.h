/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae common defines
 * Author: DSA
 * Create: 2024-7-6
 */

#ifndef KAEZLIB_COMMON_H
#define KAEZLIB_COMMON_H

#define CONF_KAEZLIB

#define KAE_ZLIB_PROCESS_IDLE 0
#define KAE_ZLIB_PROCESS_HW_BUSY -1

enum kaezip_async_data_format {
    KAEZIP_ASYNC_BLOCK = 0,
    KAEZIP_ASYNC_BUTT,
};

#include "kaezip.h"

#endif