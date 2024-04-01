/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd nosva compress header file
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */

#ifndef KAEZSTD_COMP_H
#define KAEZSTD_COMP_H

#include "kaezstd_common.h"

void kaezstd_setstatus_v1(ZSTD_CCtx* zc, unsigned int status);
int  kaezstd_compress_v1(ZSTD_CCtx* zc, const void* src, size_t srcSize);

#endif