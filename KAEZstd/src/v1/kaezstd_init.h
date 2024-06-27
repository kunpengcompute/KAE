/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd nosva init head file
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-02-26
 */

#ifndef KAEZSTD_INIT_H
#define KAEZSTD_INIT_H

#include "kaezstd_common.h"

int  kaezstd_init_v1(ZSTD_CCtx* zc);
void kaezstd_reset_v1(ZSTD_CCtx* zc);
void kaezstd_release_v1(ZSTD_CCtx* zc);

#endif