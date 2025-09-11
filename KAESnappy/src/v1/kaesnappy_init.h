/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy nosva init head file
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-02-26
 */

#ifndef KAESNAPPY_INIT_H
#define KAESNAPPY_INIT_H

#include "kaesnappy_common.h"

int  kaelz4_init_v1(LZ4_CCtx* zc);
void kaelz4_reset_v1(LZ4_CCtx* zc);
void kaelz4_release_v1(LZ4_CCtx* zc);

#endif