/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaelz4 nosva init head file
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-02-26
 */

#ifndef KAELZ4_INIT_H
#define KAELZ4_INIT_H

#include "kaelz4_common.h"

int  kaelz4_init_v1(LZ4_CCtx* zc);
void kaelz4_reset_v1(LZ4_CCtx* zc);
void kaelz4_release_v1(LZ4_CCtx* zc);

#endif