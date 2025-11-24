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

int  kaesnappy_init_v1(SNAPPY_CCtx* zc);
void kaesnappy_release_v1(SNAPPY_CCtx* zc);

#endif