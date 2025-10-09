/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * @Description: kaezip nosva init head file
 * @Author: MaXiaoFeng
 * @Date: 2025-07-09
 * @LastEditTime: 2025-07-09
 */

#ifndef KAEZIP_INIT_H
#define KAEZIP_INIT_H

#include "kaezip_common.h"

void *kaezip_init_v1(int win_size, int is_sgl, int comp_type, int comp_algtype, const device_config_t *config);

#endif