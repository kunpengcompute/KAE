/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * @Description: kaezip nosva init head file
 * @Author: MaXiaoFeng
 * @Date: 2025-07-09
 * @LastEditTime: 2025-07-09
 */

#include "kaezip.h"
#include "kaezip_init.h"
#include "kaezip_log.h"

void *kaezip_init_v1(int win_size, int is_sgl, int comp_type)
{
    kaezip_ctx_t *kaezip_ctx = kaezip_get_ctx(WCRYPTO_RAW_DEFLATE, comp_type, win_size, is_sgl);
    if (!kaezip_ctx) {
        US_ERR("kaezlib failed to get kaezip ctx!");
        return NULL;
    }
    US_INFO("kaezlib deflate init success, kaezip_ctx %p!", kaezip_ctx);
    return kaezip_ctx;
}