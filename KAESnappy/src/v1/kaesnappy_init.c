/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy nosva init
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-02-26
 */
#include "kaesnappy_ctx.h"
#include "kaesnappy_init.h"
#include "kaesnappy_log.h"

int kaesnappy_init_v1(SNAPPY_CCtx* zc)
{
    kaesnappy_ctx_t* kaesnappy_ctx = kaesnappy_get_ctx(WCRYPTO_LZ77_ONLY, WCRYPTO_DEFLATE);
    if (!kaesnappy_ctx) {
        US_ERR("kaesnappy failed to get kaezip ctx!");
        return KAE_SNAPPY_INIT_FAIL;
    }
    zc->kaeConfig = (uintptr_t)kaesnappy_ctx;

    US_INFO("kaesnappy deflate init success, kaesnappy_ctx %p!", kaesnappy_ctx);
    return KAE_SNAPPY_SUCC;
}

void kaesnappy_release_v1(SNAPPY_CCtx* zc)
{
    kaesnappy_ctx_t* kaesnappy_ctx = (kaesnappy_ctx_t*)zc->kaeConfig;
    if (kaesnappy_ctx) {
        kaesnappy_put_ctx(kaesnappy_ctx);
        US_INFO("kaesnappy release v1");
    }
    zc->kaeConfig = 0;
}
