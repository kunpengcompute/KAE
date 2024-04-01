/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd nosva init
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-02-26
 */
#include "kaezstd_ctx.h"
#include "kaezstd_init.h"
#include "kaezstd_log.h"

int kaezstd_init_v1(ZSTD_CCtx* zc)
{
    kaezip_ctx_t* kaezip_ctx = kaezip_get_ctx(WCRYPTO_LZ77_ZSTD, WCRYPTO_DEFLATE);
    if (!kaezip_ctx) {
        US_ERR("kaezstd failed to get kaezip ctx!");
        return KAE_ZSTD_INIT_FAIL;
    }
    zc->kaeConfig = (uintptr_t)kaezip_ctx;

    US_INFO("kaezstd deflate init success, kaezip_ctx %p!", kaezip_ctx);
    return KAE_ZSTD_SUCC;
}

void kaezstd_release_v1(ZSTD_CCtx* zc)
{
    kaezip_ctx_t* kaezip_ctx = (kaezip_ctx_t*)zc->kaeConfig;
    if (kaezip_ctx) {
        kaezip_put_ctx(kaezip_ctx);
        US_INFO("kaezstd release");
    }
    zc->kaeConfig = 0;
}
