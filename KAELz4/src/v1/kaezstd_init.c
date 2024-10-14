/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd nosva init
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-02-26
 */
#include "kaezstd_ctx.h"
#include "kaezstd_init.h"
#include "kaelz4_log.h"

int kaezstd_init_v1(LZ4_CCtx* zc)
{
    kaezstd_ctx_t* kaezstd_ctx = kaezstd_get_ctx(WCRYPTO_LZ77_ZSTD, WCRYPTO_DEFLATE);
    if (!kaezstd_ctx) {
        US_ERR("kaezstd failed to get kaezip ctx!");
        return KAE_ZSTD_INIT_FAIL;
    }
    zc->kaeConfig = (uintptr_t)kaezstd_ctx;

    US_INFO("kaezstd deflate init success, kaezstd_ctx %p!", kaezstd_ctx);
    return KAE_ZSTD_SUCC;
}

void kaezstd_reset_v1(LZ4_CCtx* zc)
{
    kaezstd_ctx_t* kaezstd_ctx = (kaezstd_ctx_t*)zc->kaeConfig;
    if (kaezstd_ctx) {
        kaezstd_ctx->status = KAEZIP_COMP_INIT;
        kaezstd_ctx->zstd_data.blk_type = 2; //  zstd compressed block
        US_DEBUG("kaezstd reset v1");
    }
}

void kaezstd_release_v1(LZ4_CCtx* zc)
{
    kaezstd_ctx_t* kaezstd_ctx = (kaezstd_ctx_t*)zc->kaeConfig;
    if (kaezstd_ctx) {
        kaezstd_put_ctx(kaezstd_ctx);
        US_INFO("kaezstd release v1");
    }
    zc->kaeConfig = 0;
}
