/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaelz4 nosva init
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-02-26
 */
#include "kaelz4_ctx.h"
#include "kaelz4_init.h"
#include "kaelz4_log.h"
#include "kaelz4_dev.h"

int kaelz4_init_v1(LZ4_CCtx* zc, int is_sgl, operation_mode mode, const kaelz4_device_config_t *config)
{   
    kaelz4_ctx_t* kaelz4_ctx = kaelz4_get_ctx(WCRYPTO_LZ77_ONLY, WCRYPTO_DEFLATE, is_sgl, mode, config);
    if (!kaelz4_ctx) {
        US_ERR("kaelz4 failed to get kaezip ctx!");
        return KAE_LZ4_INIT_FAIL;
    }
    zc->kaeConfig = (uintptr_t)kaelz4_ctx;

    US_INFO("kaelz4 deflate init success, kaelz4_ctx %p!", kaelz4_ctx);
    return KAE_LZ4_SUCC;
}

void kaelz4_reset_v1(LZ4_CCtx* zc)
{
    kaelz4_ctx_t* kaelz4_ctx = (kaelz4_ctx_t*)zc->kaeConfig;
    if (kaelz4_ctx) {
        kaelz4_ctx->status = KAEZIP_COMP_INIT;
        kaelz4_ctx->lz4_data.blk_type = 2; //  lz4 compressed block
        US_DEBUG("kaelz4 reset v1");
    }
}

void kaelz4_release_v1(LZ4_CCtx* zc)
{
    kaelz4_ctx_t* kaelz4_ctx = (kaelz4_ctx_t*)zc->kaeConfig;
    if (kaelz4_ctx) {
        kaelz4_put_ctx(kaelz4_ctx);
        US_INFO("kaelz4 release v1");
    }
    zc->kaeConfig = 0;
}
