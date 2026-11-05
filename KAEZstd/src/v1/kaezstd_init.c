/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kaezstd_ctx.h"
#include "kaezstd_init.h"
#include "kaezstd_log.h"

int kaezstd_init_v1(ZSTD_CCtx* zc)
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

void kaezstd_reset_v1(ZSTD_CCtx* zc)
{
    kaezstd_ctx_t* kaezstd_ctx = (kaezstd_ctx_t*)zc->kaeConfig;
    if (kaezstd_ctx) {
        kaezstd_ctx->status = KAEZIP_COMP_INIT;
        kaezstd_ctx->zstd_data.blk_type = 2; //  zstd compressed block
        US_DEBUG("kaezstd reset v1");
    }
}

void kaezstd_release_v1(ZSTD_CCtx* zc)
{
    kaezstd_ctx_t* kaezstd_ctx = (kaezstd_ctx_t*)zc->kaeConfig;
    if (kaezstd_ctx) {
        kaezstd_put_ctx(kaezstd_ctx);
        US_INFO("kaezstd release v1");
    }
    zc->kaeConfig = 0;
}
