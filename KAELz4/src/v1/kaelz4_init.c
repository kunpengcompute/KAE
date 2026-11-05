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
