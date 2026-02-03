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
