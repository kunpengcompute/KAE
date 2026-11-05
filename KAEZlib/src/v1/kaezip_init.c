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

#include "kaezip_dev.h"
#include "kaezip_init.h"
#include "kaezip_log.h"

void *kaezip_init_v1(int win_size, int is_sgl, int comp_type, int comp_algtype, const device_config_t *config)
{
    kaezip_ctx_t *kaezip_ctx = NULL;
    if (comp_type == WCRYPTO_DEFLATE && comp_algtype == WCRYPTO_RAW_DEFLATE) {
        kaezip_ctx = kaezip_get_ctx(WCRYPTO_GZIP, comp_type, win_size, is_sgl, config, ASYNC_MODE);
    } else {
        kaezip_ctx = kaezip_get_ctx(comp_algtype, comp_type, win_size, is_sgl, config, ASYNC_MODE);
    }
    if (!kaezip_ctx) {
        US_ERR("kaezlib failed to get kaezip ctx!");
        return NULL;
    }
    US_INFO("kaezlib deflate init success, kaezip_ctx %p!", kaezip_ctx);
    return kaezip_ctx;
}