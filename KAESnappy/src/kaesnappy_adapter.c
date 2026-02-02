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

#include <stdlib.h>
#include <semaphore.h>
#include "kaesnappy_common.h"
#include "kaesnappy.h"
#include "kaesnappy_utils.h"
#include "kaesnappy_adapter.h"
#include "kaesnappy_log.h"
#include "uadk/wd.h"

pthread_mutex_t g_task_queue_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_platform = -1;

static void uadk_get_accel_platform(void)
{
    if (g_platform >= 0) {
        return;
    }

    //  check no-sva
    int nosva_dev_num = wd_get_available_dev_num("lz77_zstd");
    if (nosva_dev_num > 0) {
        g_platform = HW_V1;
        goto end;
    }
    //  hardware don't support, use zstd original interface
    g_platform = HW_NONE;
end:
     US_INFO("kaesnappy v%d inited!\n", g_platform);
}

int kaesnappy_init(SNAPPY_CCtx* zc)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaesnappy_init_v1(zc);
        break;
    default:
        break;
    }
    US_INFO("kaesnappy_init return code is %d\n", ret);
    return ret;
}

void kaesnappy_release(SNAPPY_CCtx* zc)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaesnappy_release_v1(zc);
        break;
    default:
        break;
    }
    US_INFO("kaesnappy_released");
}

int kaesnappy_compress(SNAPPY_CCtx* zc, const void* src, size_t srcSize)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaesnappy_compress_v1(zc, src, srcSize);
        break;
    default:
        break;
    }
    US_INFO("kaesnappy_compress return code is %d\n", ret);
    return ret;
}
