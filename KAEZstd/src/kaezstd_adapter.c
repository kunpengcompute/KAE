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

#include "kaezstd.h"
#include "kaezstd_adapter.h"
#include "kaezstd_log.h"

static void uadk_get_accel_platform(void)
{
    if (g_platform >= 0) {
        return;
    }
    //  init log
    kaezstd_debug_init_log();
    //  check no-sva, v2 is not built in this library
    int nosva_dev_num = wd_get_available_dev_num("lz77_zstd");
    if (nosva_dev_num > 0) {
        g_platform = HW_V1;
        goto end;
    }
    //  hardware don't support, use zstd original interface
    g_platform = HW_NONE;
end:
     US_INFO("kaezstd v%d inited!\n", g_platform);
}

int kaezstd_init(ZSTD_CCtx* zc)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaezstd_init_v1(zc);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_init return code is %d\n", ret);
    return ret;
}

void kaezstd_reset(ZSTD_CCtx* zc)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaezstd_reset_v1(zc);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_reset");
}

void kaezstd_release(ZSTD_CCtx* zc)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaezstd_release_v1(zc);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_released");
}

void kaezstd_setstatus(ZSTD_CCtx* zc, unsigned int status)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaezstd_setstatus_v1(zc, status);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_set blk_type %d\n", status);
}

int kaezstd_compress(ZSTD_CCtx* zc, const void* src, size_t srcSize)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaezstd_compress_v1(zc, src, srcSize);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_compress return code is %d\n", ret);
    return ret;
}
