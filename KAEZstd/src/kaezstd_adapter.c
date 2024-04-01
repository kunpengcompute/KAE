/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd adapter for sva(v2) and nosva(v1)
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-26
 */

#include <stdlib.h>
#include "kaezstd.h"
#include "kaezstd_adapter.h"
#include "kaezstd_log.h"
#include "uadk/wd.h"

static void uadk_get_accel_platform(void)
{
    if (g_platform >= 0) {
        US_INFO("kaezstd v%d inited!\n", g_platform);
        return;
    }
    //  init log
    kaezstd_debug_init_log();
    //  check sva
    struct uacce_dev* dev = wd_get_accel_dev("lz77_zstd");
    if (dev) {
        int flag = dev->flags;
        free(dev);
        if (flag & 0x1) {
            g_platform = HW_V2;
            return;
        }
    }
    //  check no-sva
    int nosva_dev_num = wd_get_available_dev_num("lz77_zstd");
    if (nosva_dev_num > 0) {
        g_platform = HW_V1;
        return;
    }
    //  hardware don't support, use zstd original interface
    g_platform = HW_NONE;
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
    case HW_V2:
        ret = kaezstd_init_v2(zc);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_init return code is %d\n", ret);
    return ret;
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
    case HW_V2:
        kaezstd_release_v2(zc);
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
    case HW_V2:
        kaezstd_setstatus_v2(zc, status);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_setstatus %d\n", status);
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
    case HW_V2:
        ret = kaezstd_compress_v2(zc, src, srcSize);
        break;
    default:
        break;
    }
    US_INFO("kaezstd_compress return code is %d\n", ret);
    return ret;
}