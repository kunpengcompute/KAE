/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd adapter for sva(v2) and nosva(v1)
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-26
 */

#include <stdlib.h>
#include "kaelz4.h"
#include "kaelz4_adapter.h"
#include "kaelz4_log.h"
#include "uadk/wd.h"

static void uadk_get_accel_platform(void)
{
    if (g_platform >= 0) {
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
            goto end;
        }
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
     US_INFO("kaelz4 v%d inited!\n", g_platform);
}

int kaelz4_init(LZ4_CCtx* zc)
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
    US_INFO("kaelz4_init return code is %d\n", ret);
    return ret;
}

void kaelz4_reset(LZ4_CCtx* zc)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaezstd_reset_v1(zc);
        break;
    case HW_V2:
        break;
    default:
        break;
    }
    US_INFO("kaelz4_reset");
}

void kaelz4_release(LZ4_CCtx* zc)
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
    US_INFO("kaelz4_released");
}

void kaelz4_setstatus(LZ4_CCtx* zc, unsigned int status)
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
    US_INFO("kaelz4_set blk_type %d\n", status);
}

int kaelz4_compress(LZ4_CCtx* zc, const void* src, size_t srcSize)
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
    US_INFO("kaelz4_compress return code is %d\n", ret);
    return ret;
}