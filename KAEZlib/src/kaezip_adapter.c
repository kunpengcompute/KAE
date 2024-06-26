/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: adapter of Zlib(now for v1-wrapdriver and v2-uadk)
 * @Author: LiuYongYang
 * @Date: 2023-05-08
*/

#include "kaezip.h"
#include "wd_comp.h"
#include "kaezip_adapter.h"
#include "kaezip_init.h"
#include "kaezip_comp.h"
#include "kaezip_deflate.h"
#include "kaezip_inflate.h"
#include "kaezip_log.h"

enum {
    HW_NONE,
    HW_V1,
    HW_V2,
    HW_V3   //  unused now
};
static int g_platform = -1;

static void uadk_get_accel_platform(void)
{
    if (g_platform >= 0) {
        return;
    }
    //	init log
    kaezip_debug_init_log();
    //  check sva
    struct uacce_dev* dev = wd_get_accel_dev("zlib");
    if (dev) {
        int flag = dev->flags;
        free(dev);
        if (flag & 0x1) {
            g_platform = HW_V2;
            goto end;
        }
    }
    //  check no-sva
    int nosva_dev_num = wd_get_available_dev_num("zlib");
    if (nosva_dev_num > 0) {
        g_platform = HW_V1;
        goto end;
    }
    //  hardware don't support, use zlib original interface
    g_platform = HW_NONE;
end:
    US_INFO("g_platform is %d, inited!\n", g_platform);
}

/* -----------------------------------------------DEFLATE----------------------------------------------- */
int kz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                const char *version, int stream_size)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_deflateInit2_(strm, level, metho, windowBit, memLevel, strategy, version, stream_size);
        break;
    case HW_V1:
        ret = kz_deflateInit2_v1(strm, level, metho, windowBit, memLevel, strategy, version, stream_size);
        break;
    case HW_V2:
        if (level <= 0) {
            level = 1;
        } else if (level > 9) {
            level = 9;
        }
        ret = kz_deflate_init(strm, level, windowBit);
        if (ret == Z_OK) {
            (void)kz_deflate_reset(strm);
        }
        break;
    default:
        break;
    }
    US_INFO("kz_deflateInit2 return code is %d\n", ret);
    return ret;
}

int kz_deflate(z_streamp strm, int flush)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    unsigned long kaezip_ctx;
    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_deflate(strm, flush);
        break;
    case HW_V1:
        kaezip_ctx = getDeflateKaezipCtx(strm);
        if (kaezip_ctx != 0 && flush != Z_PARTIAL_FLUSH && flush != Z_TREES) {
            ret = kz_deflate_v1(strm, flush);
        } else {
            US_WARN("HW_V1: using lz_deflate! kaezip_ctx is %lu, flush is %d", kaezip_ctx, flush);
            ret = lz_deflate(strm, flush);
        }
        break;
    case HW_V2:
        ret = kz_deflate_v2(strm, flush);
        break;
    default:
        break;
    }
    US_INFO("kz_deflate return code is %d\n", ret);
    return ret;
}

int kz_deflateEnd(z_streamp strm)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_deflateEnd(strm);
        break;
    case HW_V1:
        ret = kz_deflateEnd_v1(strm);
        break;
    case HW_V2:
        ret = kz_deflate_end(strm);
        break;
    default:
        break;
    }
    US_INFO("kz_deflateEnd return code is %d\n", ret);
    return ret;
}

int kz_deflateReset(z_streamp strm)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_deflateReset(strm);
        break;
    case HW_V1:
        ret = kz_deflateReset_v1(strm);
        break;
    case HW_V2:
        ret = kz_deflate_reset(strm);
        break;
    default:
        break;
    }
    US_INFO("kz_deflateReset return code is %d\n", ret);
    return ret;
}

/* -----------------------------------------------INFLATE----------------------------------------------- */
int kz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_inflateInit2_(strm, windowBits, version, stream_size);
        break;
    case HW_V1:
        ret = kz_inflateInit2_v1(strm, windowBits, version, stream_size);
        break;
    case HW_V2:
        ret = kz_inflate_init(strm, windowBits);
        if (ret == Z_OK) {
            (void)kz_inflate_reset(strm);
        }
        break;
    default:
        break;
    }
    US_INFO("kz_inflateInit2 return code is %d\n", ret);
    return ret;
}

int kz_inflate(z_streamp strm, int flush)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    int alg_type;
    unsigned long kaezip_ctx;
    flush = (flush == Z_PARTIAL_FLUSH ? Z_NO_FLUSH : flush);

    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_inflate(strm, flush);
        break;
    case HW_V1:
        alg_type = kz_getAutoInflateAlgType(strm);
        (void)kz_do_inflateInit(strm, alg_type);
        kaezip_ctx = getInflateKaezipCtx(strm);
        if (kaezip_ctx != 0 && flush != Z_TREES) {
            ret = kz_inflate_v1(strm, flush);
        } else {
            US_WARN("HW_V1: using lz_inflate! kaezip_ctx is %lu, flush is %d", kaezip_ctx, flush);
            ret = lz_inflate(strm, flush);
        }
        break;
    case HW_V2:
        ret = kz_inflate_v2(strm, flush);
        break;
    default:
        break;
    }
    US_INFO("kz_inflate return code is %d\n", ret);
    return ret;
}

int kz_inflateEnd(z_streamp strm)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_inflateEnd(strm);
        break;
    case HW_V1:
        ret = kz_inflateEnd_v1(strm);
        break;
    case HW_V2:
        ret = kz_inflate_end(strm);
        break;
    default:
        break;
    }
    US_INFO("kz_inflateEnd return code is %d\n", ret);
    return ret;
}

int kz_inflateReset(z_streamp strm)
{
    uadk_get_accel_platform();

    int ret = Z_ERRNO;
    switch (g_platform)
    {
    case HW_NONE:
        ret = lz_inflateReset(strm);
        break;
    case HW_V1:
        ret = kz_inflateReset_v1(strm);
        break;
    case HW_V2:
        ret = kz_inflate_reset(strm);
        break;
    default:
        break;
    }
    US_INFO("kz_inflateReset return code is %d\n", ret);
    return ret;
}
