/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: adapter of Zlib(now for v1-wrapdriver and v2-uadk) header file
 * @Author: LiuYongYang
 * @Date: 2023-05-08
 */

#ifndef KAEZIP_ADAPTER_H
#define KAEZIP_ADAPTER_H

/**
 * v1 interface, used for check hardware status
*/
extern int wd_get_available_dev_num(const char* alogrithm);

/**
 * adapter interface for zlib-open
 */
int kz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                const char *version, int stream_size);
int kz_deflate(z_streamp strm, int flush);
int kz_deflateEnd(z_streamp strm);
int kz_deflateReset(z_streamp strm);

int kz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
int kz_inflate(z_streamp strm, int flush);
int kz_inflateEnd(z_streamp strm);
int kz_inflateReset(z_streamp strm);

#endif
