/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezstd adapter for sva(v2) and nosva(v1) header file
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-22
 */

#ifndef KAEZSTD_ADAPTER
#define KAEZSTD_ADAPTER

enum {
    HW_NONE,
    HW_V1,
    HW_V2,
    HW_V3   //  unused now
};
static int g_platform = -1;

extern int  kaezstd_init_v1(ZSTD_CCtx* zc);
extern void kaezstd_reset_v1(ZSTD_CCtx* zc);
extern void kaezstd_release_v1(ZSTD_CCtx* zc);
extern void kaezstd_setstatus_v1(ZSTD_CCtx* zc, unsigned int status);
extern int  kaezstd_compress_v1(ZSTD_CCtx* zc, const void* src, size_t srcSize);

extern int  kaezstd_init_v2(ZSTD_CCtx* zc);
extern void kaezstd_release_v2(ZSTD_CCtx* zc);
extern void kaezstd_setstatus_v2(ZSTD_CCtx* zc, unsigned int status);
extern int  kaezstd_compress_v2(ZSTD_CCtx* zc, const void* src, size_t srcSize);

extern int wd_get_available_dev_num(const char* alogrithm);

#endif