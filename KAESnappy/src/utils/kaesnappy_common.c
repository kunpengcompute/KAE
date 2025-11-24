/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: snappy common func
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-03-28
 */
#include <stdio.h>
#include <stdlib.h>
#include "kaesnappy_common.h"

#define HIDDEN_API  __attribute__((visibility("hidden")))
#define CONSTRUCTOR __attribute__((constructor))
typedef enum ARCH_TYPE {
    CPU_HISILICOM_V1 = 0, /* support nosva */
    CPU_HISILICOM_V2, /* support nosva and sva */
    CPU_HISILICOM_V3, /* for the future */
    CPU_HISILICOM_V4, /* for the future */
    CPU_UNKNOW,
} ARCH_TYPE;
static int g_kaesnappyInitialized = 0;

static ARCH_TYPE KaeSnappyDetect(void)
{
    unsigned long long cpuId;
    __asm__ volatile("mrs %0, MIDR_EL1":"=r"(cpuId));

    unsigned long long vendor = (cpuId >> 0x18) & 0xFF;
    unsigned long long partId = (cpuId >> 0x4) & 0xFFF;
    if ((vendor == 0x48) && (partId == 0xD01)) {
        return CPU_HISILICOM_V1;
    } else if ((vendor == 0x48) && (partId == 0xD02)) {
        return CPU_HISILICOM_V2;
    } else if ((vendor == 0x48) && (partId == 0xD03)) {
        return CPU_HISILICOM_V3;
    } else if (partId == 0xD22) {
        return CPU_HISILICOM_V4;
    }
    return CPU_UNKNOW;
}

HIDDEN_API void CONSTRUCTOR KaeSnappyInit(void)
{
    if (g_kaesnappyInitialized != 0) {
        return;
    }

    if (KaeSnappyDetect() == CPU_HISILICOM_V1 || KaeSnappyDetect() == CPU_UNKNOW) {
        fprintf(stderr, "KAEsnappy only support in V2+, please check CPU ID.\n");
        abort();
    }
    g_kaesnappyInitialized = 1;
}
