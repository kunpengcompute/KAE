/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: lz4 common func
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-03-28
 */
#include <stdio.h>
#include <stdlib.h>
#include "kaelz4_common.h"

#define HIDDEN_API __attribute__((visibility("hidden")))
#define CONSTRUCTOR __attribute__((constructor))
typedef enum ARCH_TYPE {
    CPU_HISILICOM_V1 = 0, /* support nosva */
    CPU_HISILICOM_V2,     /* support nosva and sva */
    CPU_HISILICOM_V3,     /* for the future */
    CPU_HISILICOM_V4,     /* for the future */
    CPU_UNKNOW,
} ARCH_TYPE;
static int g_kaelz4Initialized = 0;

static inline void versionCpy(char str1[], const char str2[])
{
    int i = 0;
    while (i < VERSION_STRUCT_LEN - 1 && str2[i] != '\0') {
        str1[i] = str2[i];
        ++i;
    }
    str1[i] = '\0';
}

int kaelz4_get_version(KAELz4Version *ver)
{
    if (ver == NULL) {
        return KAE_LZ4_INVAL_PARA;
    }
    versionCpy(ver->productName, "Kunpeng Boostkit");
    versionCpy(ver->productVersion, "26.1.0");
    versionCpy(ver->componentName, "KAELz4");
    versionCpy(ver->componentVersion, "2.2.0");
    return KAE_LZ4_SUCC;
}

static ARCH_TYPE KaeLz4Detect(void)
{
    unsigned long long cpuId;
    __asm__ volatile("mrs %0, MIDR_EL1" : "=r"(cpuId));

    unsigned long long vendor = (cpuId >> 0x18) & 0xFF;
    unsigned long long partId = (cpuId >> 0x4) & 0xFFF;
    if ((vendor == 0x48) && (partId == 0xD01)) {
        return CPU_HISILICOM_V1;
    } else if ((vendor == 0x48) && (partId == 0xD02)) {
        return CPU_HISILICOM_V2;
    } else if ((vendor == 0x48) && (partId == 0xD03)) {
        return CPU_HISILICOM_V3;
    } else if (partId == 0xD22 || partId == 0xD06) {
        return CPU_HISILICOM_V4;
    }
    return CPU_UNKNOW;
}

HIDDEN_API void CONSTRUCTOR KaeLz4Init(void)
{
    if (g_kaelz4Initialized != 0) {
        return;
    }

    if (KaeLz4Detect() == CPU_HISILICOM_V1 || KaeLz4Detect() == CPU_UNKNOW) {
        fprintf(stderr, "KAElz4 only support in V2+, please check CPU ID.\n");
        abort();
    }
    g_kaelz4Initialized = 1;
}
