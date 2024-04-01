/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: zstd common func
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-03-28
 */
#include <stdio.h>
#include <stdlib.h>
#include "kaezstd_common.h"

#define HIDDEN_API  __attribute__((visibility("hidden")))
#define CONSTRUCTOR __attribute__((constructor))
typedef enum ARCH_TYPE {
    CPU_HISILICOM_TSV110 = 0, /* support nosva */
    CPU_HISILICOM_920B, /* support nosva and sva */
    CPU_HISILICOM_920C, /* for the future */
    CPU_HISILICOM_920F, /* for the future */
    CPU_UNKNOW,
} ARCH_TYPE;
static int g_kaezstdInitialized = 0;

static inline void versionCpy(char str1[], const char str2[])
{
    int i = 0;
    while (i < VERSION_STRUCT_LEN && str2[i] != '\0') {
        str1[i] = str2[i];
        ++i;
    }
    str1[i] = '\0';
}

int kaezstd_get_version(KAEZstdVersion* ver)
{
    if (ver == NULL) {
        return KAE_ZSTD_INVAL_PARA;
    }
    versionCpy(ver->productName, "Kunpeng Boostkit");
    versionCpy(ver->productVersion, "23.0.RC2");
    versionCpy(ver->componentName, "KAEZstd");
    versionCpy(ver->componentVersion, "2.0.2");
    return KAE_ZSTD_SUCC;
}

static ARCH_TYPE KaeZstdDetect(void)
{
    unsigned long long cpuId;
    __asm__ volatile("mrs %0, MIDR_EL1":"=r"(cpuId));

    unsigned long long vendor = (cpuId >> 0x18) & 0xFF;
    unsigned long long partId = (cpuId >> 0x4) & 0xFFF;
    if ((vendor == 0x48) && (partId == 0xD01)) {
        return CPU_HISILICOM_TSV110;
    } else if ((vendor == 0x48) && (partId == 0xD02)) {
        return CPU_HISILICOM_920B;
    } else if ((vendor == 0x48) && (partId == 0xD03)) {
        return CPU_HISILICOM_920C;
    } else if (partId == 0xD22) {
        return CPU_HISILICOM_920F;
    }
    return CPU_UNKNOW;
}

HIDDEN_API void CONSTRUCTOR KaeZstdInit(void)
{
    if (g_kaezstdInitialized != 0) {
        return;
    }

    if (KaeZstdDetect() != CPU_HISILICOM_920B) {
        fprintf(stderr, "KAEzstd only support in KP920B, please check CPU ID.\n");
        abort();
    }
    g_kaezstdInitialized = 1;
}
