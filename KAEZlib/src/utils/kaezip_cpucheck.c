/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezip cpu check
 * @Author: LiuYongYang
 * @Date: 2024-04-26
 * @LastEditTime: 2024-04-26
 */
#include <stdio.h>
#include <stdlib.h>
#include "kaezip_cpucheck.h"

static int g_kaezlibInitialized = 0;
static ARCH_TYPE g_arch = CPU_UNKNOW;

static ARCH_TYPE KaeZlibDetect(void)
{
    unsigned long long cpuId;
    __asm__ volatile("mrs %0, MIDR_EL1":"=r"(cpuId));

    unsigned long long vendor = (cpuId >> 0x18) & 0xFF;
    unsigned long long partId = (cpuId >> 0x4) & 0xFFF;
    if ((vendor == 0x48) && (partId == 0xD01)) {
        g_arch = CPU_HISILICOM_V1;
    } else if ((vendor == 0x48) && (partId == 0xD02)) {
        g_arch = CPU_HISILICOM_V2;
    } else if ((vendor == 0x48) && (partId == 0xD03)) {
        g_arch = CPU_HISILICOM_V3;
    } else if (partId == 0xD22) {
        g_arch = CPU_HISILICOM_V4;
    }
    return g_arch;
}

HIDDEN_API void CONSTRUCTOR KaeZlibInit(void)
{
    if (g_kaezlibInitialized != 0) {
        return;
    }

    if (KaeZlibDetect() == CPU_UNKNOW) {
        fprintf(stderr, "KAEZlib is running into an error, please check CPU ID.\n");
        abort();
    }
    g_kaezlibInitialized = 1;
}

int kaezip_checkCpu_isV2(void)
{
    return g_arch == CPU_HISILICOM_V2;
}
