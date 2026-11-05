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

#include <stdio.h>
#include <stdlib.h>
#include "kaezip_log.h"
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
    } else if (partId == 0xD22 || partId == 0xD06) {
        g_arch = CPU_HISILICOM_V4;
    }
    return g_arch;
}

HIDDEN_API void CONSTRUCTOR KaeZlibInit(void)
{
    if (g_kaezlibInitialized != 0) {
        return;
    }
    // init log module
    kaezip_debug_init_log();

    if (KaeZlibDetect() == CPU_UNKNOW) {
        fprintf(stderr, "KAEZlib is running into an error, please check CPU ID.\n");
        abort();
    }
    g_kaezlibInitialized = 1;
}

int kaezip_check_support_deflate(void)
{
    return g_arch >= CPU_HISILICOM_V2;
}
