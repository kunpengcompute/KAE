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
#include "kaesnappy_log.h"
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
    } else if (partId == 0xD22 || partId == 0xD06) {
        return CPU_HISILICOM_V4;
    }
    return CPU_UNKNOW;
}

HIDDEN_API void CONSTRUCTOR KaeSnappyInit(void)
{
    if (g_kaesnappyInitialized != 0) {
        return;
    }

    kaesnappy_debug_init_log();

    if (KaeSnappyDetect() == CPU_HISILICOM_V1 || KaeSnappyDetect() == CPU_UNKNOW) {
        fprintf(stderr, "KAEsnappy only support in V2+, please check CPU ID.\n");
        abort();
    }
    g_kaesnappyInitialized = 1;
}
