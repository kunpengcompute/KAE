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

#ifndef KAEZIP_CPUCHECK_H
#define KAEZIP_CPUCHECK_H

#define HIDDEN_API  __attribute__((visibility("hidden")))
#define CONSTRUCTOR __attribute__((constructor))
typedef enum ARCH_TYPE {
    CPU_HISILICOM_V1 = 0, /* support nosva */
    CPU_HISILICOM_V2, /* support nosva and sva */
    CPU_HISILICOM_V3, /* for the future */
    CPU_HISILICOM_V4, /* for the future */
    CPU_UNKNOW,
} ARCH_TYPE;

int kaezip_check_support_deflate(void);

#endif
