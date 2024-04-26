/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezip cpu check header
 * @Author: LiuYongYang
 * @Date: 2024-04-26
 * @LastEditTime: 2024-04-26
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

int kaezip_checkCpu_isV2(void);

#endif
