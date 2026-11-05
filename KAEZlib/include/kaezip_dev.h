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


#ifndef KAEZIP_DEV_H
#define KAEZIP_DEV_H

#define MAX_STR_SIZE 512
#define MAX_DEVICES  10
#define UACCE_CLASS_PATH "/sys/class/uacce"
#define ZIP_PREFIX       "hisi_zip-"

typedef enum {
    KAE_SELECT_AUTO    = 0,   // NUMA亲和性自动选择
    KAE_SELECT_BY_DEV  = 1,   // 通过设备指定
    KAE_SELECT_BY_NUMA = 2    // 通过 NUMA 节点指定
} device_select_policy_t;

struct zip_dev {
	int numa_id;                         // 所属 NUMA 节点
	char dev_name[MAX_STR_SIZE >> 1];    // hisi_zip-*
    char dev_root[MAX_STR_SIZE];         // /sys/class/uacce/hizi_zip-*
    unsigned int hw_id;                  // 硬件 ID ( eg: 8 for hisi_zip-8)
    unsigned int dev_id;                 // 逻辑 ID ( 0,1,2...)
};

typedef struct {
    device_select_policy_t policy;
    union {
        const struct zip_dev *dev;  // policy == KAE_SELECT_BY_DEV 时有效
        unsigned int numa_node;     // policy == KAE_SELECT_BY_NUMA 时有效
    } param;
} device_config_t;

#define KAE_CONFIG_AUTO() \
    (device_config_t){ .policy = KAE_SELECT_AUTO }

#define KAE_CONFIG_BY_DEV(dev_ptr) \
    (device_config_t){ .policy = KAE_SELECT_BY_DEV, .param.dev = (dev_ptr) }

#define KAE_CONFIG_BY_NUMA(node) \
    (device_config_t){ .policy = KAE_SELECT_BY_NUMA, .param.numa_node = (node) }

#endif