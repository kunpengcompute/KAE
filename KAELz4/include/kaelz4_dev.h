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

#ifndef KAELZ4_DEV_H
#define KAELZ4_DEV_H

#define MAX_STR_SIZE 512
#define MAX_DEVICES  10
#define UACCE_CLASS_PATH "/sys/class/uacce"
#define ZIP_PREFIX       "hisi_zip-"

typedef enum {
    KAELZ4_SELECT_AUTO    = 0,   // NUMA亲和性自动选择
    KAELZ4_SELECT_BY_DEV  = 1,   // 通过设备指定
    KAELZ4_SELECT_BY_NUMA = 2    // 通过 NUMA 节点指定
} kaelz4_device_select_policy_t;

struct lz4_dev {
	int numa_id;                  // 所属 NUMA 节点
	char dev_name[256];           // hisi_zip-*
    char dev_root[MAX_STR_SIZE];  // /sys/class/uacce/hizi_zip-*
    unsigned int hw_id;           // 硬件 ID ( - 后面的数字，如 hisi_zip-8)
    unsigned int dev_id;          // 逻辑 ID ( 0,1,2...)
};

typedef struct {
    kaelz4_device_select_policy_t policy;
    union {
        const struct lz4_dev *dev;  // policy == KAELZ4_SELECT_BY_DEV 时有效
        unsigned int numa_node;     // policy == KAELZ4_SELECT_BY_NUMA 时有效
    } param;
} kaelz4_device_config_t;

#define KAELZ4_CONFIG_AUTO() \
    (kaelz4_device_config_t){ .policy = KAELZ4_SELECT_AUTO }

#define KAELZ4_CONFIG_BY_DEV(dev_ptr) \
    (kaelz4_device_config_t){ .policy = KAELZ4_SELECT_BY_DEV, .param.dev = (dev_ptr) }

#define KAELZ4_CONFIG_BY_NUMA(node) \
    (kaelz4_device_config_t){ .policy = KAELZ4_SELECT_BY_NUMA, .param.numa_node = (node) }

#endif