/*****************************************************************************
 * @file kaelz4_dev.h
 *
 * This file defines the data structures and constants for KAE ZIP accelerator
 * devices, including device descriptors, selection policies, and related macros.
 *
 *****************************************************************************/

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