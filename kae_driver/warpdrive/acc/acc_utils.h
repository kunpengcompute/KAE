/* Copyright (c) 2019 Huawei Technologies Co., Ltd Limited. */

/**
 **************************************************************
 * @file acc.h
 *
 *
 *
 *
 * @brief This is the top level definition for inner modules.
 *
 * @details
 *
 */

#ifndef __ACC_UTILS_H__
#define __ACC_UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include "acc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

extern acc_log dbg_log;
#define modeId 12
#define __FILENAME__ (strrchr(__FILE__, '/') ? \
                (strrchr(__FILE__, '/') + 1) : __FILE__)
#define ACC_LOG(fmt, ...)  dbg_log("[%s,%d,%s][%x]"fmt, (char*)__FILENAME__, \
                __LINE__, __func__, modeId, ##__VA_ARGS__)

void acc_free_sgl(struct sgl_hw *sgl);
void *acc_alloc_sgl(uint32_t dlen, uint32_t sge_size, uint32_t sgl_max_entry);
int acc_sgl_to_buf(struct sgl_hw *sgl, void *buf, size_t len, size_t offset);
int acc_buf_to_sgl(void *buf, struct sgl_hw *sgl, size_t len, size_t offset);

#ifdef __cplusplus
}
#endif
#endif /* __ACC_UTILS_H__ */
