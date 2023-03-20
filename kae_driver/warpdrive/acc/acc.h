/* Copyright (c) 2019 Huawei Technologies Co., Ltd Limited. */

/**
 *
 * @brief This is the top level definition for inner modules.
 *
 * @details
 *
 */

#ifndef __ACC_H__
#define __ACC_H__

#include <stddef.h>
#include <stdint.h>
#include "acc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

struct acc_inner {
	void *wd_ctx;
	void *q;
	void *pool;
	int ref_cnt;
};

int acc_transform_err_code(int value);

#ifdef __cplusplus
}
#endif
#endif /* __ACC_H__ */
