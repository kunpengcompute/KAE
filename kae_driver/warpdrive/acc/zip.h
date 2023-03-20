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

#ifndef __ACC_ZIP_H__
#define __ACC_ZIP_H__

#include "acc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int acc_zip_init(struct acc_ctx *ctx);
int acc_zip_clear(struct acc_ctx *ctx);
int acc_zip_poll(struct acc_ctx *ctx, int num, int* remainder);
int acc_zip_get_dev_idle_state(int *state);

#ifdef __cplusplus
}
#endif
#endif
