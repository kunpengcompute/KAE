/* Copyright (c) 2019 Huawei Technologies Co., Ltd Limited. */

/**
 **************************************************************
 * @file rde.h
 *
 *
 *
 *
 * @brief This is the top level definition for rde modules.
 *
 * @details
 *
 */

#ifndef __RDE_H__
#define __RDE_H__

#include "acc.h"
#include "wd_ec.h"
#include "wd_bmm.h"
#include "wd_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/*POOL_BLK_NUM should smaller than 4, otherwise will return error*/
#define RDE_POOL_BLK_NUM 2
#define RDE_POOL_ALIGN_SIZE 4096

enum rde_op_result {
	RDE_STATUS_NULL = 0,
	RDE_BD_ADDR_NO_ALIGN = 0x2,
	RDE_BD_RD_BUS_ERR = 0x3,
	RDE_IO_ABORT = 0x4,
	RDE_BD_ERR = 0x5,
	RDE_ECC_ERR = 0x6,
	RDE_SGL_ADDR_ERR = 0x7,
	RDE_SGL_PARA_ERR = 0x8,
	RDE_DATA_RD_BUS_ERR = 0x1c,
	RDE_DATA_WR_BUS_ERR = 0x1d,
	RDE_CRC_CHK_ERR = 0x1e,
	RDE_REF_CHK_ERR = 0x1f,
	RDE_DISK0_VERIFY = 0x20,
	RDE_DISK1_VERIFY = 0x21,
	RDE_DISK2_VERIFY = 0x22,
	RDE_DISK3_VERIFY = 0x23,
	RDE_DISK4_VERIFY = 0x24,
	RDE_DISK5_VERIFY = 0x25,
	RDE_DISK6_VERIFY = 0x26,
	RDE_DISK7_VERIFY = 0x27,
	RDE_DISK8_VERIFY = 0x28,
	RDE_DISK9_VERIFY = 0x29,
	RDE_DISK10_VERIFY = 0x2a,
	RDE_DISK11_VERIFY = 0x2b,
	RDE_DISK12_VERIFY = 0x2c,
	RDE_DISK13_VERIFY = 0x2d,
	RDE_DISK14_VERIFY = 0x2e,
	RDE_DISK15_VERIFY = 0x2f,
	RDE_DISK16_VERIFY = 0x30,
	RDE_CHAN_TMOUT = 0x31,
};

int acc_rde_init(struct acc_ctx *ctx);
int acc_rde_clear(struct acc_ctx *ctx);
int acc_rde_poll(struct acc_ctx *ctx, int num, int *reminder);


#ifdef __cplusplus
}
#endif

#endif /* __RDE_H__ */
