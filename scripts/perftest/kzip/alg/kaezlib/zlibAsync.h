/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: common functions for algorithms
 * @Author: Ma Xiaofeng
 * @Date: 2025-7-31
 * @LastEditTime: 2025-7-31
 */

#ifndef ZLIB_ASYNC_H
#define ZLIB_ASYNC_H

void zlib_prepare_ctx(struct compress_ctx *ctx, struct compress_param *params);
void zlib_prepre_out_buf(struct compress_ctx *ctx, struct compress_out_buf *out_buf, struct compress_param *params);

#endif
