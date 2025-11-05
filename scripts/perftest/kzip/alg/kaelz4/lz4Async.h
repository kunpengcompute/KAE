/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: common functions for algorithms
 * @Author: Ma Xiaofeng
 * @Date: 2025-7-31
 * @LastEditTime: 2025-7-31
 */

#ifndef LZ4_ASYNC_H
#define LZ4_ASYNC_H

int lz4_async_init(struct compress_ctx *ctx);
void lz4_async_cleanup(struct compress_ctx *ctx);
void lz4_async_polling(struct compress_session *sess, int budget);
void lz4_compress_async_callback(struct kaelz4_result *result);
void lz4_prepare_param_from_ctx(struct compress_ctx *ctx, struct compress_param *params);
void lz4_prepre_out_buf(struct compress_ctx *ctx, struct compress_out_buf *out_buf, struct compress_param *params);

#endif
