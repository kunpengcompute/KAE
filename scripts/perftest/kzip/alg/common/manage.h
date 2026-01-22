
/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: contain and manage all support algorithms
 * @Author: Ma Xiaofeng
 * @Date: 2025-3-31
 * @LastEditTime: 2025-3-31
 */


#ifndef MANAGE_H
#define MANAGE_H
#include <lz4.h>
#include <lz4frame.h>

// 大页大小配置（由Makefile传入，与hugepage.c保持一致）
#ifndef HPAGE_SIZE_BYTES
#define HPAGE_SIZE_BYTES (1024 * 1024 * 1024)  // 默认1GB
#endif
#define HPAGE_SIZE HPAGE_SIZE_BYTES

#define HW_MAX_SGE_LEN 0x800000UL

typedef enum ALG_TYPE {
    ALG_KAE_LZ4,
    ALG_KAE_ZLIB,
    ALG_QAT_LZ4,
    ALG_QAT_DEFLATE,
} alg_type_enum;

struct compress_ctx;
struct compress_param;
struct compress_out_buf;
struct compress_session;

typedef struct {
    enum ALG_TYPE alg_type;
    const char *name;
    // 同步接口
    int (*init)(struct compress_ctx *ctx);
    int (*bound)(int src_len);
    // 我们约定：由框架统一读取待处理的数据以及大小。统一申请待存储的空间以及大小。
    // 压缩解压算法需要输出正确的处理后产物，输出正确的 dst_len。
    // 统一返回 0 表示算法OK
    // 返回其他表示压缩解压异常
    int (*compress)(struct compress_param *param);
    int (*decompress)(struct compress_param *param);
    void (*cleanup)(struct compress_ctx *ctx);
    void (*prepare_param)(struct compress_ctx *ctx, struct compress_param *param);
    void (*prepare_outbuf)(struct compress_ctx *ctx, struct compress_out_buf *out_buf, struct compress_param *param);
    void (*poll)(struct compress_session *sess, int budget); // polling 模式下，根据session查询结果的接口
    // 异步接口
    int (*async_compress)(struct compress_session *sess, struct compress_param *param);

    int (*async_decompress)(struct compress_session *sess, struct compress_param *param);
} compression_algorithm_t;

// 注册算法
void register_algorithm(compression_algorithm_t *algorithm);

// 根据名称查找算法
compression_algorithm_t *get_algorithm(const char *name);

int vaild_algorithm(const char *name);

// 初始化所有算法（自动注册）
void initialize_algorithms(void);

void register_lz4_algorithm(void);
void register_lz4_frame_algorithm(void);
void register_lz4async_block_algorithm(void);
void register_lz4async_frame_algorithm(void);
void register_lz4async_lz77_algorithm(void);
void register_lz4async_lz77_frame_algorithm(void);
void register_zlib_algorithm(void);
void register_zlib_deflate_algorithm(void);
void register_zlibasync_block_algorithm(void);

#endif
