/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy nosva compress header file
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */

#ifndef KAESNAPPY_COMP_H
#define KAESNAPPY_COMP_H

#include "kaesnappy_common.h"
#include <stdint.h>
#include <arm_acle.h>
#include <arm_neon.h>


#define TOKEN_NUM_CONTROL 0 // 用于控制生成压缩块中三元组数目，来保证解压速度（对齐实际match length需+3）
#define ML_BITS  4
#define ML_MASK  ((1U<<ML_BITS)-1)
#define RUN_BITS (8-ML_BITS)
#define RUN_MASK ((1U<<RUN_BITS)-1)
#define MFLIMIT       12
#define KAE_SNAPPY_REBUILD_FAIL -257
#define KAE_SNAPPY_SW_RETURN_0_FAIL -256

#define HARDWARE_BLOCK_SIZE (64 * 1024) // 硬件支持的最大压缩块大小

#if !defined(SNAPPY_memcpy)
#  if defined(__GNUC__) && (__GNUC__ >= 4)
#    define SNAPPY_memcpy(dst, src, size) __builtin_memcpy(dst, src, size)
#  else
#    define SNAPPY_memcpy(dst, src, size) memcpy(dst, src, size)
#  endif
#endif

#if defined(__x86_64__)
  typedef U64    reg_t;   /* 64-bits in x32 mode */
#else
  typedef size_t reg_t;   /* 32-bits in x32 mode */
#endif

typedef union { U16 u16; U32 u32; reg_t uArch; } __attribute__((packed)) SNAPPY_unalign;

struct kaesnappy_compress_ctx;
struct kaesnappy_async_req;


struct kaesnappy_compress_ctx {
    size_t srcSize;
    size_t dstCapacity;
    size_t dst_len;
    const void *src;
    void *dst;
    void *prev_last_lit_ptr; // 用户输入数据>64K需要分块、返回BLOCK格式、现有保序返回切块压缩结果的约束下，记录前一个分块的last literal信息
    size_t prev_last_lit_len;
    unsigned int recv_cnt;
    int status;
    snappy_async_callback callback;
    struct kaesnappy_result *result;
    enum kae_snappy_async_data_format data_format;
    int preferences;
    struct kaesnappy_async_req *req_list;
    struct kaesnappy_compress_ctx *next;
};

struct kaesnappy_async_req {
    SNAPPY_CCtx zc;
    const void* src;
    size_t src_size;
    U32 idx;
    U32 special_flag;
    U32 last;
    U32 done;
    struct kaesnappy_compress_ctx *compress_ctx;
    struct kaesnappy_async_req *next;
};

#define MAX_NUM_IN_COMP 2  // 每个线程最多允许同时进行的压缩任务数
struct kaesnappy_async_ctrl {
    struct kaesnappy_compress_ctx *ctx_head;
    struct kaesnappy_compress_ctx *tail;
    sw_compress_fn sw_compress;
    sw_compress_frame_fn sw_compress_frame;
    int cur_num_in_comp; // 当前正在压缩的任务数量
    kaesnappy_ctx_t *kz_ctx[MAX_NUM_IN_COMP];
    int ctx_index;
    volatile int *stop_flag;
};

int  kaesnappy_compress_v1(SNAPPY_CCtx* zc, const void* src, size_t srcSize);

// part1.frame模式的header & footer描述
#define KAESNAPPY_MAGIC_NUMBER    0x184D2204U
#define KAESNAPPY_MAGIC_SKIPPABLE 0x184D2A50U

#define KAESNAPPY_VERSION                  0x1        // version必须为01
#define KAESNAPPY_BLOCK_INDEPENDENCE_FLAG  0x1        // block间独立不依赖
#define KAESNAPPY_BLOCK_CHECKSUM_FLAG      (1 << 4)        // 各block不带checksum
#define KAESNAPPY_CONTENT_SIZE_FLAG        (1 << 3)        // 携带原始数据长度
#define KAESNAPPY_CONTENT_CHECKSUM_FLAG    (1 << 2)        // frame携带checksum
#define KAESNAPPY_DICTIONARY_ID_FLAG       0x0        // 不使用字典dict
#define KAESNAPPY_MAX_BLK_SIZE  0x4                   // 各block大小64KB
#define KAESNAPPY_ENDMARK       0x0                   // frame结束标志

#define KAESNAPPY_MAGIC_SIZE    4                     // magic number长度
#define KAESNAPPY_FRAMEDESCRIPTOR_SIZE     11         // frame descriptor长度
#define KAESNAPPY_HEADER_SIZE   (KAESNAPPY_MAGIC_SIZE + KAESNAPPY_FRAMEDESCRIPTOR_SIZE) // frame header长度

#define KAESNAPPY_BLOCK_HEADER_SIZE  4                // block header长度(4字节)
#define KAESNAPPY_STOREDBLOCK_FLAG   0x80000000U      // 长度为0的未压缩块，是有效的
#define KAESNAPPY_STORED_HEADER_SIZE 4

#define KAESNAPPY_CHECKSUM_SIZE 4                     // checksum长度
#define KAESNAPPY_ENDMARK_SIZE  4                     // endmark长度
#define KAESNAPPY_FOOTER_SIZE   (KAESNAPPY_CHECKSUM_SIZE + KAESNAPPY_ENDMARK_SIZE) // frame footer长度

// part2.首尾数据结构
// frame header
typedef struct KAESNAPPYH_S {
    uint32_t magic_number;
    uint8_t  flag_descriptor;
    uint8_t  block_descriptor;
    uint64_t content_size;
    uint8_t  header_checksum;
} KAESNAPPYH_T;

// frame footer
typedef struct KAESNAPPYF_S {
    uint32_t end_mark;
    uint32_t content_checksum;
} KAESNAPPYF_T;

// part4.功能函数
inline unsigned long KAESNAPPYHeaderSz(void)
{
    return KAESNAPPY_HEADER_SIZE;
}

inline unsigned long KAESNAPPYFooterSz(void)
{
    return KAESNAPPY_FOOTER_SIZE;
}

inline unsigned long KAESNAPPYBlockHeaderSz(void)
{
    return KAESNAPPY_BLOCK_HEADER_SIZE;
}

#endif
