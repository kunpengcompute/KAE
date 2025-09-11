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
#define MFLIMIT       12   /* see ../doc/lz4_Block_format.md#parsing-restrictions */
#define KAE_LZ4_REBUILD_FAIL -257
#define KAE_LZ4_SW_RETURN_0_FAIL -256

#define HARDWARE_BLOCK_SIZE (64 * 1024) // 硬件支持的最大压缩块大小

#if !defined(LZ4_memcpy)
#  if defined(__GNUC__) && (__GNUC__ >= 4)
#    define LZ4_memcpy(dst, src, size) __builtin_memcpy(dst, src, size)
#  else
#    define LZ4_memcpy(dst, src, size) memcpy(dst, src, size)
#  endif
#endif

#if defined(__x86_64__)
  typedef U64    reg_t;   /* 64-bits in x32 mode */
#else
  typedef size_t reg_t;   /* 32-bits in x32 mode */
#endif

typedef union { U16 u16; U32 u32; reg_t uArch; } __attribute__((packed)) LZ4_unalign;

struct kaelz4_compress_ctx;
struct kaelz4_async_req;

typedef int (*kaelz4_post_process_handle_t)(struct kaelz4_async_req *req, const void *source, void *dest);

struct kaelz4_compress_ctx {
    size_t srcSize;
    size_t dstCapacity;
    size_t dst_len;
    const void *src;
    void *dst;
    void *prev_last_lit_ptr; // 用户输入数据>64K需要分块、返回BLOCK格式、现有保序返回切块压缩结果的约束下，记录前一个分块的last literal信息
    size_t prev_last_lit_len;
    unsigned int recv_cnt;
    int status;
    lz4_async_callback callback;
    struct kaelz4_result *result;
    enum kae_lz4_async_data_format data_format;
    int preferences;
    kaelz4_post_process_handle_t kaelz4_post_process_handle;
    struct kaelz4_async_req *req_list;
    struct kaelz4_compress_ctx *next;
};

struct kaelz4_async_req {
    LZ4_CCtx zc;
    const void* src;
    size_t src_size;
    U32 idx;
    U32 special_flag;
    U32 last;
    U32 done;
    struct kaelz4_compress_ctx *compress_ctx;
    struct kaelz4_async_req *next;
};

#define MAX_NUM_IN_COMP 2  // 每个线程最多允许同时进行的压缩任务数
struct kaelz4_async_ctrl {
    struct kaelz4_compress_ctx *ctx_head;
    struct kaelz4_compress_ctx *tail;
    sw_compress_fn sw_compress;
    sw_compress_frame_fn sw_compress_frame;
    int cur_num_in_comp; // 当前正在压缩的任务数量
    kaelz4_ctx_t *kz_ctx[MAX_NUM_IN_COMP];
    int ctx_index;
    volatile int *stop_flag;
};

void kaelz4_setstatus_v1(LZ4_CCtx* zc, unsigned int status);
int  kaelz4_compress_v1(LZ4_CCtx* zc, const void* src, size_t srcSize);

// part1.frame模式的header & footer描述
#define KAELZ4_MAGIC_NUMBER    0x184D2204U
#define KAELZ4_MAGIC_SKIPPABLE 0x184D2A50U

#define KAELZ4_VERSION                  0x1        // version必须为01
#define KAELZ4_BLOCK_INDEPENDENCE_FLAG  0x1        // block间独立不依赖
#define KAELZ4_BLOCK_CHECKSUM_FLAG      (1 << 4)        // 各block不带checksum
#define KAELZ4_CONTENT_SIZE_FLAG        (1 << 3)        // 携带原始数据长度
#define KAELZ4_CONTENT_CHECKSUM_FLAG    (1 << 2)        // frame携带checksum
#define KAELZ4_DICTIONARY_ID_FLAG       0x0        // 不使用字典dict
#define KAELZ4_MAX_BLK_SIZE  0x4                   // 各block大小64KB
#define KAELZ4_ENDMARK       0x0                   // frame结束标志

#define KAELZ4_MAGIC_SIZE    4                     // magic number长度
#define KAELZ4_FRAMEDESCRIPTOR_SIZE     11         // frame descriptor长度
#define KAELZ4_HEADER_SIZE   (KAELZ4_MAGIC_SIZE + KAELZ4_FRAMEDESCRIPTOR_SIZE) // frame header长度

#define KAELZ4_BLOCK_HEADER_SIZE  4                // block header长度(4字节)
#define KAELZ4_STOREDBLOCK_FLAG   0x80000000U      // 长度为0的未压缩块，是有效的
#define KAELZ4_STORED_HEADER_SIZE 4

#define KAELZ4_CHECKSUM_SIZE 4                     // checksum长度
#define KAELZ4_ENDMARK_SIZE  4                     // endmark长度
#define KAELZ4_FOOTER_SIZE   (KAELZ4_CHECKSUM_SIZE + KAELZ4_ENDMARK_SIZE) // frame footer长度

// part2.首尾数据结构
// frame header
typedef struct KAELZ4H_S {
    uint32_t magic_number;
    uint8_t  flag_descriptor;
    uint8_t  block_descriptor;
    uint64_t content_size;
    uint8_t  header_checksum;
} KAELZ4H_T;

// frame footer
typedef struct KAELZ4F_S {
    uint32_t end_mark;
    uint32_t content_checksum;
} KAELZ4F_T;

// part4.功能函数
inline unsigned long KAELZ4HeaderSz(void)
{
    return KAELZ4_HEADER_SIZE;
}

inline unsigned long KAELZ4FooterSz(void)
{
    return KAELZ4_FOOTER_SIZE;
}

inline unsigned long KAELZ4BlockHeaderSz(void)
{
    return KAELZ4_BLOCK_HEADER_SIZE;
}

int kaelz4_async_is_thread_do_comp_full();
#endif
