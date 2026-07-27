/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaelz4 nosva compress header file
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */

#ifndef KAELZ4_COMP_H
#define KAELZ4_COMP_H

#include <lz4frame.h>
#include <lz4.h>
#include "kaelz4_common.h"
#include <stdint.h>
#include <arm_acle.h>
#include <arm_neon.h>
#include "kaelz4_ctx.h"
#include "uadk/v1/wd_sgl.h"
#include "kaelz4_dev.h"

#define TOKEN_NUM_CONTROL 0 // 用于控制生成压缩块中三元组数目，来保证解压速度（对齐实际match length需+3）
#define ML_BITS  4
#define ML_MASK  ((1U<<ML_BITS)-1)
#define RUN_BITS (8-ML_BITS)
#define RUN_MASK ((1U<<RUN_BITS)-1)
#define MFLIMIT       12   /* see ../doc/lz4_Block_format.md#parsing-restrictions */
#define KAE_LZ4_REBUILD_FAIL -257
#define KAE_LZ4_SW_RETURN_0_FAIL -256

#define HARDWARE_BLOCK_SIZE (64 * 1024) // 硬件支持的最大压缩块大小

#define MAX_NUM_IN_COMP MAX_KAE_CTX_DEPTH  // 每个线程最多允许同时进行的压缩任务数

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

struct kaelz4_priv_save_info {
    void *prev_last_lit_ptr; // 用户输入数据>64K需要分块、返回BLOCK格式、现有保序返回切块压缩结果的约束下，记录前一个分块的last literal信息
    size_t prev_last_lit_len;
    unsigned int prev_last_lit_buf_index; // 用户输入数据>64K需要分块、返回BLOCK格式、现有保序返回切块压缩结果的约束下，记录前一个分块的last literal信息
    const struct kaelz4_buffer_list *src;
    LZ4F_preferences_t preferences;
    int *status;
    size_t dstCapacity;
    size_t dst_len;
};

typedef int (*kaelz4_post_process_handle_t)(struct kaelz4_async_req *req, const struct wd_buf_list *source,
                                            void *dest, struct kaelz4_priv_save_info *save_info);

struct kaelz4_compress_ctx {
    size_t srcSize;
    const struct kaelz4_buffer_list *src;
    struct kaelz4_buffer_list *dst;
    struct kaelz4_priv_save_info save_info;
    lz4_async_callback callback;
    struct kaelz4_result *result;
    enum kae_lz4_async_data_format data_format;
    kaelz4_post_process_handle_t kaelz4_post_process_handle;
    struct kaelz4_async_req *req_list;
    struct kaelz4_compress_ctx *next;
    int status;
};

struct kaelz4_seq_result {
    unsigned int seq_num;
    unsigned char seq_start[];
};

struct kaelz4_async_req {
    LZ4_CCtx zc;
    struct wd_buf_list src;
    struct wd_buf_list dst;
    struct wd_buf buffers[REQ_BUFFER_MAX];
    struct wd_buf dst_buffers[REQ_BUFFER_MAX];
    size_t src_size;
    U32 idx;
    U32 special_flag;
    U16 last;
    U16 buf_start_index;
    U32 done;
    struct kaelz4_compress_ctx *compress_ctx;
    struct kaelz4_async_req *next;
};

struct kaelz4_async_ctrl {
    struct kaelz4_compress_ctx *ctx_head;
    struct kaelz4_compress_ctx *tail;
    sw_compress_fn sw_compress;
    sw_compress_frame_fn sw_compress_frame;
    sw_decompress_fn sw_decompress;
    int cur_num_in_comp; // 当前正在压缩的任务数量
    kaelz4_ctx_t *kz_ctx[MAX_NUM_IN_COMP];
    int ctx_num;
    int ctx_index;
    volatile int *stop_flag;
    iova_map_fn usr_map;
    int is_polling;
    const kaelz4_device_config_t *config;
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

static void LZ4_write16(void* memPtr, U16 value) { ((LZ4_unalign*)memPtr)->u16 = value; }

static unsigned LZ4_isLittleEndian(void)
{
    const union { U32 u; BYTE c[4]; } one = { 1 };   /* don't use static : performance detrimental */
    return one.c[0];
}

static inline void LZ4_wildCopy8(void* dstPtr, const void* srcPtr, void* dstEnd)
{
    BYTE* d = (BYTE*)dstPtr;
    const BYTE* s = (const BYTE*)srcPtr;
    BYTE* const e = (BYTE*)dstEnd;

    do { KZL_MEMCPY_8(d, s, 8); d += 8; s += 8; } while (d < e);
}

/*
 * Callers must ensure that the current source segment contains every byte
 * touched by the rounded-up 16-byte loads. Rebuild paths keep MFLIMIT bytes in
 * the segment after a complete sequence; segment-boundary paths copy exactly.
 */
static inline void LZ4_wildCopy16(void* dstPtr, const void* srcPtr, void* dstEnd)
{
    BYTE* d = (BYTE*)dstPtr;
    const BYTE* s = (const BYTE*)srcPtr;
    BYTE* const e = (BYTE*)dstEnd;

    do { KZL_MEMCPY_16(d, s, 16); d += 16; s += 16; } while (d < e);
}


static inline void LZ4_writeLE16(void* memPtr, U16 value)
{
    if (LZ4_isLittleEndian()) {
        LZ4_write16(memPtr, value);
    } else {
        BYTE* p = (BYTE*)memPtr;
        p[0] = (BYTE) value;
        p[1] = (BYTE)(value>>8);
    }
}

static inline void wd_ip_add_len(const struct wd_buf_list *src, unsigned int *cur_idx, const BYTE **ip,
                                 size_t *remain, size_t len)
{
    while (len > 0 && *cur_idx < src->buf_num) {
        if (*remain > len) {
            *ip += len;
            *remain -= len;
            return;
        } else {
            len -= *remain;
            ++(*cur_idx);
            if (*cur_idx < src->buf_num) {
                *ip = (const BYTE*)src->buf[*cur_idx].data;
                *remain = src->buf[*cur_idx].buf_len;
            } else {
                *ip = NULL;
                *remain = 0;
            }
        }
    }
}

static inline void wd_copy_from_buffers(const struct wd_buf_list *src, unsigned int *cur_idx, const BYTE **ip,
                                        size_t *remain, BYTE *dst, size_t len)
{
    while (len > 0 && *cur_idx < src->buf_num) {
        size_t can_copy = *remain < len ? *remain : len;
        LZ4_memcpy(dst, *ip, can_copy);
        dst += can_copy;
        len -= can_copy;
        wd_ip_add_len(src, cur_idx, ip, remain, can_copy);
    }
}

static inline void kaelz4_ip_add_len(const struct kaelz4_buffer_list *src, unsigned int *cur_idx, const BYTE **ip,
                                     size_t *remain, size_t len)
{
    while (len > 0 && *cur_idx < src->buf_num) {
        if (*remain > len) {
            *ip += len;
            *remain -= len;
            return;
        } else {
            len -= *remain;
            ++(*cur_idx);
            if (*cur_idx < src->buf_num) {
                *ip = (const BYTE*)src->buf[*cur_idx].data;
                *remain = src->buf[*cur_idx].buf_len;
            } else {
                *ip = NULL;
                *remain = 0;
            }
        }
    }
}

static inline void kaelz4_copy_from_buffers(const struct kaelz4_buffer_list *src, unsigned int *cur_idx, const BYTE **ip,
                                            size_t *remain, BYTE *dst, size_t len)
{
    while (len > 0 && *cur_idx < src->buf_num) {
        size_t can_copy = *remain < len ? *remain : len;
        LZ4_memcpy(dst, *ip, can_copy);
        dst += can_copy;
        len -= can_copy;
        kaelz4_ip_add_len(src, cur_idx, ip, remain, can_copy);
    }
}

int kaelz4_async_is_thread_do_comp_full(struct kaelz4_async_ctrl *ctrl);
#endif
