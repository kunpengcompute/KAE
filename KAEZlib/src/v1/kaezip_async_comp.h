/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezlib nosva compress header file
 * @Author: LiuYongYang
 * @Date: 2024-02-26
 * @LastEditTime: 2024-03-28
 */

#ifndef KAEZIP_ASYNC_COMP_H
#define KAEZIP_ASYNC_COMP_H

#include <zlib.h>
#include <string.h>
#include "kaezlib_common.h"
#include <stdint.h>
#include <arm_acle.h>
#include <arm_neon.h>
#include <dirent.h>
#include "uadk/v1/wd_sgl.h"
#include "kaezip_dev.h"

#define KAE_ZLIB_REBUILD_FAIL     (-257)
#define KAE_ZLIB_SW_RETURN_0_FAIL (-256)

#define HARDWARE_BLOCK_SIZE (64 * 1024) // 硬件支持的最大压缩块大小

#define MAX_NUM_IN_COMP MAX_KAE_CTX_DEPTH  // 每个线程最多允许同时进行的压缩任务数

#if defined(__x86_64__)
  typedef U64    reg_t;   /* 64-bits in x32 mode */
#else
  typedef size_t reg_t;   /* 32-bits in x32 mode */
#endif

typedef union { U16 u16; U32 u32; reg_t uArch; } __attribute__((packed)) ZLIB_unalign;

struct kaezip_compress_ctx;
struct kaezip_async_req;

struct kaezip_priv_save_info {
    void *prev_last_lit_ptr; // 用户输入数据>64K需要分块、返回BLOCK格式、现有保序返回切块压缩结果的约束下，记录前一个分块的last literal信息
    size_t prev_last_lit_len;
    unsigned int prev_last_lit_buf_index; // 用户输入数据>64K需要分块、返回BLOCK格式、现有保序返回切块压缩结果的约束下，记录前一个分块的last literal信息
    const struct kaezip_buffer_list *src;
};

typedef int (*kaezip_post_process_handle_t)(struct kaezip_async_req *req, const struct wd_buf_list *source,
                                            void *dest, struct kaezip_priv_save_info *save_info);

struct kaezip_async_req {
    kaezip_ctx_t *kz_ctx;
    struct wd_buf_list src;
    struct wd_buf_list dst;
    struct wd_buf buffers[REQ_BUFFER_MAX];
    struct wd_buf dst_buffers[REQ_BUFFER_MAX];
    size_t src_size;
    size_t dst_len;
    U32 idx;
    U16 last;
    U16 buf_start_index;
    U32 done;
    struct kaezip_compress_ctx *compress_ctx;
    struct kaezip_async_req *next;
};

struct kaezip_compress_ctx {
    size_t srcSize;
    size_t dstCapacity;
    size_t dst_len;
    const struct kaezip_buffer_list *src;
    struct kaezip_buffer_list *dst;
    struct kaezip_priv_save_info save_info;
    kaezip_async_callback callback;
    struct kaezip_result *result;
    enum kaezip_async_data_format data_format;
    kaezip_post_process_handle_t kaezip_post_process_handle;
    struct kaezip_async_req *req_list;
    struct kaezip_async_req req;
    struct kaezip_compress_ctx *next;
    int status;
    int ibuf_checksum_flag;  // identify the checksum of inbuf is calculated or not
};

struct kaezip_seq_result {
    unsigned int seq_num;
    unsigned char seq_start[];
};

struct kaezip_async_ctrl {
    struct kaezip_compress_ctx *ctx_head;
    struct kaezip_compress_ctx *tail;
    struct kaezip_compress_ctx ctx[MAX_NUM_IN_COMP];
    int cur_num_in_comp; // 当前正在压缩的任务数量
    kaezip_ctx_t *kz_ctx[MAX_NUM_IN_COMP];
    int ctx_num;
    int ctx_index;
    volatile int *stop_flag;
    iova_map_fn usr_map;
    int is_polling;
    const char *header;
    const device_config_t *config;
};

#define KZL_MEMCPY_16(dst, src, size) vst1q_u8((dst), vld1q_u8(src))

static inline void ZIP_wildCopy16(void* dstPtr, const void* srcPtr, void* dstEnd)
{
    BYTE* d = (BYTE*)dstPtr;
    const BYTE* s = (const BYTE*)srcPtr;
    BYTE* const e = (BYTE*)dstEnd;

    do { KZL_MEMCPY_16(d,s,16); d+=16; s+=16; } while (d<e);
}

static inline void ZIP_wildCopy16Exact(void* dstPtr, const void* srcPtr, size_t len)
{
    BYTE* d = (BYTE*)dstPtr;
    const BYTE* s = (const BYTE*)srcPtr;
    size_t copy16_len = len & ~(size_t)0xf;

    if (copy16_len > 0) {
        ZIP_wildCopy16(d, s, d + copy16_len);
        d += copy16_len;
        s += copy16_len;
    }

    if (len > copy16_len) {
        memcpy(d, s, len - copy16_len);
    }
}

int kaezip_async_is_thread_do_comp_full(struct kaezip_async_ctrl *ctrl);

int scan_hisi_zip_devices(struct zip_dev *g_devices, unsigned int *g_dev_count);
#endif
