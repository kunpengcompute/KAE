#ifndef _COMPRESS_CTX_H
#define _COMPRESS_CTX_H

#include <semaphore.h>
#include <pthread.h>
#include "alg/manage.h"
#include "scene_test_functions/entry.h"

struct fragment_metadata {
    unsigned int offset;   // 分片的起始偏移量
    unsigned int len;      // 分片的长度
};

struct compress_out_buf {
    void *buf_addr;
    unsigned int len;
    unsigned int sn;
    struct compress_out_buf *next;
    void *src;
    unsigned int src_len;
    uint32_t ibuf_crc;
    uint32_t obuf_crc;
};


struct compress_ctx;

struct __attribute__((aligned(64))) compress_param {
    struct kaelz4_result result;
    struct compress_ctx *ctx;
    uint32_t ibuf_crc;
    uint32_t obuf_crc;
    unsigned int sn;
    unsigned int loop_index;
    unsigned int src_len;
    unsigned int dst_len;
    struct kaelz4_buffer_list src;
    struct kaelz4_buffer_list dst;
    struct kaelz4_buffer_list tuple;
    uint64_t start_time;
    volatile unsigned int done;
    struct kaelz4_buffer src_buf[1024];
    struct kaelz4_buffer dst_buf[1024];
    struct kaelz4_buffer tuple_buf[1024];
};

struct compress_ctx {
    struct compress_param param_buf[1024];
    compression_algorithm_t *algorithm;
    unsigned int param_index;
    unsigned int loop_times;
    unsigned int inflight_num;
    unsigned int loop_index;
    unsigned int sn;
    volatile unsigned int finish_num;
    void *src_buf;
    unsigned long src_len;
    unsigned long out_total_len;
    unsigned int chunk_len;
    int compress_or_decompress;
    struct compress_out_buf *out_buf_list;
    struct compress_out_buf *out_buf_tail;
    void *page_info;
    void *tuple_page_info;
    void *tuple_buf;
    size_t tuple_buf_offset;
    size_t tuple_buf_len;
    int thread_id;
    int with_crc;
    unsigned int src_buf_num;
    void *sess;
    uint64_t *all_delays;
    int is_lz77_mode;
};


struct thread_compress_args {
    struct compress_ctx ctx;
    const char* in_filename;
    const char* out_filename;
    int multi;
    int window_bits;
    int level;
};

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__
#define dsb(opt)        { asm volatile("dsb " #opt : : : "memory"); }
#define rmb() dsb(ld) /* read fence */
#define wmb() dsb(st) /* write fence */
#define mb() dsb(sy) /* rw fence */
#else
#define rmb() __sync_synchronize() /* read fence */
#define wmb() __sync_synchronize() /* write fence */
#define mb() __sync_synchronize() /* rw fence */
#endif
#endif
