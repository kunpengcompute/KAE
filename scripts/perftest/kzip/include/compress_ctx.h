#ifndef _COMPRESS_CTX_H
#define _COMPRESS_CTX_H

#include <semaphore.h>
#include <pthread.h>
#include "manage.h"

struct fragment_metadata {
    unsigned int offset;  // 分片的起始偏移量
    unsigned int len;     // 分片的长度
    size_t src_chunk_len;
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

#ifdef CONFIG_KAELZ4
#include <kaelz4.h>
typedef struct {
    struct kaelz4_result result;
    struct kaelz4_buffer_list src;
    struct kaelz4_buffer_list dst;            // 一般的传给硬件的输出指针
    struct kaelz4_buffer_list tuple;          // 特殊的lz77_only模式传给硬件的输出指针
    struct kaelz4_buffer_list *dst_buf_list;  // 真正的传给硬件压缩的dst指针。
    struct kaelz4_buffer src_buf[1024];
    struct kaelz4_buffer dst_buf[1024];
    struct kaelz4_buffer tuple_buf[1024];
} kaelz4_param;
#endif

#ifdef CONFIG_KAEZLIB
#include <kaezip.h>
typedef struct {
    struct kaezip_result result;
    struct kaezip_buffer_list src;
    struct kaezip_buffer_list dst;
    struct kaezip_buffer_list tuple;
    struct kaezip_buffer_list *dst_buf_list;
    struct kaezip_buffer src_buf[1024];
    struct kaezip_buffer dst_buf[1024];
    struct kaezip_buffer tuple_buf[1024];
} kaezip_param;
#endif


struct __attribute__((aligned(64))) compress_param {
    struct compress_ctx *ctx;
    uint32_t ibuf_crc;
    uint32_t obuf_crc;
    unsigned int sn;
    unsigned int loop_index;
    unsigned int src_len;   // 单次压缩任务的输入长度
    void *src_buf;          // 单次压缩任务起始内存地址
    size_t src_buf_offset;  // 单次压缩任务起始内存地址偏移
    unsigned int dst_len;   // 单次压缩任务的输出长度
    void *dst_buf;

    union {

#ifdef CONFIG_KAELZ4
        kaelz4_param kaelz4_param;
#endif
#ifdef CONFIG_KAEZLIB
        kaezip_param kaezip_param;
#endif
    };

    uint64_t start_time;
    volatile unsigned int done;
};

struct compress_session {
    void *kae_sess;
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
    size_t total_size;
    size_t meta_size;
    void *tuple_page_info;
    void *tuple_buf;
    size_t tuple_buf_offset;
    size_t tuple_buf_len;
    int thread_id;
    int with_crc;
    unsigned int src_buf_num;
    struct compress_session sess;
    struct compress_session *sess_array;  // sess指针数组
    int sess_count;       // sess指针数量，默认1
    int enable_huge_page; // 是否开启大页, 使能零拷贝

    uint64_t *all_delays;
    int is_polling;
    int is_lz77_mode;
    int is_zlib;
    int use_tuple_buf;
    int fork_id;
};

struct thread_compress_args {
    struct compress_ctx ctx;
    const char *in_filename;
    const char *out_filename;
    int multi;
    int window_bits;
    int level;
};

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__
#define dsb(opt)                                  \
    {                                             \
        asm volatile("dsb " #opt : : : "memory"); \
    }
#define rmb() dsb(ld) /* read fence */
#define wmb() dsb(st) /* write fence */
#define mb() dsb(sy)  /* rw fence */
#else
#define rmb() __sync_synchronize() /* read fence */
#define wmb() __sync_synchronize() /* write fence */
#define mb() __sync_synchronize()  /* rw fence */
#endif

uint32_t crc32c_sw(uint32_t crc, const uint8_t *data, size_t len);
void *get_physical_address_wrapper(void *usr, void *vaddr, size_t sz);
void release_huge_pages(void *addr, size_t total_size);
void *get_huge_pages(size_t total_size);
struct cache_page_map* init_cache_page_map(void *base_vaddr, size_t total_size);
void free_cache_page_map(struct cache_page_map *cache);
#endif
