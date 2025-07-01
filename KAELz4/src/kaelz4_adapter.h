/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaelz4 adapter for sva(v2) and nosva(v1) header file
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-22
 */

#ifndef KAELZ4_ADAPTER
#define KAELZ4_ADAPTER
#include <lz4frame.h>
#include <lz4.h>
#include "kaelz4_common.h"

enum {
    HW_NONE,
    HW_V1,
    HW_V2,
    HW_V3   //  unused now
};

#define MAX_TASK_NUM 32
#define KAELZ4_TASK_THREAD_NUM 12
#define KAELZ4_TASK_QUEUE_DEPTH 1024
#define ENQUEUE_TIME_OUT_US 1000000
#define SMALL_BLOCK_SIZE (64 * 1024)
#define ASYNC_DEQUEUE_PROCESS_DEFAULT_BUDGET 3
#define ASYNC_POLLING_DEFAULT_BUDGET 1

typedef struct {
    const struct kaelz4_buffer_list *src;
    struct kaelz4_buffer_list *dst;
    lz4_async_callback callback;
    struct kaelz4_result *result;
    enum kae_lz4_async_data_format data_format;
    LZ4F_preferences_t preferences;
    LZ4F_decompressOptions_t options;
    atomic_bool ready;
} lz4_async_task_t;

typedef struct {
    lz4_async_task_t *tasks;
    atomic_uint pi; // pi
    volatile unsigned int ci;  // ci
    pthread_mutex_t mutex;   // 保护tasks资源的多线程互斥锁
    pthread_cond_t cond;
    pthread_t worker_thread;
    volatile int stop;  // 用于停止线程的标志
    int index;
    int is_polling;
} lz4_task_queue;

typedef struct {
    lz4_task_queue task_queue[MAX_TASK_NUM];
    lz4_task_queue decompress_queue[MAX_TASK_NUM];
    sw_compress_fn sw_compress;
    sw_compress_frame_fn sw_compress_frame;
    sw_decompress_fn sw_decompress;
    iova_map_fn usr_map;
    unsigned int num;
    unsigned int decompress_queue_num;
    volatile int init;
} lz4_task_queues;

struct kaelz4_async_ctrl;
typedef struct {
    lz4_task_queue task_queue;
    iova_map_fn usr_map;
    struct kaelz4_async_ctrl *ctrl;
} kaelz4_session;

typedef void *(*task_queue_process_fn)(void *);

int  kaelz4_init_v1(LZ4_CCtx* zc, int is_sgl);
void kaelz4_reset_v1(LZ4_CCtx* zc);
void kaelz4_release_v1(LZ4_CCtx* zc);
void kaelz4_setstatus_v1(LZ4_CCtx* zc, unsigned int status);
int  kaelz4_compress_v1(LZ4_CCtx* zc, const void* src, size_t srcSize);
int kaelz4_compress_async(struct kaelz4_async_ctrl *ctrl, const void *src, void *dst,
                           lz4_async_callback callback, struct kaelz4_result *result,
                           enum kae_lz4_async_data_format data_format, const LZ4F_preferences_t *ptr);
int kaelz4_async_compress_polling(struct kaelz4_async_ctrl *ctrl, int budget);

int  kaelz4_init_v2(LZ4_CCtx* zc);
void kaelz4_release_v2(LZ4_CCtx* zc);
void kaelz4_setstatus_v2(LZ4_CCtx* zc, unsigned int status);
int  kaelz4_compress_v2(LZ4_CCtx* zc, const void* src, size_t srcSize);

int wd_get_available_dev_num(const char* alogrithm);
int kaelz4_async_is_thread_do_comp_full(struct kaelz4_async_ctrl *ctrl);
struct kaelz4_async_ctrl *kaelz4_async_init(volatile int *stop, sw_compress_fn sw_compress, sw_compress_frame_fn sw_compress_frame,
                                            sw_decompress_fn sw_decompress, iova_map_fn usr_map);
void kaelz4_async_deinit(void);
int kaelz4_async_instances_init(struct kaelz4_async_ctrl **ctrl, iova_map_fn usr_map);
void kaelz4_async_instances_deinit(struct kaelz4_async_ctrl *ctrl);

int kaelz4_triples_rebuild_impl(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *tuple_buf, struct kaelz4_buffer_list *dst,
                                struct kaelz4_result *result, enum kae_lz4_async_data_format data_format, const LZ4F_preferences_t *ptr);
#endif