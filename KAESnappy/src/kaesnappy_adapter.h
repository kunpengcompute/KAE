/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy adapter for sva(v2) and nosva(v1) header file
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-22
 */

#ifndef KAESNAPPY_ADAPTER
#define KAESNAPPY_ADAPTER
#include "kaesnappy_common.h"

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
    const void *src;
    void *dst;
    lz4_async_callback callback;
    struct kaelz4_result *result;
    enum kae_lz4_async_data_format data_format;
    int preferences;
} lz4_async_task_t;

typedef struct {
    lz4_async_task_t *tasks;
    volatile size_t pi; // pi
    volatile size_t ci;  // ci
    pthread_mutex_t *mutex;   // 保护tasks资源的多线程互斥锁
    pthread_cond_t cond;
    sem_t sem;
    pthread_t worker_thread;
    volatile int stop;  // 用于停止线程的标志
    int index;
} lz4_task_queue;

typedef struct {
    lz4_task_queue task_queue[MAX_TASK_NUM];
    sw_compress_fn sw_compress;
    sw_compress_frame_fn sw_compress_frame;
    int num;
    volatile int init;
} lz4_task_queues;

int  kaelz4_init_v1(LZ4_CCtx* zc);
void kaelz4_reset_v1(LZ4_CCtx* zc);
void kaelz4_release_v1(LZ4_CCtx* zc);
void kaelz4_setstatus_v1(LZ4_CCtx* zc, unsigned int status);
int  kaelz4_compress_v1(LZ4_CCtx* zc, const void* src, size_t srcSize);
void kaelz4_compress_async(const void *src, void *dst,
                           lz4_async_callback callback, struct kaelz4_result *result,
                           enum kae_lz4_async_data_format data_format, const int *ptr);
int kaelz4_async_compress_polling(int budget);

int  kaelz4_init_v2(LZ4_CCtx* zc);
void kaelz4_release_v2(LZ4_CCtx* zc);
void kaelz4_setstatus_v2(LZ4_CCtx* zc, unsigned int status);
int  kaelz4_compress_v2(LZ4_CCtx* zc, const void* src, size_t srcSize);

int wd_get_available_dev_num(const char* alogrithm);
int kaelz4_async_is_thread_do_comp_full();
void kaelz4_async_init(volatile int *stop, sw_compress_fn sw_compress, sw_compress_frame_fn sw_compress_frame);
void kaelz4_async_deinit(void);
void kaelz4_ctx_clear(void);
#endif