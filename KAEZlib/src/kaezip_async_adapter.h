/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezlib adapter for sva(v2) and nosva(v1) header file
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-22
 */

#ifndef KAEZIP_ASYNC_ADAPTER_H
#define KAEZIP_ASYNC_ADAPTER_H
#include <zlib.h>
#include <stdatomic.h>
#include "kaezlib_common.h"
#include "kaezip_adapter.h"
#include "kaezip.h"

enum {
    HW_NONE,
    HW_V1,
    HW_V2, //  unused now
    HW_V3
};

#define MAX_TASK_NUM 32
#define KAEZLIB_TASK_THREAD_NUM 12
#define KAEZLIB_TASK_QUEUE_DEPTH 1024
#define ENQUEUE_TIME_OUT_US 1000000
#define ASYNC_DEQUEUE_PROCESS_DEFAULT_BUDGET 1
#define ASYNC_POLLING_DEFAULT_BUDGET 1

typedef struct {
    const struct kaezip_buffer_list *src;
    struct kaezip_buffer_list *dst;
    kaezip_async_callback callback;
    struct kaezip_result *result;
    enum kaezip_async_data_format data_format;
    atomic_bool ready;
} kaezip_async_task_t;

typedef struct {
    kaezip_async_task_t *tasks;
    atomic_uint pi; // pi
    volatile unsigned int ci;  // ci
    pthread_mutex_t mutex;   // 保护tasks资源的多线程互斥锁
    pthread_cond_t cond;
    pthread_t worker_thread;
    volatile int stop;  // 用于停止线程的标志
    int index;
    int is_polling;
} kaezip_task_queue;

typedef struct {
    kaezip_task_queue task_queue[MAX_TASK_NUM];
    kaezip_task_queue decompress_queue[MAX_TASK_NUM];
    iova_map_fn usr_map;
    unsigned int num;
    unsigned int decompress_queue_num;
    volatile int init;
} kaezip_task_queues;

struct kaezip_async_ctrl;
typedef struct {
    kaezip_task_queue task_queue;
    iova_map_fn usr_map;
    struct kaezip_async_ctrl *ctrl;
    int comp_optype;
    int comp_algtype;
} kaezip_session;

typedef void *(*task_queue_process_fn)(void *);
typedef int (*compress_async_fn)(struct kaezip_async_ctrl *ctrl, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                 kaezip_async_callback callback, struct kaezip_result *result,
                                 enum kaezip_async_data_format data_format, int comp_optype, int comp_algtype);

void *kaezip_init_v1(int win_size, int is_sgl, int comp_optype, int comp_algtype);

int kaezip_get_win_size(void);

int kaezip_compress_async(struct kaezip_async_ctrl *ctrl, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                          kaezip_async_callback callback, struct kaezip_result *result,
                          enum kaezip_async_data_format data_format, int comp_optype, int comp_algtype);
int kaezip_async_compress_polling(struct kaezip_async_ctrl *ctrl, int budget);

int kaezip_async_is_thread_do_comp_full(struct kaezip_async_ctrl *ctrl);

int kaezip_async_instances_init(struct kaezip_async_ctrl **ctrl, iova_map_fn usr_map, int comp_optype, 
                                int comp_algtype, const device_config_t *config);
                                
void kaezip_async_instances_deinit(struct kaezip_async_ctrl *ctrl);
void kaezip_hw_timeout_handle(struct kaezip_async_ctrl *ctrl, int comp_optype, int comp_algtype);
void kaezip_set_zlib_header(struct kaezip_async_ctrl *ctrl, int level, int windowBits);

int scan_hisi_zip_devices(struct zip_dev *g_devices, unsigned int *g_dev_count);
#endif