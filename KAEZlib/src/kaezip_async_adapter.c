/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaezlib adapter for sva(v2) and nosva(v1)
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-26
 */

#include <stdlib.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <pthread.h>
#include "kaezlib_common.h"
#include "kaezip_ctx.h"
#include "kaezip.h"
#include "kaezip_utils.h"
#include "kaezip_async_adapter.h"
#include "kaezip_log.h"
#include "uadk/wd.h"

static struct zip_dev g_devices[MAX_DEVICES];
static unsigned int g_dev_count = 0;
static atomic_int g_initialized = 0; // 初始化标志
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static void kaezip_dequeue_process(struct kaezip_async_ctrl *ctrl, kaezip_task_queue *task_queue, int budget, 
                                    int comp_optype, int comp_algtype, compress_async_fn compress_fn)
{
    int cnt = 0;
    // 等待任务
    while (task_queue->pi != task_queue->ci && (cnt < budget || budget == 0)) {

        // 如果要停止线程
        if (task_queue->stop) {
            break;
        }
        if (kaezip_async_is_thread_do_comp_full(ctrl) == 1) {
            break;
        }

        // 获取任务
        unsigned int ci = task_queue->ci % KAEZLIB_TASK_QUEUE_DEPTH;
        kaezip_async_task_t task;

        if (!atomic_load_explicit(&task_queue->tasks[ci].ready, memory_order_acquire)) {
            continue;
        }
        task = task_queue->tasks[ci];
        atomic_store_explicit(&task_queue->tasks[ci].ready, false, memory_order_release);
        // 更新 ci，复用空闲位置
        task_queue->ci++;
        // 执行压缩操作
        compress_fn(ctrl, task.src, task.dst, task.callback, task.result, task.data_format, comp_optype, comp_algtype);
        cnt++;
    }
    return;
}

static int kaezip_task_queue_init(kaezip_task_queue *task_queue, int index)
{
    task_queue->tasks = malloc(KAEZLIB_TASK_QUEUE_DEPTH * sizeof(kaezip_async_task_t));
    if (task_queue->tasks == NULL) {
        return KAE_ZLIB_ALLOC_FAIL;
    }
    task_queue->pi = 0;
    task_queue->ci = 0;
    task_queue->stop = 0;
    task_queue->index = index;
    for (int i = 0; i < KAEZLIB_TASK_QUEUE_DEPTH; i++) {
        atomic_store_explicit(&task_queue->tasks[i].ready, false, memory_order_release);
    }
    pthread_mutex_init(&task_queue->mutex, NULL);
    pthread_cond_init(&task_queue->cond, NULL);

    task_queue->is_polling = TRUE;
    return KAE_ZLIB_SUCC;
}

static void kaezip_task_queue_free(kaezip_task_queue *task_queue)
{

    if (!task_queue->is_polling) {
        pthread_mutex_lock(&task_queue->mutex);
        task_queue->stop = 1;
        pthread_cond_signal(&task_queue->cond);
        pthread_mutex_unlock(&task_queue->mutex);
        while (task_queue->stop) {
            pthread_cond_signal(&task_queue->cond);
        }

        pthread_join(task_queue->worker_thread, NULL);
    }

    pthread_mutex_destroy(&task_queue->mutex);

    free(task_queue->tasks);
    task_queue->tasks = NULL;
}

static inline int kaezip_enqueue(kaezip_task_queue *task_queue, kaezip_async_task_t *task)
{
    uint32_t pos = atomic_fetch_add(&task_queue->pi, 1);
    kaezip_async_task_t *cell = &task_queue->tasks[pos % KAEZLIB_TASK_QUEUE_DEPTH];
    if (atomic_load_explicit(&cell->ready, memory_order_acquire)) {
        return KAE_ZLIB_TASK_QUEUE_FULL;
    }
    *cell = *task;
    atomic_store_explicit(&cell->ready, true, memory_order_release);
    pthread_cond_signal(&task_queue->cond);
    return 0;
}

static int kaezip_check_param_valid(kaezip_session *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                    kaezip_async_callback callback, struct kaezip_result *result)
{
    if (unlikely(src == NULL || dst == NULL || callback == NULL || result == NULL)) {
        return KAE_ZLIB_INVAL_PARA;
    }

    if (unlikely(src->buf_num > REQ_BUFFER_MAX || src->buf_num <= 0 || dst->buf_num > REQ_BUFFER_MAX || dst->buf_num <= 0)) {
        return KAE_ZLIB_INVAL_PARA;
    }

    result->src_size = 0;

    // 对于 zlib 格式，第一个SGE缓冲区大小不得小于2字节，用于容纳zlib-header
    if (unlikely(src->buf[0].data == NULL || src->buf[0].buf_len == 0 || 
                        src->buf[0].buf_len > REQ_BUFFER_MAX_SIZE || src->buf[0].buf_len < REQ_BUFFER_MIN_SIZE)) {
        return KAE_ZLIB_INVAL_PARA;
    }
    result->src_size += src->buf[0].buf_len;

    for (unsigned int i = 1; i < src->buf_num; i++) {
        if (unlikely(src->buf[i].data == NULL || src->buf[i].buf_len == 0 || 
                        src->buf[i].buf_len > REQ_BUFFER_MAX_SIZE)) {
            return KAE_ZLIB_INVAL_PARA;
        }
        result->src_size += src->buf[i].buf_len;
    }

    if (unlikely(dst->buf[0].data == NULL || dst->buf[0].buf_len == 0 || 
                        dst->buf[0].buf_len > REQ_BUFFER_MAX_SIZE || dst->buf[0].buf_len < REQ_BUFFER_MIN_SIZE)) {
        return KAE_ZLIB_INVAL_PARA;
    }
    result->dst_len += dst->buf[0].buf_len;

    for (unsigned int i = 1; i < dst->buf_num; i++) {
        if (unlikely(dst->buf[i].data == NULL || dst->buf[i].buf_len == 0 ||
                        dst->buf[i].buf_len > REQ_BUFFER_MAX_SIZE)) {
            return KAE_ZLIB_INVAL_PARA;
        }
        result->dst_len += dst->buf[i].buf_len;
    }

    // src_size should not be larger than ASYNC_COMP_BLOCK_SIZE for no-SVA case
    if (unlikely(sess->usr_map == NULL && result->src_size > ASYNC_COMP_BLOCK_SIZE)) {
        return KAE_ZLIB_INVAL_PARA;
    }

    return KAE_ZLIB_SUCC;
}

static int kaezip_check_session_valid(kaezip_session *sess, int comp_optype)
{
    if (sess == NULL) {
        return KAE_ZLIB_INVAL_PARA;
    }
    if (sess->comp_optype != comp_optype) {
        return KAE_ZLIB_INVAL_PARA;
    }
    return KAE_ZLIB_SUCC;
}

static int kaezip_async_do_comp_in_session(kaezip_session *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                           kaezip_async_callback callback, struct kaezip_result *result,
                                           enum kaezip_async_data_format data_format, int comp_optype, int comp_algtype)
{
    kaezip_task_queue *task_queue = &sess->task_queue;
    kaezip_async_task_t task = {0};
    task.src = src;
    task.dst = dst;
    task.callback = callback;
    task.result = result;
    task.data_format = data_format;

    if (task_queue->pi != task_queue->ci && !kaezip_async_is_thread_do_comp_full(sess->ctrl)) {
        kaezip_dequeue_process(sess->ctrl, task_queue, ASYNC_DEQUEUE_PROCESS_DEFAULT_BUDGET, comp_optype, comp_algtype, kaezip_compress_async);
    }

    if (task_queue->pi != task_queue->ci || kaezip_async_is_thread_do_comp_full(sess->ctrl)) {
        return kaezip_enqueue(task_queue, &task);
    } else {
        return kaezip_compress_async(sess->ctrl, task.src, task.dst, task.callback, task.result,
                                     task.data_format, comp_optype, comp_algtype);
    }
}


int KAEZIP_compress_async_in_session(void *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                     kaezip_async_callback callback, struct kaezip_result *result)
{
    if (unlikely(kaezip_check_session_valid(sess, WCRYPTO_DEFLATE) != KAE_ZLIB_SUCC || kaezip_check_param_valid(sess, src, dst, callback, result) != KAE_ZLIB_SUCC)) {
        return KAE_ZLIB_INVAL_PARA;
    }

    return kaezip_async_do_comp_in_session(sess, src, dst, callback, result, KAEZIP_ASYNC_BLOCK, WCRYPTO_DEFLATE, ((kaezip_session *)sess)->comp_algtype);
}

void KAEZIP_async_polling_in_session(void *sess, int budget)
{
    struct kaezip_async_ctrl *ctrl = NULL;
    kaezip_task_queue *task_queue = NULL;
    int ret = 1;
    int cnt = 0;

    if (kaezip_check_session_valid(sess, WCRYPTO_DEFLATE) != KAE_ZLIB_SUCC &&
        kaezip_check_session_valid(sess, WCRYPTO_INFLATE) != KAE_ZLIB_SUCC)
        return;

    ctrl = ((kaezip_session *)sess)->ctrl;
    task_queue = &((kaezip_session *)sess)->task_queue;

    while (ret > 0 && cnt < budget) {
        ret = kaezip_async_compress_polling(ctrl, ASYNC_POLLING_DEFAULT_BUDGET);
        if (!kaezip_async_is_thread_do_comp_full(ctrl)) {
            kaezip_dequeue_process(ctrl, task_queue, ASYNC_DEQUEUE_PROCESS_DEFAULT_BUDGET, ((kaezip_session *)sess)->comp_optype, 
                                    ((kaezip_session *)sess)->comp_algtype, kaezip_compress_async);
        }
        cnt += ret;
    }
}

void *KAEZIP_create_async_compress_session(iova_map_fn usr_map, const device_config_t *config)
{
    kaezip_session *sess = (kaezip_session *)kae_malloc(sizeof(kaezip_session));
    int ret = 0;

    if (!sess)
        return NULL;

    // check config
    if (config != NULL && config->policy == KAE_SELECT_BY_DEV && config->param.dev == NULL) {
        return NULL;
    }

    sess->usr_map = usr_map;
    sess->comp_optype = WCRYPTO_DEFLATE;
    sess->comp_algtype = WCRYPTO_RAW_DEFLATE;
    ret = kaezip_task_queue_init(&sess->task_queue, 0);
    if (ret != 0) {
        free(sess);
        return NULL;
    }
    ret = kaezip_async_instances_init(&sess->ctrl, usr_map, sess->comp_optype, sess->comp_algtype, config);
    if (ret != 0) {
        kaezip_task_queue_free(&sess->task_queue);
        free(sess);
        return NULL;
    }

    return sess;
}

void KAEZIP_destroy_async_compress_session(void *sess)
{
    if (sess) {
        kaezip_async_instances_deinit(((kaezip_session *)sess)->ctrl);
        kaezip_task_queue_free(&((kaezip_session *)sess)->task_queue);
        free(sess);
    }
}

static int kaezip_task_flush_callback(struct kaezip_async_ctrl *ctrl, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                      kaezip_async_callback callback, struct kaezip_result *result,
                                      enum kaezip_async_data_format data_format, int comp_optype, int comp_algtype)
{
    result->status = KAE_ZLIB_HW_TIMEOUT_FAIL;
    result->dst_len = 0;
    callback(result);
    return KAE_ZLIB_HW_TIMEOUT_FAIL;
}

static void kaezip_flush_task_queue(kaezip_session *sess)
{
    kaezip_dequeue_process(sess->ctrl, &sess->task_queue, 0, sess->comp_optype, sess->comp_algtype, kaezip_task_flush_callback);
}

void KAEZIP_reset_session(void *sess)
{
    if (sess) {
        kaezip_hw_timeout_handle(((kaezip_session *)sess)->ctrl, ((kaezip_session *)sess)->comp_optype, ((kaezip_session *)sess)->comp_algtype);
        kaezip_flush_task_queue(sess);
    }
}

void *KAEZIP_create_async_decompress_session(iova_map_fn usr_map, const device_config_t *config)
{
    kaezip_session *sess = (kaezip_session *)kae_malloc(sizeof(kaezip_session));
    int ret = 0;

    if (!sess)
        return NULL;

    // check config
    if (config != NULL && config->policy == KAE_SELECT_BY_DEV && config->param.dev == NULL) {
        return NULL;
    }

    sess->usr_map = usr_map;
    sess->comp_optype = WCRYPTO_INFLATE;
    sess->comp_algtype = WCRYPTO_RAW_DEFLATE;
    ret = kaezip_task_queue_init(&sess->task_queue, 0);
    if (ret != 0) {
        free(sess);
        return NULL;
    }
    ret = kaezip_async_instances_init(&sess->ctrl, usr_map, sess->comp_optype, sess->comp_algtype, config);
    if (ret != 0) {
        kaezip_task_queue_free(&sess->task_queue);
        free(sess);
        return NULL;
    }

    return sess;
}

void KAEZIP_destroy_async_decompress_session(void *sess)
{
    KAEZIP_destroy_async_compress_session(sess);
}

int KAEZIP_decompress_async_in_session(void *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                     kaezip_async_callback callback, struct kaezip_result *result)
{
    if (unlikely(kaezip_check_session_valid(sess, WCRYPTO_INFLATE) != KAE_ZLIB_SUCC || kaezip_check_param_valid(sess, src, dst, callback, result) != KAE_ZLIB_SUCC)) {
        return KAE_ZLIB_INVAL_PARA;
    }

    return kaezip_async_do_comp_in_session(sess, src, dst, callback, result, KAEZIP_ASYNC_BLOCK, WCRYPTO_INFLATE, ((kaezip_session *)sess)->comp_algtype);
}

void *KAEZIP_create_async_compress_session_zlib(iova_map_fn usr_map, const device_config_t *config, int level, int windowBits)
{
    kaezip_session *sess = (kaezip_session *)kae_malloc(sizeof(kaezip_session));
    int ret = 0;

    if (!sess)
        return NULL;

    // check config
    if (config != NULL && config->policy == KAE_SELECT_BY_DEV && config->param.dev == NULL) {
        return NULL;
    }

    sess->usr_map = usr_map;
    sess->comp_optype = WCRYPTO_DEFLATE;
    sess->comp_algtype = WCRYPTO_ZLIB;
    ret = kaezip_task_queue_init(&sess->task_queue, 0);
    if (ret != 0) {
         free(sess);
        return NULL;
    }
    ret = kaezip_async_instances_init(&sess->ctrl, usr_map, sess->comp_optype, sess->comp_algtype, config);
    // generate zlib header
    kaezip_set_zlib_header(sess->ctrl, level, windowBits);

    if (ret != 0) {
        kaezip_task_queue_free(&sess->task_queue);
        free(sess);
        return NULL;
    }

    return sess;
}

void *KAEZIP_create_async_decompress_session_zlib(iova_map_fn usr_map, const device_config_t *config)
{
    kaezip_session *sess = (kaezip_session *)kae_malloc(sizeof(kaezip_session));
    int ret = 0;

    if (!sess)
        return NULL;

    // check config
    if (config != NULL && config->policy == KAE_SELECT_BY_DEV && config->param.dev == NULL) {
        return NULL;
    }

    sess->usr_map = usr_map;
    sess->comp_optype = WCRYPTO_INFLATE;
    sess->comp_algtype = WCRYPTO_ZLIB;
    ret = kaezip_task_queue_init(&sess->task_queue, 0);
    if (ret != 0) {
        free(sess);
        return NULL;
    }
    ret = kaezip_async_instances_init(&sess->ctrl, usr_map, sess->comp_optype, sess->comp_algtype, config);
    if (ret != 0) {
        kaezip_task_queue_free(&sess->task_queue);
        free(sess);
        return NULL;
    }

    return sess;
}

const struct zip_dev *KAEZIP_get_devices(unsigned int *num)
{
    // initialized, return without lock
    if (atomic_load_explicit(&g_initialized, memory_order_acquire)) {
        if (num) {
            *num = g_dev_count;
        }
        return g_dev_count > 0 ? g_devices : NULL;
    }

    // not initialized
    pthread_mutex_lock(&g_init_mutex);
    if (!g_initialized) {
        if (scan_hisi_zip_devices(g_devices, &g_dev_count) == 0) {
            atomic_store_explicit(&g_initialized, 1, memory_order_release);
        }
    }
    pthread_mutex_unlock(&g_init_mutex);

    if (num) {
        *num = g_dev_count;
    }
    return g_dev_count > 0 ? g_devices : NULL;
}