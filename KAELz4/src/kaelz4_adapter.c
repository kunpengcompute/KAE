/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaelz4 adapter for sva(v2) and nosva(v1)
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-26
 */

#include <stdlib.h>
#include <semaphore.h>
#include "kaelz4_common.h"
#include "kaelz4.h"
#include "kaelz4_utils.h"
#include "kaelz4_adapter.h"
#include "kaelz4_log.h"
#include "uadk/wd.h"

lz4_task_queues g_task_queues = {0};
pthread_mutex_t g_task_queue_init_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_task_queue_mutex[MAX_TASK_NUM] = { PTHREAD_MUTEX_INITIALIZER };
static struct timespec polling_timeout = { 1, 0 };  // 1秒超时
static __thread int g_platform = -1;

static void uadk_get_accel_platform(void)
{
    if (g_platform >= 0) {
        return;
    }
    //  init log
    kaelz4_debug_init_log();
    //  check sva
    struct uacce_dev* dev = wd_get_accel_dev("lz77_zstd");
    if (dev) {
        int flag = dev->flags;
        free(dev);
        if (flag & 0x1) {
            g_platform = HW_V2;
            goto end;
        }
    }
    //  check no-sva
    int nosva_dev_num = wd_get_available_dev_num("lz77_zstd");
    if (nosva_dev_num > 0) {
        g_platform = HW_V1;
        goto end;
    }
    //  hardware don't support, use zstd original interface
    g_platform = HW_NONE;
end:
     US_INFO("kaelz4 v%d inited!\n", g_platform);
}

int kaelz4_init(LZ4_CCtx* zc)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaelz4_init_v1(zc);
        break;
    case HW_V2:
        ret = kaelz4_init_v2(zc);
        break;
    default:
        break;
    }
    US_INFO("kaelz4_init return code is %d\n", ret);
    return ret;
}

void kaelz4_reset(LZ4_CCtx* zc)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaelz4_reset_v1(zc);
        break;
    case HW_V2:
        break;
    default:
        break;
    }
    US_INFO("kaelz4_reset");
}

void kaelz4_release(LZ4_CCtx* zc)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaelz4_release_v1(zc);
        break;
    case HW_V2:
        kaelz4_release_v2(zc);
        break;
    default:
        break;
    }
    US_INFO("kaelz4_released");
}

void kaelz4_setstatus(LZ4_CCtx* zc, unsigned int status)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaelz4_setstatus_v1(zc, status);
        break;
    case HW_V2:
        kaelz4_setstatus_v2(zc, status);
        break;
    default:
        break;
    }
    US_INFO("kaelz4_set blk_type %d\n", status);
}

int kaelz4_compress(LZ4_CCtx* zc, const void* src, size_t srcSize)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaelz4_compress_v1(zc, src, srcSize);
        break;
    case HW_V2:
        ret = kaelz4_compress_v2(zc, src, srcSize);
        break;
    default:
        break;
    }
    US_INFO("kaelz4_compress return code is %d\n", ret);
    return ret;
}

#define MAX_CPUS 512 // 最大可绑核数量。
static int g_taskset_cpus_arr_numa1[MAX_CPUS]; // 自动获取的numa1的CPU核心数组
static int g_taskset_cpus_arr_numa1_count = 0; // 自动获取的numa1的CPU核心数组长度
static int g_taskset_cpus_arr_numa2[MAX_CPUS];
static int g_taskset_cpus_arr_numa2_count = 0;

/**
 * 获取所有亲和的CPU，根据所需的numa1 和 numa2 的值，将亲和的CPU过滤出来，分别存放到arr1和arr2中。
 */
static void get_parent_cpu_affinity(int *arr1, int *count1, int numa1, int *arr2, int *count2, int numa2)
{
    // 子线程中获取父进程的亲和性
    cpu_set_t parent_affinity;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &parent_affinity) != 0) {
        US_ERR("sched_getaffinity failed");
        return;
    }

    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &parent_affinity)) {
            int node = numa_node_of_cpu(i);
            if (node == numa1) {
                arr1[(*count1)++] = i;
            } else if (node == numa2) {
                arr2[(*count2)++] = i;
            }
        }
    }
}

static void auto_init_cpuset_config(int *arr1, int *count1, int *arr2, int *count2)
{
    int cpu = sched_getcpu();
    int node = numa_node_of_cpu(cpu);
    // 使用比较亲近的两组numa。此处默认0与1亲近、2与3亲近。可通过 numactl -H 查看真实情况。
    int needNuma1 = node > 1 ? 2 : 0;
    int needNuma2 = node > 1 ? 3 : 1;
    get_parent_cpu_affinity(arr1, count1, needNuma1, arr2, count2, needNuma2);
}
/**
 * 绑定CPU亲和
 * @params [in] i 并发的进程或线程数
 */
static void set_cpu_affinity_for_child(int i)
{
    if (g_taskset_cpus_arr_numa2_count <= 0 && g_taskset_cpus_arr_numa1_count <= 0) {
        return;
    }
    cpu_set_t mask;
    CPU_ZERO(&mask);           // 清空 CPU 集合

    int real_loop;
    int *real_arr;
    if (g_taskset_cpus_arr_numa1_count > 0 && g_taskset_cpus_arr_numa2_count > 0) {
        // 如果用户同时设置了2组NUMA上的CPU，那么偶数线程使用numa1的CPU，奇数线程使用numa2的CPU
        real_loop = (i % 2 == 0) ? g_taskset_cpus_arr_numa1_count : g_taskset_cpus_arr_numa2_count;
        real_arr = (i % 2 == 0) ? g_taskset_cpus_arr_numa1 : g_taskset_cpus_arr_numa2;
    } else {
        // 如果用户只设置了一组NUMA上的CPU，那么所有线程都使用这组CPU
        real_loop = g_taskset_cpus_arr_numa1_count > 0 ? g_taskset_cpus_arr_numa1_count : g_taskset_cpus_arr_numa2_count;
        real_arr = g_taskset_cpus_arr_numa1_count > 0 ? g_taskset_cpus_arr_numa1 : g_taskset_cpus_arr_numa2;
    }
    for (int j = 0; j < real_loop; j++) {
        CPU_SET(real_arr[j], &mask);
    }

    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) != 0) {
        US_ERR("pthread_setaffinity_np failed! thread num: %d.", i);
    }
}

static void kaelz4_dequeue_process(lz4_task_queue *task_queue, int budget)
{
    US_DEBUG("do kaelz4_dequeue_process. budget: %d", budget);
    int cnt = 0;
    // 等待任务
    while (task_queue->pi != task_queue->ci && cnt < budget) {

        // 如果要停止线程
        if (task_queue->stop) {
            break;
        }
        if (kaelz4_async_is_thread_do_comp_full() == 1) {
            break;
        }

        // 获取任务
        size_t ci = task_queue->ci;
        lz4_async_task_t task;

        task = task_queue->tasks[ci];
        // 更新 ci，复用空闲位置
        task_queue->ci = (task_queue->ci + 1) % KAELZ4_TASK_QUEUE_DEPTH;
        // 执行压缩操作
        kaelz4_compress_async(task.src, task.dst, task.callback, task.result,
                              task.data_format, &task.preferences);
        cnt++;
    }
    return;
}

static void *compress_thread_func(void *arg)
{
    lz4_task_queue *task_queue = arg;
    struct timespec timeout;
    int ret = 0;
    int enter_idle = 0;

    set_cpu_affinity_for_child(task_queue->index);

    kaelz4_async_init(&task_queue->stop, g_task_queues.sw_compress, g_task_queues.sw_compress_frame);

    while (1) {
        // 等待任务
        while (task_queue->pi == task_queue->ci && ret == KAE_LZ4_PROCESS_IDLE) {
            if (enter_idle == 0) {
                get_time_out_spec(&timeout, &polling_timeout);
                enter_idle = 1;
            }
            // 如果要停止线程
            if (unlikely(task_queue->stop)) {
                goto exit_thread;
            }

            if (unlikely(check_time_out(&timeout))) {
                kaelz4_ctx_clear();
                sem_wait(&task_queue->sem);
            }
        }

        if (unlikely(task_queue->stop)) {
            break;
        }

        enter_idle = 0;

        if (!kaelz4_async_is_thread_do_comp_full()) {
            kaelz4_dequeue_process(task_queue, ASYNC_DEQUEUE_PROCESS_DEFAULT_BUDGET);
        }
        ret = kaelz4_async_compress_polling(ASYNC_POLLING_DEFAULT_BUDGET);
    }

exit_thread:
    kaelz4_async_deinit();
    return NULL;
}

static void init_env_config()
{

    char *task_queue_num = getenv("KAE_LZ4_ASYNC_THREAD_NUM");
    if (task_queue_num != NULL) {
        g_task_queues.num = atoi(task_queue_num);
        if (g_task_queues.num > MAX_TASK_NUM) {
            g_task_queues.num = MAX_TASK_NUM;
        }
    }

    auto_init_cpuset_config(g_taskset_cpus_arr_numa1,
        &g_taskset_cpus_arr_numa1_count,
        g_taskset_cpus_arr_numa2,
        &g_taskset_cpus_arr_numa2_count);
}
__attribute__((constructor))
void async_thread_constructor(void)
{
    init_env_config();
}

static int kaelz4_task_queue_init(lz4_task_queue *task_queue, int index)
{
    task_queue->tasks = malloc(KAELZ4_TASK_QUEUE_DEPTH * sizeof(lz4_async_task_t));
    if (task_queue->tasks == NULL) {
        return KAE_LZ4_ALLOC_FAIL;
    }
    task_queue->pi = 0;
    task_queue->ci = 0;
    task_queue->stop = 0;
    task_queue->index = index;
    sem_init(&task_queue->sem, 0, 0);
    task_queue->mutex = &g_task_queue_mutex[index];
    if (pthread_create(&task_queue->worker_thread, NULL, compress_thread_func, task_queue) != 0) {
        US_ERR("Error: Failed to create compression worker thread");
        free(task_queue->tasks);
        task_queue->tasks = NULL;
        return KAE_LZ4_INIT_FAIL;
    }
    return KAE_LZ4_SUCC;
}

static void kaelz4_task_queue_free(lz4_task_queue *task_queue)
{
    pthread_mutex_lock(task_queue->mutex);
    task_queue->stop = 1;
    sem_post(&task_queue->sem);
    pthread_join(task_queue->worker_thread, NULL);
    sem_destroy(&task_queue->sem);
    free(task_queue->tasks);
    task_queue->tasks = NULL;
    pthread_mutex_unlock(task_queue->mutex);
}

static int kaelz4_task_queues_init(int task_queue_num)
{
    int i;

    if (g_task_queues.num == 0) {
        g_task_queues.num = task_queue_num;
    }

    if (g_task_queues.num > MAX_TASK_NUM) {
        return KAE_LZ4_INIT_FAIL;
    }

    for (i = 0; i < g_task_queues.num; i++) {
        if (kaelz4_task_queue_init(&g_task_queues.task_queue[i], i) != 0)
            goto task_queue_free;
    }

    return KAE_LZ4_SUCC;

task_queue_free:
    while (i--) {
        kaelz4_task_queue_free(&g_task_queues.task_queue[i]);
    }
    return KAE_LZ4_INIT_FAIL;
}

int KAELZ4_async_compress_init(sw_compress_fn sw_compress, sw_compress_frame_fn sw_compress_frame)
{
    int ret = 0;
    pthread_mutex_lock(&g_task_queue_init_mutex);
    if (g_task_queues.init == 0) {
        g_task_queues.sw_compress = sw_compress;
        g_task_queues.sw_compress_frame = sw_compress_frame;
        ret = kaelz4_task_queues_init(KAELZ4_TASK_THREAD_NUM);
        if (ret != 0) {
            g_task_queues.init = 0;
            pthread_mutex_unlock(&g_task_queue_init_mutex);
            return ret;
        }
    }
    g_task_queues.init = 1;
    pthread_mutex_unlock(&g_task_queue_init_mutex);
    return ret;
}

void KAELZ4_teardown_async_compress(void)
{
    pthread_mutex_lock(&g_task_queue_init_mutex);
    if (g_task_queues.init == 0) {
        pthread_mutex_unlock(&g_task_queue_init_mutex);
        return;
    }

    g_task_queues.init = 0;
    for (int i = 0; i < g_task_queues.num; i++) {
        kaelz4_task_queue_free(&g_task_queues.task_queue[i]);
    }
    pthread_mutex_unlock(&g_task_queue_init_mutex);
    return;
}

static inline int kaelz4_enqueue(lz4_task_queue *task_queue, lz4_async_task_t *task)
{
    unsigned int cnt = 0;

    pthread_mutex_lock(task_queue->mutex);
    while ((task_queue->pi + 1) % KAELZ4_TASK_QUEUE_DEPTH == task_queue->ci) {
        pthread_mutex_unlock(task_queue->mutex);
        if (cnt > ENQUEUE_TIME_OUT_US) {
            return KAE_LZ4_ALLOC_FAIL;
        }

        cnt++;
        usleep(1);
        pthread_mutex_lock(task_queue->mutex);
    }

    if (task_queue->tasks == NULL) {
        return KAE_LZ4_ALLOC_FAIL;
    }
    US_DEBUG("receive a task, enqueue");

    size_t task_index = task_queue->pi;
    task_queue->tasks[task_index] = *task;
    wmb();
    task_queue->pi = (task_queue->pi + 1) % KAELZ4_TASK_QUEUE_DEPTH;

    sem_post(&task_queue->sem);
    pthread_mutex_unlock(task_queue->mutex);
    return 0;
}

static unsigned int kaelz4_get_queue_id(void)
{
    unsigned int index = 0;
    unsigned int min = 0xFFFFFFFF;
    for (int i = 0; i < g_task_queues.num; i++) {
        unsigned int depth = (g_task_queues.task_queue[i].pi + KAELZ4_TASK_QUEUE_DEPTH - g_task_queues.task_queue[i].ci) % KAELZ4_TASK_QUEUE_DEPTH;
        if (min > depth) {
            min = depth;
            index = i;
            if (min == 0) {
                break;
            }
        }
    }
    return index;
}
static int kaelz4_async_do_comp(const void *src, void *dst,
                                lz4_async_callback callback, struct kaelz4_result *result,
                                enum kae_lz4_async_data_format data_format, const LZ4F_preferences_t* preferences_ptr)
{
    // 初始化队列容量
    if (unlikely(g_task_queues.init == 0)) {
        if (KAELZ4_async_compress_init(NULL, NULL) != 0) {
            return KAE_LZ4_INIT_FAIL;
        }
    }

    // 添加任务到队列
    unsigned int index = kaelz4_get_queue_id();
    lz4_async_task_t task = {0};
    task.src = src;
    task.dst = dst;
    task.callback = callback;
    task.result = result;
    task.data_format = data_format;
    if (preferences_ptr != NULL) {
        task.preferences = *preferences_ptr;
    }

    return kaelz4_enqueue(&g_task_queues.task_queue[index], &task);
}

int KAELZ4_compress_async(const void *src, void *dst, lz4_async_callback callback,
                          struct kaelz4_result *result)
{
    if (unlikely(src == NULL || dst == NULL || callback == NULL || result == NULL || result->src_size == 0)) {
        return KAE_LZ4_INVAL_PARA;
    }

    if (result->src_size <= SMALL_BLOCK_SIZE) {
        return kaelz4_async_do_comp(src, dst, callback, result, KAELZ4_ASYNC_SMALL_BLOCK, NULL);
    }

    return kaelz4_async_do_comp(src, dst, callback, result, KAELZ4_ASYNC_BLOCK, NULL);
}

int KAELZ4F_compressFrame_async(const void* src, void* dst, lz4_async_callback callback,
                                struct kaelz4_result *result, const void *preferences_ptr)
{
    if (unlikely(src == NULL || dst == NULL || callback == NULL || result == NULL || result->src_size == 0)) {
        return KAE_LZ4_INVAL_PARA;
    }

    return kaelz4_async_do_comp(src, dst, callback, result, KAELZ4_ASYNC_FRAME, preferences_ptr);
}
