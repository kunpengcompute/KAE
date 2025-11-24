/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy adapter for sva(v2) and nosva(v1)
 * @Author: LiuYongYang
 * @Date: 2024-02-22
 * @LastEditTime: 2024-02-26
 */

#include <stdlib.h>
#include <semaphore.h>
#include "kaesnappy_common.h"
#include "kaesnappy.h"
#include "kaesnappy_utils.h"
#include "kaesnappy_adapter.h"
#include "kaesnappy_log.h"
#include "uadk/wd.h"

snappy_task_queues g_task_queues = {0};
pthread_mutex_t g_task_queue_init_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_task_queue_mutex[MAX_TASK_NUM] = { PTHREAD_MUTEX_INITIALIZER };
static __thread int g_platform = -1;

static void uadk_get_accel_platform(void)
{
    if (g_platform >= 0) {
        return;
    }
    //  init log
    kaesnappy_debug_init_log();

    //  check no-sva
    int nosva_dev_num = wd_get_available_dev_num("lz77_zstd");
    if (nosva_dev_num > 0) {
        g_platform = HW_V1;
        goto end;
    }
    //  hardware don't support, use zstd original interface
    g_platform = HW_NONE;
end:
     US_INFO("kaesnappy v%d inited!\n", g_platform);
}

int kaesnappy_init(SNAPPY_CCtx* zc)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaesnappy_init_v1(zc);
        break;
    default:
        break;
    }
    US_INFO("kaesnappy_init return code is %d\n", ret);
    return ret;
}

void kaesnappy_release(SNAPPY_CCtx* zc)
{
    uadk_get_accel_platform();

    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        kaesnappy_release_v1(zc);
        break;
    default:
        break;
    }
    US_INFO("kaesnappy_released");
}

int kaesnappy_compress(SNAPPY_CCtx* zc, const void* src, size_t srcSize)
{
    uadk_get_accel_platform();

    int ret = -1;
    switch (g_platform)
    {
    case HW_NONE:
        break;
    case HW_V1:
        ret = kaesnappy_compress_v1(zc, src, srcSize);
        break;
    default:
        break;
    }
    US_INFO("kaesnappy_compress return code is %d\n", ret);
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

static void init_env_config()
{

    char *task_queue_num = getenv("KAE_SNAPPY_ASYNC_THREAD_NUM");
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
