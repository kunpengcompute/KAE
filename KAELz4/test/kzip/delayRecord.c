#include <stdlib.h>
#include <stdint.h>
#include <stdio.h> // printf
#include "delayRecord.h"
// 定义哈希表条目的最大数量
#define MAX_REASONABLE_LATENCY_NS (10ULL * 1000000000ULL)  // 10s
#define MIN_REASONABLE_LATENCY_NS 0  // 0ns

// 记录时延数据
void record_latency(uint64_t *all_delays, uint64_t latency, size_t sn)
{
    if (latency < MIN_REASONABLE_LATENCY_NS || latency > MAX_REASONABLE_LATENCY_NS) {
        return;
    }

    if (all_delays == NULL) {
        all_delays = (uint64_t *)malloc(MAX_LATENCY_COUNT * sizeof(uint64_t));
        if (all_delays == NULL) {
            return;
        }
    }
    if (sn < MAX_LATENCY_COUNT) {
        all_delays[sn] = latency;
    }
}

static int compare_uint64(const void *a, const void *b)
{
    uint64_t ua = *(uint64_t *)a;
    uint64_t ub = *(uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

double get_average_latency(uint64_t *all_delays, size_t cnt)
{
    uint64_t total_latency = 0;    // 总时延（单位 ns）

    if (cnt > MAX_LATENCY_COUNT) {
        cnt = MAX_LATENCY_COUNT;
    }
    if (cnt == 0) return -1.0;
    for (int i = 0; i < cnt; ++i) {
        total_latency += all_delays[i];
    }

    return total_latency / 1000.0 / cnt;
}
// 获取百分位置的时延数据。单位 us
double get_percent_delay(uint64_t *all_delays, int num, size_t cnt)
{
    if (cnt == 0) return -1.0;
    uint64_t idx;
    if (num >= 0 && num <= 100) {
        idx = cnt * num / 100;
    } else if (num > 100 && num <= 1000) {
        idx = cnt * num / 1000;
    } else if (num < 0) { // 负值从尾部开始计数
        idx = cnt + num;
    } else {
        return -1.0;  // 非法参数
    }
    if (idx >= cnt || idx < 0) return -1.0;  // 防越界
    return all_delays[idx] / 1000.0;  // 返回微秒，double 类型
}

void get_percent_latencies(uint64_t *all_delays, double *out_latencies, const int *percentiles, int count, size_t sn)
{
    if (sn > MAX_LATENCY_COUNT) {
        sn = MAX_LATENCY_COUNT;
    }
    if (!out_latencies || !percentiles || count <= 0) return;
    qsort(all_delays, sn, sizeof(uint64_t), compare_uint64);
    for (int i = 0; i < count; ++i) {
        out_latencies[i] = get_percent_delay(all_delays, percentiles[i], sn);
    }
    // for(int j = 0; j < 200; j++) {
    //     uint64_t idx = latency_count - 1 - j;
    //     printf("%ld:%.2f \n",idx, all_delays[idx] / 1000.0);
    // }
}