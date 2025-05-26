#include <stdlib.h>
// #include <stdio.h>

// 定义哈希表条目的最大数量
#define MAX_LATENCY_COUNT 3000
// 用于存储每个时延的结构体
typedef struct {
    float latency;
    int count;
} LatencyEntry;
// 哈希表，用于存储时延值及其出现次数
LatencyEntry latencies[MAX_LATENCY_COUNT];
int latency_count = 0;  // 当前存储的时延数
// 记录时延数据
void record_latency(float latency) {
    // 查找是否已有该时延值
    for (int i = 0; i < latency_count; i++) {
        if (latencies[i].latency == latency) {
            latencies[i].count++;
            return;
        }
    }
    // 如果没有找到该时延值，插入新条目
    if (latency_count < MAX_LATENCY_COUNT) {
        latencies[latency_count].latency = latency;
        latencies[latency_count].count = 1;
        latency_count++;
    }
}
// 比较函数，用于排序（按时延出现的次数从大到小）
int compare(const void *a, const void *b) {
    return ((LatencyEntry *)b)->count - ((LatencyEntry *)a)->count;
}
// 获取出现次数最多的前三个时延
void get_top_latencies(float top_latencies[3], int top_counts[3]) {
    // 如果没有足够的数据，返回默认值
    if (latency_count < 1) {
        top_latencies[0] = top_latencies[1] = top_latencies[2] = 0;
        top_counts[0] = top_counts[1] = top_counts[2] = 0;
        return;
    }

    // 排序时延数据，根据 count 值降序排列
    qsort(latencies, latency_count, sizeof(LatencyEntry), compare);

    // 获取前三个时延和它们的出现次数
    for (int i = 0; i < 3 && i < latency_count; i++) {
        top_latencies[i] = latencies[i].latency;
        top_counts[i] = latencies[i].count;
    }

    // 如果总数不足3个，剩下的用默认值填充
    for (int i = latency_count; i < 3; i++) {
        top_latencies[i] = 0;
        top_counts[i] = 0;
    }
}

int get_all_data_count() {
    return latency_count;
}
