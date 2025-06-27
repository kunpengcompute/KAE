/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: Recording the statistical delay data
 * @Author: Ma Xiaofeng
 * @Date: 2025-3-31
 * @LastEditTime: 2025-3-31
 */
#ifndef DELAY_RECORD_H
#define DELAY_RECORD_H

#define MAX_LATENCY_COUNT 100000000
void record_latency(uint64_t *all_delays, uint64_t latency, size_t sn);
void get_percent_latencies(uint64_t *all_delays, double *out_latencies, const int *percentiles, int count, size_t sn);
double get_average_latency(uint64_t *all_delays, size_t cnt);

#endif
