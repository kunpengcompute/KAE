/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * @Description: Recording the statistical delay data
 * @Author: Ma Xiaofeng
 * @Date: 2025-3-31
 * @LastEditTime: 2025-3-31
 */
#ifndef DELAY_RECORD_H
#define DELAY_RECORD_H

void record_latency(float latency);
void get_top_latencies(float top_latencies[3], int top_counts[3]);
int get_all_data_count();

#endif
