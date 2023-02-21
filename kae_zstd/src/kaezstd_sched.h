/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae schedules functions
 * Author: songchao
 * Create: 2021-7-19
 */

#ifndef KAEZSTD_SCHED_H
#define KAEZSTD_SCHED_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "uadk/wd_alg_common.h"
#include "uadk/wd.h"
#include "uadk/wd_comp.h"
#include "uadk/uacce.h"

#include "kaezstd.h"

#define MAX_NUMA_NUM 4
#define INVALID_POS 0xFFFFFFFF
#define MAX_POLL_TIMES 1000

typedef int (*user_poll_func)(__u32 pos, __u32 expect, __u32 *count);

enum sched_region_mode {
    SCHED_MODE_SYNC = 0,
    SCHED_MODE_ASYNC = 1,
    SCHED_MODE_BUTT
};

/*
* struct sched_ctx_range - define one ctx pos.
* @begin: the start pos in ctxs of config.
* @end: the end pos in ctxx of config.
* @last: the last one which be distributed.
*/
struct sched_ctx_region {
    __u32 begin;
    __u32 end;
    __u32 last;
    bool valid;
    pthread_mutex_t lock;
};

/*
* sample_sched_info - define the context of the scheduler.
* @ctx_region: define the map for the comp ctxs, using for quickly search.
*              the x range: two(sync and async), the y range:
*              two(e.g. comp and uncomp) the map[x][y]'s value is the ctx
*              begin and end pos.
* @valid: the region used flag.
*/
struct sample_sched_info {
    struct sched_ctx_region *ctx_region[SCHED_MODE_BUTT];
    bool valid;
};

struct sample_sched_ctx {
    __u32 policy;
    __u32 type_num;
    __u8  numa_num;
    user_poll_func poll_func;
    struct sample_sched_info sched_info[0];
};

struct cache {
    __u32 *buff;
    __u32 depth;
    __u32 head;
    __u32 tail;
    __u32 used_num;
};

/**
 * sample_sched_fill_data - Fill the schedule min region.
 * @sched: The schdule instance
 * @numa_id: NUMA ID
 * @mode: Sync or async mode. sync: 0, async: 1
 * @type: Service type, the value must smaller than type_num.
 * @begin: The begig ctx resource index for the region
 * @end:  The end ctx resource index for the region.
 *
 * The shedule indexed mode is NUMA -> MODE -> TYPE -> [BEGIN : END],
 * then select one index from begin to end.
 */
int sample_sched_fill_data(const struct wd_sched *sched, int numa_id,
    __u8 mode, __u8 type, __u32 begin, __u32 end);

#endif
