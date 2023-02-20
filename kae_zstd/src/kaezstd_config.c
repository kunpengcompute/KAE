/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae config functions
 * Author: songchao
 * Create: 2021-7-19
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "uadk/wd_alg_common.h"
#include "uadk/wd.h"
#include "uadk/wd_comp.h"
#include "uadk/wd_sched.h"
#include "uadk/uacce.h"

#include "kaezstd_common.h"
#include "kaezstd_sched.h"
#include "kaezstd_config.h"

KaeZstdConfig* kaezstd_get_config(ZSTD_CCtx* zc)
{
    KaeZstdConfig* config = (KaeZstdConfig*)(zc->kaeConfig);

    if (config != NULL) {
        return config;
    } else {
        return NULL;
    }
}

void kaezstd_set_config(ZSTD_CCtx* zc, KaeZstdConfig* config)
{
    if (zc != NULL) {
        zc->kaeConfig = (uintptr_t)config;
    }
}

static int lib_poll_func(__u32 pos, __u32 expect, __u32 *count)
{
    int ret;

    ret = wd_comp_poll_ctx(pos, expect, count);
    if (ret < 0) {
        return ret;
    }
    return 0;
}
int sample_sched_fill_data(const struct wd_sched *sched, int numa_id,
    __u8 mode, __u8 type, __u32 begin, __u32 end)
{
    struct sample_sched_info *sched_info = NULL;
    struct sample_sched_ctx *sched_ctx = NULL;

    if (!sched || !sched->h_sched_ctx) {
        WD_ERR("para err: sched of h_sched_ctx is null\n");
        return -EINVAL;
    }

    sched_ctx = (struct sample_sched_ctx*)sched->h_sched_ctx;

    if ((numa_id >= sched_ctx->numa_num) || (numa_id < 0) ||
        (mode >= SCHED_MODE_BUTT) ||
        (type >= sched_ctx->type_num)) {
        WD_ERR("para err: numa_id=%d, mode=%u, type=%u\n", numa_id, mode, type);
        return -EINVAL;
    }

    sched_info = sched_ctx->sched_info;

    if (!sched_info[numa_id].ctx_region[mode]) {
        WD_ERR("para err: ctx_region:numa_id=%d, mode=%u is null\n", numa_id, mode);
        return -EINVAL;
    }

    sched_info[numa_id].ctx_region[mode][type].begin = begin;
    sched_info[numa_id].ctx_region[mode][type].end = end;
    sched_info[numa_id].ctx_region[mode][type].last = begin;
    sched_info[numa_id].ctx_region[mode][type].valid = true;
    sched_info[numa_id].valid = true;

    pthread_mutex_init(&sched_info[numa_id].ctx_region[mode][type].lock, NULL);

    return 0;
}
static int kaezstd_init_ctx_config(Info* info, Options opts)
{
    struct wd_ctx_config *ctx_config = &(info->ctx_config);
    struct wd_sched *sched = info->sched;
    int ctx_num = opts.ctx_num;
    int ret;
    int i, j;

    sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 2, 2, lib_poll_func);
    if (!sched) {
        WD_ERR("failed to alloc a sample_sched\n");
        return KAE_ZSTD_ALLOC_FAIL;
    }

    sched->name = "sched_rr";

    ret = sample_sched_fill_data(sched, 0, 0, 0, 0, ctx_num - 1);
    if (ret < 0) {
        WD_ERR("Fail to fill sched region.\n");
        ret = KAE_ZSTD_SET_FAIL;
        goto out_fill;
    }
    ret = sample_sched_fill_data(sched, 0, 0, 1, ctx_num, ctx_num * 2 - 1);
    if (ret < 0) {
        WD_ERR("Fail to fill sched region.\n");
        ret = KAE_ZSTD_SET_FAIL;
        goto out_fill;
    }
    ret = sample_sched_fill_data(sched, 0, 1, 0, ctx_num * 2,
                                ctx_num * 3 - 1);
    if (ret < 0) {
        WD_ERR("Fail to fill sched region.\n");
        ret = KAE_ZSTD_SET_FAIL;
        goto out_fill;
    }
    ret = sample_sched_fill_data(sched, 0, 1, 1, ctx_num * 3,
                                ctx_num * 4 - 1);
    if (ret < 0) {
        WD_ERR("Fail to fill sched region.\n");
        ret = KAE_ZSTD_SET_FAIL;
        goto out_fill;
    }

    memset(ctx_config, 0, sizeof(struct wd_ctx_config));
    ctx_config->ctx_num = ctx_num * 4;
    ctx_config->ctxs = calloc(1, ctx_num * 4 * sizeof(struct wd_ctx));
    if (!ctx_config->ctxs) {
        WD_ERR("Not enough memory to allocate contexts.\n");
        ret = KAE_ZSTD_ALLOC_FAIL;
        goto out_fill;
    }

    // dbg("request ctx number is %u\n", ctx_config->ctx_num);

    for (i = 0; i < ctx_config->ctx_num; i++) {
        ctx_config->ctxs[i].ctx = wd_request_ctx(info->list->dev);
        if (!ctx_config->ctxs[i].ctx) {
            WD_ERR("Fail to allocate context #%d\n", i);
            ret = KAE_ZSTD_ALLOC_FAIL;
            goto out_ctx;
        }
        ctx_config->ctxs[i].op_type = WD_DIR_COMPRESS;
        ctx_config->ctxs[i].ctx_mode = CTX_MODE_SYNC;
    }

    wd_comp_init(ctx_config, sched);

    return ret;
out_ctx:
    for (j = 0; j < i; j++)
        wd_release_ctx(ctx_config->ctxs[j].ctx);
    free(ctx_config->ctxs);

out_fill:
    wd_sched_rr_release(sched);

    return ret;
}

void kaezstd_options_init(KaeZstdConfig *config)
{
    config->opts.ctx_num = KAEZSTD_DEFAULT_CTX_NUM;
    config->opts.thread_num = KAEZSTD_DEFAULT_THREAD_NUM;
}

struct uacce_dev_list *kaezstd_get_dev_list(Options opts)
{
    unsigned int total_ctx_num = opts.ctx_num * opts.thread_num * 4;
    struct uacce_dev_list *head = NULL;
    struct uacce_dev_list *prev = NULL;
    struct uacce_dev_list *list = NULL;
    struct uacce_dev_list *p = NULL;
    int avail_ctx_num;

    // dbg("total ctx number is %x\n", total_ctx_num);

    list = wd_get_accel_list("lz77_zstd");
    if (!list) {
        WD_ERR("failed to get device list\n");
        return NULL;
    }

    p = list;
    /* Find one device matching the requested contexts. */
    while (p) {
        avail_ctx_num = wd_get_avail_ctx(p->dev);
        /*
         * Check whether there's enough contexts.
         * There may be multiple taskes running together.
         * The number of multiple taskes is specified in children.
         */
        if (avail_ctx_num < total_ctx_num) {
            if (!head) {
                head = p;
            }
            prev = p;
            p = p->next;
        } else {
            break;
        }
    }

    if (!p) {
        WD_ERR("Request too much contexts: %d\n", total_ctx_num);
        goto out;
    }

    /* Adjust p to the head of list if p is in the middle. */
    if (p && (p != list)) {
        prev->next = p->next;
        p->next = head;
        return p;
    }

    return list;

out:
    wd_free_list_accels(list);

    return NULL;
}

int kaezstd_create_session(KaeZstdConfig *config)
{
    config->setup.alg_type = WD_LZ77_ZSTD;
    config->setup.op_type = WD_DIR_COMPRESS;
    config->sess = wd_comp_alloc_sess(&(config->setup));
    if (!(config->sess)) {
        WD_ERR("failed to alloc comp sess!\n");
        return KAE_ZSTD_ALLOC_FAIL;
    }
    config->req.src = calloc(1, REQ_SRCBUFF_LEN);
    config->req.dst = calloc(1, REQ_DSTBUFF_LEN);
    config->req.dst_len = REQ_DSTBUFF_LEN;
    config->req.op_type = WD_DIR_COMPRESS;
    config->req.data_fmt = WD_FLAT_BUF;
    config->req.priv = &(config->tuple);
    config->tuple.bstatus = TUPLE_STATUS_COMPRESS;

    return 0;
}

void kaezstd_release_ctx(KaeZstdConfig *config)
{
    int i;

    for (i = 0; i < config->info.ctx_config.ctx_num; i++)
        wd_release_ctx(config->info.ctx_config.ctxs[i].ctx);

    free(config->info.ctx_config.ctxs);

    wd_sched_rr_release(config->info.sched);
}

int kaezstd_init(ZSTD_CCtx* zc)
{
    int ret;
    KaeZstdConfig *config = NULL;

    config = (KaeZstdConfig*)malloc(sizeof(KaeZstdConfig));
    if (config == NULL) {
        WD_ERR("failed to alloc config!\n");
        return KAE_ZSTD_INIT_FAIL;
    }

    kaezstd_options_init(config);

    config->info.list = kaezstd_get_dev_list(config->opts);
    if (!(config->info.list)) {
        WD_ERR("failed to find devices!\n");
        goto get_dev_list_fail;
    }

    ret = kaezstd_init_ctx_config(&(config->info), config->opts);
    if (ret) {
        WD_ERR("failed to init ctx!\n");
        goto init_ctx_config_fail;
    }

    ret = kaezstd_create_session(config);
    if (ret) {
        WD_ERR("failed to init session!\n");
        goto create_session_fail;
    }

    kaezstd_set_config(zc, config);

    return ret;

create_session_fail:
   kaezstd_release_ctx(config);

init_ctx_config_fail:
    wd_free_list_accels(config->info.list);

get_dev_list_fail:
    free(config);
    return KAE_ZSTD_INIT_FAIL;
}

void kaezstd_release(ZSTD_CCtx* zc)
{
    KaeZstdConfig *config = NULL;

    if (zc == NULL) {
        return;
    }

    config = kaezstd_get_config(zc);

    kaezstd_release_ctx(config);

    wd_comp_free_sess(config->sess);

    wd_free_list_accels(config->info.list);
}
