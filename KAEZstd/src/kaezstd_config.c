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
#include "kaezstd_config.h"
#include "kaezstd_log.h"

#define CTX_SET_SIZE 4
#define CTX_SET_NUM 1

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

static struct wd_sched *kaezstd_sched_init()
{
    int ctx_set_num = CTX_SET_NUM;
    int ret;
    int i, j;
    struct sched_params param;
    struct wd_sched *sched;

    sched = wd_sched_rr_alloc(SCHED_POLICY_RR, 2, 2, lib_poll_func);
    if (!sched) {
        US_ERR("failed to alloc a sample_sched\n");
        return NULL;
    }

    sched->name = "sched_rr";

    for (i = 0; i < CTX_SET_SIZE; i++) {
        for (j = CTX_SET_NUM * i; j < CTX_SET_NUM * (i + 1); j++) {
            param.mode = i / 2;
            param.type = i % 2;
            param.numa_id = 0;
            param.begin = ctx_set_num * i;
            param.end = ctx_set_num * (i + 1) - 1;
            ret = wd_sched_rr_instance(sched, &param);
            if (ret < 0) {
                US_ERR("Fail to fill sched region.\n");
                ret = KAE_ZSTD_SET_FAIL;
                goto out_fill;
            }
        }
    }
    return sched;

out_fill:
    wd_sched_rr_release(sched);
    return NULL;
}

static int kaezstd_init_ctx_config(Info* info, Options opts)
{
    struct wd_ctx_config *ctx_config = &(info->ctx_config);
    int ctx_num = opts.ctx_num;
    int ret;
    int i, j;

    memset(ctx_config, 0, sizeof(struct wd_ctx_config));
    ctx_config->ctx_num = ctx_num * 4;
    ctx_config->ctxs = calloc(1, ctx_num * 4 * sizeof(struct wd_ctx));
    if (!ctx_config->ctxs) {
        US_ERR("Not enough memory to allocate contexts.\n");
        ret = KAE_ZSTD_ALLOC_FAIL;
        return ret;
    }

    for (i = 0; i < ctx_config->ctx_num; i++) {
        ctx_config->ctxs[i].ctx = wd_request_ctx(info->list->dev);
        if (!ctx_config->ctxs[i].ctx) {
            US_ERR("Fail to allocate context #%d\n", i);
            ret = KAE_ZSTD_ALLOC_FAIL;
            goto out_ctx;
        }
        ctx_config->ctxs[i].op_type = i % 2;
        ctx_config->ctxs[i].ctx_mode = i / 2;
    }

    struct wd_sched *sched = kaezstd_sched_init();
    if (!sched) {
        ret = -WD_EINVAL;
        goto out_ctx;
    }
    info->sched = sched;

    ret = wd_comp_init(ctx_config, sched);
    if (ret) {
        US_ERR("fail to init comp.\n");
        goto out_fill;
    }

    return ret;
out_fill:
    wd_sched_rr_release(sched);

out_ctx:
    for (j = 0; j < i; j++)
        wd_release_ctx(ctx_config->ctxs[j].ctx);
    free(ctx_config->ctxs);

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
        US_ERR("failed to get device list\n");
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
        US_ERR("Request too much contexts: %d\n", total_ctx_num);
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
    struct sched_params *param = NULL;
    param = (struct sched_params *)malloc(sizeof(struct sched_params));
    if (param == NULL) {
        US_ERR("failed to alloc param!\n");
        return KAE_ZSTD_ALLOC_FAIL;
    }
    memset(param, 0, sizeof(struct sched_params));
    memset(&config->req, 0, sizeof(struct wd_comp_req));
    memset(&config->setup, 0, sizeof(struct wd_comp_sess_setup));
    config->setup.sched_param = param;
    config->setup.alg_type = WD_LZ77_ZSTD;
    config->setup.op_type = WD_DIR_COMPRESS;
    config->setup.win_sz = REQ_WINDOW_SIZE;
    config->setup.comp_lv = REQ_COMPRESS_LEVEL;
    config->sess = wd_comp_alloc_sess(&(config->setup));
    if (!(config->sess)) {
        US_ERR("failed to alloc comp sess!\n");
        free(param);
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

static inline void versionCpy(char str1[], const char str2[])
{
    int i = 0;
    while (str2[i] != '\0' && i < VERSION_STRUCT_LEN) {
        str1[i] = str2[i];
        i++;
    }
    str1[i] = '\0';
}

int kaezstd_get_version(KAEZstdVersion* ver)
{
    if (ver == NULL) {
        return KAE_ZSTD_INVAL_PARA;
    }
    versionCpy(ver->productName, "Kunpeng Boostkit");
    versionCpy(ver->productVersion, "23.0.RC2");
    versionCpy(ver->componentName, "KAEZstd");
    versionCpy(ver->componentVersion, "2.0.0");
    return KAE_ZSTD_SUCC;
}

int kaezstd_init(ZSTD_CCtx* zc)
{
    int ret;
    KaeZstdConfig *config = NULL;
    kaezstd_debug_init_log();
    US_DEBUG("Begin init KAE zstd.");
    config = (KaeZstdConfig*)malloc(sizeof(KaeZstdConfig));
    if (config == NULL) {
        US_ERR("failed to alloc config!\n");
        return KAE_ZSTD_INIT_FAIL;
    }

    kaezstd_options_init(config);

    config->info.list = kaezstd_get_dev_list(config->opts);
    if (!(config->info.list)) {
        US_ERR("failed to find devices!\n");
        goto get_dev_list_fail;
    }

    ret = kaezstd_init_ctx_config(&(config->info), config->opts);
    if (ret) {
        US_ERR("failed to init ctx!\n");
        goto init_ctx_config_fail;
    }

    ret = kaezstd_create_session(config);
    if (ret) {
        US_ERR("failed to init session!\n");
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

    kaezstd_debug_close_log();
}
