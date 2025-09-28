/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2024. All rights reserved.
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

#include "kaesnappy_common.h"
#include "kaesnappy_config.h"
#include "kaesnappy_log.h"

#define CTX_SET_SIZE 4
#define CTX_SET_NUM 1

enum snappy_init_status {
    KAE_SNAPPY_UNINIT,
    KAE_SNAPPY_INIT,
};

struct kz_snappywrapper_config {
    int count;
    int status;
};

static struct kz_snappywrapper_config snappy_config = {0};
static pthread_mutex_t kz_snappy_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline int kaesnappy_lock()
{
   return pthread_mutex_lock(&kz_snappy_mutex);
}

static inline int kaesnappy_unlock()
{
   return pthread_mutex_unlock(&kz_snappy_mutex);
}

inline KaeSnappyConfig* kaesnappy_get_config(SNAPPY_CCtx* zc)
{
    KaeSnappyConfig* config = (KaeSnappyConfig*)(zc->kaeConfig);

    if (config != NULL) {
        return config;
    } else {
        return NULL;
    }
}

inline void kaesnappy_set_config(SNAPPY_CCtx* zc, KaeSnappyConfig* config)
{
    if (zc != NULL) {
        zc->kaeConfig = (uintptr_t)config;
    }
}

static inline void kaesnappy_options_init(KaeSnappyConfig *config)
{
    config->opts.ctx_num = KAESNAPPY_DEFAULT_CTX_NUM;
    config->opts.thread_num = KAESNAPPY_DEFAULT_THREAD_NUM;
}

// level 8\9 win 0-4
static void Compression_level_conversion(int reqlevel, int* kae_lev, int* kae_win)
{
    if (reqlevel <= 3) {
        * kae_lev = 8;
        * kae_win = 0;
        return;
    } else if (reqlevel >= 4 && reqlevel<=5) {
        * kae_lev = 9;
        * kae_win = 0;
        return;
    } else if (reqlevel >= 6 && reqlevel<=7) {
        * kae_lev = 8;
        * kae_win = 1;
        return;
    } else if (reqlevel >= 8 && reqlevel<=9) {
        * kae_lev = 9;
        * kae_win = 1;
        return;
    } else if (reqlevel >= 10 && reqlevel<=11) {
        * kae_lev = 8;
        * kae_win = 2;
        return;
    } else if (reqlevel >= 12 && reqlevel<=13) {
        * kae_lev = 9;
        * kae_win = 2;
        return;
    } else if (reqlevel >= 14 && reqlevel<=15) {
        * kae_lev = 8;
        * kae_win = 3;
        return;
    } else if (reqlevel >= 16 && reqlevel<=17) {
        * kae_lev = 9;
        * kae_win = 3;
        return;
    } else if (reqlevel >= 18 && reqlevel<=19) {
        * kae_lev = 8;
        * kae_win = 4;
        return;
    } else {
        * kae_lev = 9;
        * kae_win = 4;
        return;
    }
}

static int kaesnappy_get_level_by_env()
{
    char *snappy_str = getenv("KAE_SNAPPY_LEVEL");
    if (snappy_str == NULL) {
        US_DEBUG("KAE_SNAPPY_LEVEL is NULL\n");
        return -1;
    }
    int snappy_val = atoi(snappy_str);
    if (snappy_val < 1 || snappy_val > 22) {
        US_DEBUG("KAE_SNAPPY_LEVEL value out of range ：%d ", snappy_val);
        return -1;
    }
    US_DEBUG("KAE_SNAPPY_LEVEL value is ：%d ", snappy_val);
    return snappy_val;
}

static int kaesnappy_create_session(KaeSnappyConfig *config, int snappy_level)
{
    struct sched_params param = {0};
    int kaeLev, kaeWin, reqlevel;
    int env_level = kaesnappy_get_level_by_env();
    if (env_level > 0) {
	reqlevel = env_level;
    } else {
	reqlevel = snappy_level;
    }
    Compression_level_conversion(reqlevel, &kaeLev, &kaeWin);

    config->setup.sched_param = &param;
    config->setup.alg_type = WD_LZ77_ZSTD;
    config->setup.op_type = WD_DIR_COMPRESS;
    config->setup.win_sz  = kaeWin;
    config->setup.comp_lv = kaeLev;
    config->sess = (handle_t)0;
    config->sess = wd_comp_alloc_sess(&(config->setup));
    if (!(config->sess)) {
        US_ERR("failed to alloc comp sess!\n");
        return KAE_SNAPPY_ALLOC_FAIL;
    }
    config->req.dst = malloc(REQ_DSTBUFF_LEN);
    config->req.dst_len = REQ_DSTBUFF_LEN;
    config->req.op_type = WD_DIR_COMPRESS;
    config->req.data_fmt = WD_FLAT_BUF;
    config->req.priv = &(config->tuple);
    config->tuple.bstatus = TUPLE_STATUS_COMPRESS;
    US_DEBUG("[DEBUG] sess level is : %d; win is %d, algtype is %d.", config->setup.comp_lv, config->setup.win_sz, config->setup.alg_type);
    return 0;
}

static inline void snappy_uadk_uninit(void)
{
    return wd_comp_uninit2();
}

# define KAESNAPPY_CTX_SET_NUM 1
static int kaesnappy_alg_init2(void)
{
    struct wd_ctx_nums *ctx_set_num;
    struct wd_ctx_params cparams = {0};
    int ret, i;

    if (snappy_config.status == 1) {
        // 进程已经初始化过，直接返回
        return 0;
    }
    ctx_set_num = calloc(KAESNAPPY_CTX_SET_NUM, sizeof(*ctx_set_num));
    if (!ctx_set_num) {
	WD_ERR("failed to alloc ctx_set_size!\n");
	return KAE_SNAPPY_ALLOC_FAIL;
    }

    cparams.op_type_num = KAESNAPPY_CTX_SET_NUM;
    cparams.ctx_set_num = ctx_set_num;
    cparams.bmp = numa_allocate_nodemask();
    if (!cparams.bmp) {
	WD_ERR("failed to create nodemask!\n");
	ret = KAE_SNAPPY_INIT_FAIL;
	goto out_freectx;
    }

    int cpu = sched_getcpu();
    int node = numa_node_of_cpu(cpu);

    struct uacce_dev *dev = wd_get_accel_dev("lz77_zstd");//获取支持某种算法的最亲和的设备
    if (dev == NULL) {
        ret = KAE_SNAPPY_INIT_FAIL;
        goto out_freebmp;
    }
    numa_bitmask_setbit(cparams.bmp, dev->numa_id);
    US_DEBUG("cpu is %d, numa_niode_of_cpu is %d, dev-numaid is %d\n", cpu, node, dev->numa_id);

    for (i = 0; i < 1; i++)
	ctx_set_num[i].sync_ctx_num = KAESNAPPY_CTX_SET_NUM;

    ret = wd_comp_init2_("lz77_zstd", 0, 1, &cparams);
    if (ret && ret != -WD_EEXIST) {
        WD_ERR("failed to init wd_comp_init2_ ret is :%d!\n", ret);
	ret = KAE_SNAPPY_INIT_FAIL;
	goto out_freedev;
    }
    atexit(snappy_uadk_uninit);  // 注册退出处理函数
    snappy_config.status = 1;

out_freedev:
    free(dev);
out_freebmp:
    numa_free_nodemask(cparams.bmp);

out_freectx:
    free(ctx_set_num);
    return ret;
}

int kaesnappy_init_v2(SNAPPY_CCtx* zc)
{
    int ret;
    KaeSnappyConfig *config = NULL;

    US_DEBUG("Begin init KAE-v2 snappy.");
    config = (KaeSnappyConfig*)malloc(sizeof(KaeSnappyConfig));
    if (config == NULL) {
        US_ERR("failed to alloc config!\n");
        return KAE_SNAPPY_INIT_FAIL;
    }
    memset(config, 0, sizeof(KaeSnappyConfig));
    kaesnappy_options_init(config);

    kaesnappy_lock();
    ret = kaesnappy_alg_init2();
    if (ret) {
        US_ERR("failed to kaesnappy_alg_init2!\n");
        goto free_config;
    }

    ret = kaesnappy_create_session(config, zc->kaeLevel);
    if (ret) {
        US_ERR("failed to init session!\n");
        goto free_config;
    }
    kaesnappy_unlock();

    kaesnappy_set_config(zc, config);

    __atomic_fetch_add(&snappy_config.count, 1, __ATOMIC_SEQ_CST);
    return ret;

free_config:
    free(config);
    kaesnappy_unlock();
    return KAE_SNAPPY_INIT_FAIL;
}

void kaesnappy_release_v2(SNAPPY_CCtx* zc)
{
    KaeSnappyConfig *config = NULL;
    if (zc == NULL) {
        return;
    }

    config = kaesnappy_get_config(zc);
    wd_comp_free_sess(config->sess);
    free(config->req.dst);
    free(config);
    return;
}
