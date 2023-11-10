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

enum zstd_init_status {
	KAE_ZSTD_UNINIT,
	KAE_ZSTD_INIT,
};

struct kz_zstdwrapper_config {
	int count;
	int status;
};

static struct kz_zstdwrapper_config zstd_config = {0};
static pthread_mutex_t kz_zstd_mutex = PTHREAD_MUTEX_INITIALIZER;

int kaezstd_lock() {
   return pthread_mutex_lock(&kz_zstd_mutex);
}

int kaezstd_unlock() {
   return pthread_mutex_unlock(&kz_zstd_mutex);
} 
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
// level 8\9 win 0-4
static void Compression_level_conversion(int reqlevel, int* kae_lev, int* kae_win)
{
    if (reqlevel >= 0 && reqlevel <=3) {
        * kae_lev = 8;
        * kae_win = 0;
        return;
    } else if (reqlevel >= 4 && reqlevel<=5) {
        * kae_lev = 8;
        * kae_win = 1;
        return;
    } else if (reqlevel >= 6 && reqlevel<=7) {
        * kae_lev = 8;
        * kae_win = 2;
        return;
    } else if (reqlevel >= 8 && reqlevel<=9) {
        * kae_lev = 8;
        * kae_win = 3;
        return;
    } else if (reqlevel >= 10 && reqlevel<=11) {
        * kae_lev = 8;
        * kae_win = 4;
        return;
    } else if (reqlevel >= 12 && reqlevel<=13) {
        * kae_lev = 9;
        * kae_win = 0;
        return;
    } else if (reqlevel >= 14 && reqlevel<=15) {
        * kae_lev = 9;
        * kae_win = 1;
        return;
    } else if (reqlevel >= 16 && reqlevel<=17) {
        * kae_lev = 9;
        * kae_win = 2;
        return;
    } else if (reqlevel >= 18 && reqlevel<=19) {
        * kae_lev = 9;
        * kae_win = 3;
        return;
    } else {
        * kae_lev = 9;
        * kae_win = 4;
        return;
    }
}

int kaezstd_get_level_by_env()
{
    char *zstd_str = getenv("KAE_ZSTD_LEVEL");
    if (zstd_str == NULL) {
        US_DEBUG("KAE_ZSTD_LEVEL is NULL\n");
        return 1;
    }
    int zstd_val = atoi(zstd_str);
    if (zstd_val < 1 || zstd_val > 22) {
        US_DEBUG("KAE_ZSTD_LEVEL value out of range ：%d ", zstd_val);
        return 1;
    }
    US_DEBUG("KAE_ZSTD_LEVEL value is ：%d ", zstd_val);
    return zstd_val;
}

int kaezstd_create_session(KaeZstdConfig *config)
{
    struct sched_params param = {0};
    int kaeLev, kaeWin, reqlevel;
    reqlevel = kaezstd_get_level_by_env();
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
        return KAE_ZSTD_ALLOC_FAIL;
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

static void zstd_uadk_uninit(void)
{
    return wd_comp_uninit2();
}

# define KAEZSTD_CTX_SET_NUM 1
static int kaezstd_alg_init2(void)
{
    struct wd_ctx_nums *ctx_set_num;
	struct wd_ctx_params cparams;
	int ret, i;
    
    if (zstd_config.status == 1) {
        // 进程已经初始化过，直接返回
        return 0;
    }
    kaezstd_lock();
	ctx_set_num = calloc(KAEZSTD_CTX_SET_NUM, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		WD_ERR("failed to alloc ctx_set_size!\n");
        kaezstd_unlock();
		return KAE_ZSTD_ALLOC_FAIL;
	}

	cparams.op_type_num = KAEZSTD_CTX_SET_NUM;
	cparams.ctx_set_num = ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		WD_ERR("failed to create nodemask!\n");
		ret = KAE_ZSTD_INIT_FAIL;
		goto out_freectx;
	}

    int cpu = sched_getcpu();
    int node = numa_node_of_cpu(cpu);

    struct uacce_dev *dev = wd_get_accel_dev("lz77_zstd");//获取支持某种算法的最亲和的设备
    if (dev == NULL) {
        ret = KAE_ZSTD_INIT_FAIL;
        goto out_freebmp;
    }
    numa_bitmask_setbit(cparams.bmp, dev->numa_id); 
    US_DEBUG("cpu is %d, numa_niode_of_cpu is %d, dev-numaid is %d\n", cpu, node, dev->numa_id);

	for (i = 0; i < 1; i++)
		ctx_set_num[i].sync_ctx_num = KAEZSTD_CTX_SET_NUM;

	ret = wd_comp_init2_("lz77_zstd", 0, 1, &cparams);
	if (ret && ret != -WD_EEXIST) {
        WD_ERR("failed to init wd_comp_init2_ ret is :%d!\n", ret);
		ret = KAE_ZSTD_INIT_FAIL;
		goto out_freebmp;
	}
    atexit(zstd_uadk_uninit);  // 注册退出处理函数
    zstd_config.status = 1;
    
out_freebmp:
	numa_free_nodemask(cparams.bmp);

out_freectx:
	free(ctx_set_num);
    free(dev);
    kaezstd_unlock();
	return ret;
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
    memset(config, 0, sizeof(KaeZstdConfig));
    kaezstd_options_init(config);

    ret = kaezstd_alg_init2();
    if (ret) {
        US_ERR("failed to kaezstd_alg_init2!\n");
        goto free_config;
    }

    ret = kaezstd_create_session(config);
    if (ret) {
        US_ERR("failed to init session!\n");
        goto free_config;
    }

    kaezstd_set_config(zc, config);

    __atomic_fetch_add(&zstd_config.count, 1, __ATOMIC_SEQ_CST);
    return ret;

free_config:
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
    wd_comp_free_sess(config->sess);
    free(config->req.dst);
    free(config);
    kaezstd_debug_close_log();


    return;
}
