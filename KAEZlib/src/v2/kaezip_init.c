/* ===   Dependencies   === */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <numa.h>
#include <unistd.h>

#include "wd.h"
#include "wd_comp.h"
#include "wd_sched.h"
#include "wd_util.h"
#include "drv/wd_comp_drv.h"
#include "wd_zlibwrapper.h"
#include "kaezip_init.h"
#include "kaezip_log.h"

#define max(a, b)		((a) > (b) ? (a) : (b))

enum kz_init_status {
	WD_ZLIB_UNINIT,
	WD_ZLIB_INIT,
};

struct kz_zlibwrapper_config {
	int count;
	int status;
};

static pthread_mutex_t kz_zlib_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct kz_zlibwrapper_config zlib_config = {0};

static int kz_getzlib_device_num(void)
{
	int num = 0;
	struct uacce_dev_list* zlib_list = wd_get_accel_list("zlib");
	if (zlib_list) {
		struct uacce_dev_list* p = zlib_list;
		do {
			num++;
			p = p->next;
		} while (p);
	}
	US_INFO("zlib device num is %d\n", num);
	return num;
}

static void kz_zlib_unlock(void)
{
	pthread_mutex_unlock(&kz_zlib_mutex);
	zlib_config.status = WD_ZLIB_UNINIT;
}

static int kz_zlib_uadk_init(void)
{
	struct wd_ctx_nums *ctx_set_num;
	struct wd_ctx_params cparams;
	int ret, i;

	if (zlib_config.status == WD_ZLIB_INIT)
		return 0;

	ctx_set_num = calloc(WD_DIR_MAX, sizeof(*ctx_set_num));
	if (!ctx_set_num) {
		US_ERR("failed to alloc ctx_set_size!\n");
		return Z_MEM_ERROR;
	}

	cparams.op_type_num = WD_DIR_MAX;
	cparams.ctx_set_num = ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		US_ERR("failed to create nodemask!\n");
		ret = Z_MEM_ERROR;
		goto out_freectx;
	}

    pid_t the_pid = getpid();
	int zlib_device_num = kz_getzlib_device_num();
	if (zlib_device_num == 0) {
		US_ERR("no zlib device!\n");
		return Z_ERRNO;
	}
	numa_bitmask_setbit(cparams.bmp, the_pid % zlib_device_num);

	for (i = 0; i < WD_DIR_MAX; i++)
		ctx_set_num[i].sync_ctx_num = WD_DIR_MAX;

	ret = wd_comp_init2_("zlib", 0, 0, &cparams);
	if (ret) {
		ret = Z_STREAM_ERROR;
		goto out_freebmp;
	}

	zlib_config.status = WD_ZLIB_INIT;

out_freebmp:
	numa_free_nodemask(cparams.bmp);

out_freectx:
	free(ctx_set_num);

	return ret;
}

static void kz_zlib_uadk_uninit(void)
{
	wd_comp_uninit2();
	zlib_config.status = WD_ZLIB_UNINIT;
}

static int kz_zlib_analy_alg(int windowbits, int *alg, int *windowsize)
{
	static const int ZLIB_MAX_WBITS = 15;
	static const int ZLIB_MIN_WBITS = 8;
	static const int GZIP_MAX_WBITS = 31;
	static const int GZIP_MIN_WBITS = 24;
	static const int DEFLATE_MAX_WBITS = -8;
	static const int DEFLATE_MIN_WBITS = -15;
	static const int WBINS_ZLIB_4K = 11;
	static const int WBINS_GZIP_4K = 27;
	static const int WBINS_DEFLATE_4K = -12;

	if ((windowbits >= ZLIB_MIN_WBITS) && (windowbits <= ZLIB_MAX_WBITS)) {
		*alg = WD_ZLIB;
		*windowsize = max(windowbits - WBINS_ZLIB_4K, WD_COMP_WS_4K);
	} else if ((windowbits >= GZIP_MIN_WBITS) && (windowbits <= GZIP_MAX_WBITS)) {
		*alg = WD_GZIP;
		*windowsize = max(windowbits - WBINS_GZIP_4K, WD_COMP_WS_4K);
	} else if ((windowbits >= DEFLATE_MIN_WBITS) && (windowbits <= DEFLATE_MAX_WBITS)) {
		*alg = WD_DEFLATE;
		*windowsize = max(windowbits - WBINS_DEFLATE_4K, WD_COMP_WS_4K);
	} else {
		return Z_STREAM_ERROR;
	}

	return Z_OK;
}

static int kz_zlib_alloc_sess(z_streamp strm, int level, int windowbits, enum wd_comp_op_type type)
{
	struct wd_comp_sess_setup setup = {0};
	struct sched_params sparams = {0};
	int windowsize, alg, ret;
	handle_t h_sess;

	ret = kz_zlib_analy_alg(windowbits, &alg, &windowsize);
	if (ret < 0) {
		US_ERR("invalid: windowbits is %d!\n", windowbits);
		return ret;
	}

	setup.comp_lv = level;
	setup.alg_type = alg;
	setup.win_sz = windowsize;
	setup.op_type = type;
	sparams.type = type;
	setup.sched_param = &sparams;

	h_sess = wd_comp_alloc_sess(&setup);
	if (!h_sess) {
		US_ERR("failed to alloc comp sess!\n");
		return Z_STREAM_ERROR;
	}
	strm->reserved = (__u64)h_sess;

	return Z_OK;
}

static void kz_zlib_free_sess(z_streamp strm)
{
	wd_comp_free_sess((handle_t)strm->reserved);
}

static int kz_zlib_init(z_streamp strm, int level, int windowbits, enum wd_comp_op_type type)
{
	int ret;

	if (unlikely(!strm))
		return Z_STREAM_ERROR;

	pthread_mutex_lock(&kz_zlib_mutex);
	ret = kz_zlib_uadk_init();
	if (unlikely(ret < 0))
		goto out_unlock;

	strm->total_in = 0;
	strm->total_out = 0;

	ret = kz_zlib_alloc_sess(strm, level, windowbits, type);
	if (unlikely(ret < 0))
		goto out_uninit;

	__atomic_add_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&kz_zlib_mutex);

	return Z_OK;

out_uninit:
	kz_zlib_uadk_uninit();

out_unlock:
	pthread_mutex_unlock(&kz_zlib_mutex);

	return ret;
}

static int kz_zlib_uninit(z_streamp strm)
{
	int ret;

	if (unlikely(!strm))
		return Z_STREAM_ERROR;

	kz_zlib_free_sess(strm);

	pthread_mutex_lock(&kz_zlib_mutex);

	ret = __atomic_sub_fetch(&zlib_config.count, 1, __ATOMIC_RELAXED);
	if (ret != 0)
		goto out_unlock;

	kz_zlib_uadk_uninit();

out_unlock:
	pthread_mutex_unlock(&kz_zlib_mutex);

	return Z_OK;
}

/* ===   Compression   === */
int kz_deflate_init(z_streamp strm, int level, int windowbits)
{
	pthread_atfork(NULL, NULL, kz_zlib_unlock);
	return kz_zlib_init(strm, level, windowbits, WD_DIR_COMPRESS);
}

int kz_deflate_reset(z_streamp strm)
{
	return wd_deflate_reset(strm);
}

int kz_deflate_end(z_streamp strm)
{
	return kz_zlib_uninit(strm);
}

/* ===   Decompression   === */
int kz_inflate_init(z_streamp strm, int  windowbits)
{
	pthread_atfork(NULL, NULL, kz_zlib_unlock);
	return kz_zlib_init(strm, 0, windowbits, WD_DIR_DECOMPRESS);
}

int kz_inflate_reset(z_streamp strm)
{
	return wd_inflate_reset(strm);
}

int kz_inflate_end(z_streamp strm)
{
	return kz_zlib_uninit(strm);
}