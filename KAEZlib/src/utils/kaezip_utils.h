/*
 * Copyright (C) 2019. Huawei Technologies Co., Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the zlib License.
 * You may obtain a copy of the License at
 *
 *     https://www.zlib.net/zlib_license.html
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * zlib License for more details.
 */

/*****************************************************************************
 * @file kaezip_utils.h
 *
 * This file provides the utils funtion;
 *
 *****************************************************************************/

#ifndef KAEZIP_UTILS_H
#define KAEZIP_UTILS_H
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "uadk/v1/wd_comp.h"

#define gettid() syscall(SYS_gettid)
#define PRINTPID \
    US_DEBUG("pid=%d, ptid=%lu, tid=%d", getpid(), pthread_self(), gettid())

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef true
#define true (0 == 0)
#endif

#ifndef false
#define false (0 == 1)
#endif

#define KAEZIP_FAILED              (-1)
#define KAEZIP_SUCCESS             (0)
#define KAEZIP_DRIVER_DO_TASK_NOW  (1)
#define KAEZIP_SAVE_DATA_TO_BUFFER (2)

#define COMP_BLOCK_NUM              (4)
#define COMP_BLOCK_SIZE             (2 * 1024 * 1024)
#define KAEZIP_STREAM_CHUNK_IN      ((COMP_BLOCK_SIZE) >> 3)  // change the input size would change the performace
#define KAEZIP_STREAM_CHUNK_OUT     (COMP_BLOCK_SIZE)

#define ASYNC_COMP_BLOCK_SIZE       (8 * 1024 * 1024)

#define KAEZIP_RETURN_FAIL_IF(cond, mesg, ret) \
        if (unlikely(cond)) {\
            US_ERR(mesg); \
            return (ret); \
        }\

#define UNUSED(x) (void)(x)

#define BLOCKSIZES_OF(data) (sizeof((data)) / sizeof(((data)[0])))

#define KAE_SPIN_INIT(q)     kae_spinlock_init(&(q))
#define KAE_SPIN_LOCK(q)     kae_spinlock_lock(&(q))
#define KAE_SPIN_TRYLOCK(q)  kae_spinlock_trylock(&(q))
#define KAE_SPIN_UNLOCK(q)   kae_spinlock_unlock(&(q))

#define kae_free(addr)      \
    do {                    \
        if (addr != NULL) { \
            free(addr);     \
            addr = NULL;    \
        }                   \
    } while (0)

typedef   uint8_t BYTE;
typedef   uint8_t U8;
typedef  uint16_t U16;
typedef  uint32_t U32;
typedef  uint64_t U64;

static inline void *kae_malloc(unsigned int size)
{
    return malloc(size);
}

struct kae_spinlock {
    int lock;
};

static inline void kae_spinlock_init(struct kae_spinlock *lock)
{
    lock->lock = 0;
}

static inline void kae_spinlock_lock(struct kae_spinlock *lock)
{
    while (__sync_lock_test_and_set(&lock->lock, 1)) {}
}

static inline int kae_spinlock_trylock(struct kae_spinlock *lock)
{
    return __sync_lock_test_and_set(&lock->lock, 1) == 0;
}

static inline void kae_spinlock_unlock(struct kae_spinlock *lock)
{
    __sync_lock_release(&lock->lock);
}

static inline int kz_zlib_analy_alg(int windowbits, int *alg, int *windowsize, int level)
{
	static const int ZLIB_MAX_WBITS = 15;
	static const int ZLIB_MIN_WBITS = 8;
	static const int GZIP_MAX_WBITS = 31;
	static const int GZIP_MIN_WBITS = 24;
	static const int DEFLATE_MAX_WBITS = -8;
	static const int DEFLATE_MIN_WBITS = -15;
	//	windowbits only for algorithm type
	if ((windowbits >= ZLIB_MIN_WBITS) && (windowbits <= ZLIB_MAX_WBITS)) {
		*alg = WCRYPTO_ZLIB;
	} else if ((windowbits >= GZIP_MIN_WBITS) && (windowbits <= GZIP_MAX_WBITS)) {
		*alg = WCRYPTO_GZIP;
	} else if ((windowbits >= DEFLATE_MIN_WBITS) && (windowbits <= DEFLATE_MAX_WBITS)) {
		*alg = WCRYPTO_RAW_DEFLATE;
	} else {
		return -3;	// Z_DATA_ERROR
	}
	//	level only for compress rate
	level = (level == -1) ? 6 : level;
	if (level <= 2) {
		*windowsize = WCRYPTO_COMP_WS_4K;
	} else if (level <= 4) {
		*windowsize = WCRYPTO_COMP_WS_8K;
	} else if (level <= 6) {
		*windowsize = WCRYPTO_COMP_WS_16K;
	} else if (level <= 8) {
		*windowsize = WCRYPTO_COMP_WS_24K;
	} else {
		*windowsize = WCRYPTO_COMP_WS_32K;
	}

	return 0;
}

#define NSEC_TO_SEC 1000000000L
static inline void get_time_out_spec(struct timespec *start, struct timespec *polling_timeout)
{
    clock_gettime(CLOCK_MONOTONIC_RAW, start); /* Get current real time. */
    start->tv_sec += polling_timeout->tv_sec;
    start->tv_nsec += polling_timeout->tv_nsec;
    start->tv_sec += start->tv_nsec / NSEC_TO_SEC;
    start->tv_nsec = start->tv_nsec % NSEC_TO_SEC;
}

static inline int check_time_out(struct timespec *time)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now); /* Get current real time. */

    if ((now.tv_sec < time->tv_sec) || (now.tv_sec == time->tv_sec && now.tv_nsec <= time->tv_nsec)) {
        return 0;
    }

    return 1;
}

#endif
