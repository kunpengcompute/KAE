/*
 * @Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @Description: kaesnappy init and utils
 * @Author: LiuYongYang
 * @Date: 2024-02-23
 * @LastEditTime: 2024-02-23
 */

/*****************************************************************************
 * @file kaesnappy_utils.h
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
#include <unistd.h>

#define gettid() syscall(SYS_gettid)
#define PRINTPID \
    US_DEBUG("pid=%d, ptid=%lu, tid=%d", getpid(), pthread_self(), gettid())

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifndef true
#define true (0 == 0)
#endif

#ifndef false
#define false (0 == 1)
#endif

#define KAEZIP_FAILED           (-1)
#define KAEZIP_SUCCESS          (0)

#define COMP_BLOCK_NUM              (4)
#define COMP_BLOCK_SIZE             (2 * 1024 * 1024)
#define KAEZIP_STREAM_CHUNK_IN         ((COMP_BLOCK_SIZE) >> 3)  // change the input size would change the performace
#define KAEZIP_STREAM_CHUNK_OUT        (COMP_BLOCK_SIZE)

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

#define NSEC_TO_SEC 1000000000L
static inline void get_time_out_spec(struct timespec *start, struct timespec *polling_timeout)
{
    clock_gettime(CLOCK_REALTIME, start); /* Get current real time. */
    start->tv_sec += polling_timeout->tv_sec;
    start->tv_nsec += polling_timeout->tv_nsec;
    start->tv_sec += start->tv_nsec / NSEC_TO_SEC;
    start->tv_nsec = start->tv_nsec % NSEC_TO_SEC;
}

static inline int check_time_out(struct timespec *time)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now); /* Get current real time. */

    if ((now.tv_sec < time->tv_sec) || (now.tv_sec == time->tv_sec && now.tv_nsec <= time->tv_nsec)) {
        return 0;
    }

    return 1;
}

#endif
