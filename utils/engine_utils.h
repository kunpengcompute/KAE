/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the interface for utils module
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KAE_ACC_ENGINE_UTILS_H
#define KAE_ACC_ENGINE_UTILS_H
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/syscall.h>

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

enum KAE_Q_INIT_FLAG {
    NOT_INIT = 0,
    INITED,
};

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

static inline void *kae_malloc(unsigned int size)
{
    return malloc(size);
}

static inline void *kae_realloc(void *mem_address, unsigned int newsize)
{
    return realloc(mem_address, newsize);
}

static inline void *kae_calloc(unsigned int num, unsigned int size)
{
    return calloc(num, size);
}

static inline int kae_strcmp(const char *src, const char *dst)
{
    return strcmp(src, dst);
}

static inline void kae_memset(void *ptr, int value, int len)
{
    (void)memset(ptr, value, len);
}

static inline void kae_memcpy(void *src, const void *dst, int len)
{
    (void)memcpy(src, dst, len);
}

static inline void kae_pthread_yield()
{
    (void)pthread_yield(); //lint !e1055
}

int kae_create_thread(pthread_t *thread_id, const pthread_attr_t *attr,
    void *(*start_func)(void *), void *p_arg);

int kae_create_thread_joinable(pthread_t *thread_id, const pthread_attr_t *attr,
    void *(*start_func)(void *), void *p_arg);

inline int kae_join_thread(pthread_t thread_id, void **retval);

#endif
