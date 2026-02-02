/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
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

#ifndef KAESNAPPY_LOG_H
#define KAESNAPPY_LOG_H
#include <sys/file.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#define KAESNAPPY_DEBUG_FILE_PATH   "/var/log/kaesnappy.log"
#define KAESNAPPY_DEBUG_FILE_PATH_OLD "/var/log/kaesnappy.log.old"
#define KAE_LOG_MAX_SIZE 209715200

extern FILE *g_kaesnappy_debug_log_file;
extern pthread_mutex_t g_kaesnappy_debug_file_mutex;
extern const char *g_kaesnappy_log_level_string[];
extern int g_kaesnappy_log_level;
extern __thread int g_kaesnappy_threadid;

enum KAE_LOG_LEVEL {
    KAE_NONE = 0,
    KAE_ERROR,
    KAE_WARNING,
    KAE_INFO,
    KAE_DEBUG,
};

void ENGINE_LOG_LIMIT(int level, int times, int limit, const char *fmt, ...);

#define KAESNAPPY_CRYPTO(LEVEL, fmt, args...)                                                                     \
    do {                                                                                                \
        if (LEVEL > g_kaesnappy_log_level) {                                                                  \
            break;                                                                                      \
        }                                                                                               \
        struct tm *log_tm_p = NULL;                                                                     \
        time_t timep = time((time_t *)NULL);                                                            \
        log_tm_p = localtime(&timep);                                                                   \
        flock(g_kaesnappy_debug_log_file->_fileno, LOCK_EX);                                                  \
        pthread_mutex_lock(&g_kaesnappy_debug_file_mutex);                                                        \
        fseek(g_kaesnappy_debug_log_file, 0, SEEK_END);                                                       \
        if (log_tm_p != NULL) {                                                                         \
            fprintf(g_kaesnappy_debug_log_file, "[%4d-%02d-%02d %02d:%02d:%02d][%d][%s][%s:%d:%s()] " fmt "\n",   \
                (1900 + log_tm_p->tm_year), (1 + log_tm_p->tm_mon), log_tm_p->tm_mday,                  \
                log_tm_p->tm_hour, log_tm_p->tm_min, log_tm_p->tm_sec, g_kaesnappy_threadid,               \
                g_kaesnappy_log_level_string[LEVEL], __FILE__, __LINE__, __func__, ##args);                              \
        } else {                                                                                        \
            fprintf(g_kaesnappy_debug_log_file, "[%d][%s][%s:%d:%s()] " fmt "\n", g_kaesnappy_threadid,                 \
                g_kaesnappy_log_level_string[LEVEL], __FILE__, __LINE__, __func__, ##args);                              \
        }                                                                                               \
        if (ftell(g_kaesnappy_debug_log_file) > KAE_LOG_MAX_SIZE) {                                           \
            kaesnappy_save_log(g_kaesnappy_debug_log_file);                                                         \
            if(ftruncate(g_kaesnappy_debug_log_file->_fileno, 0));                                                \
            fseek(g_kaesnappy_debug_log_file, 0, SEEK_SET);                                                   \
        }                                                                                               \
            pthread_mutex_unlock(&g_kaesnappy_debug_file_mutex);                                                  \
            flock(g_kaesnappy_debug_log_file->_fileno, LOCK_UN);                                              \
    } while (0)

#define US_ERR(fmt, args...)          KAESNAPPY_CRYPTO(KAE_ERROR, fmt, ##args)
#define US_WARN(fmt, args...)         KAESNAPPY_CRYPTO(KAE_WARNING, fmt, ##args)
#define US_INFO(fmt, args...)         KAESNAPPY_CRYPTO(KAE_INFO, fmt, ##args)
#define US_DEBUG(fmt, args...)        KAESNAPPY_CRYPTO(KAE_DEBUG, fmt, ##args)

void kaesnappy_debug_init_log();
void kaesnapy_debug_close_log();
void kaesnappy_save_log(FILE *src);

#endif
