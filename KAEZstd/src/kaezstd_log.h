/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae log
 * Author: liuyang
 * Create: 2023-5-30
 */

#ifndef KAEZSTD_LOG_H
#define KAEZSTD_LOG_H
#include <sys/file.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#define KAEZSTD_DEBUG_FILE_PATH   "/var/log/kaezstd.log"
#define KAEZSTD_DEBUG_FILE_PATH_OLD "/var/log/kaezstd.log.old"
#define KAE_LOG_MAX_SIZE 209715200

extern FILE *g_kaezstd_debug_log_file;
extern pthread_mutex_t g_kaezstd_debug_file_mutex;
extern const char *g_kaezstd_log_level_string[];
extern int g_kaezstd_log_level;

enum KAE_LOG_LEVEL {
    KAE_NONE = 0,
    KAE_ERROR,
    KAE_WARNING,
    KAE_INFO,
    KAE_DEBUG,
};

void ENGINE_LOG_LIMIT(int level, int times, int limit, const char *fmt, ...);

#define KAEZSTD_CRYPTO(LEVEL, fmt, args...)                                                                     \
    do {                                                                                                \
        if (LEVEL > g_kaezstd_log_level) {                                                                  \
            break;                                                                                      \
        }                                                                                               \
        struct tm *log_tm_p = NULL;                                                                     \
        time_t timep = time((time_t *)NULL);                                                            \
        log_tm_p = localtime(&timep);                                                                   \
        flock(g_kaezstd_debug_log_file->_fileno, LOCK_EX);                                                  \
        pthread_mutex_lock(&g_kaezstd_debug_file_mutex);                                                        \
        fseek(g_kaezstd_debug_log_file, 0, SEEK_END);                                                       \
        if (log_tm_p != NULL) {                                                                         \
            fprintf(g_kaezstd_debug_log_file, "[%4d-%02d-%02d %02d:%02d:%02d][%s][%s:%d:%s()] " fmt "\n",   \
                (1900 + log_tm_p->tm_year), (1 + log_tm_p->tm_mon), log_tm_p->tm_mday,                  \
                log_tm_p->tm_hour, log_tm_p->tm_min, log_tm_p->tm_sec,                                  \
                g_kaezstd_log_level_string[LEVEL], __FILE__, __LINE__, __func__, ##args);                              \
        } else {                                                                                        \
            fprintf(g_kaezstd_debug_log_file, "[%s][%s:%d:%s()] " fmt "\n",                                 \
                g_kaezstd_log_level_string[LEVEL], __FILE__, __LINE__, __func__, ##args);                              \
        }                                                                                               \
        if (ftell(g_kaezstd_debug_log_file) > KAE_LOG_MAX_SIZE) {                                           \
            kaezstd_save_log(g_kaezstd_debug_log_file);                                                         \
            if(ftruncate(g_kaezstd_debug_log_file->_fileno, 0));                                                \
            fseek(g_kaezstd_debug_log_file, 0, SEEK_SET);                                                   \
        }                                                                                               \
            pthread_mutex_unlock(&g_kaezstd_debug_file_mutex);                                                  \
            flock(g_kaezstd_debug_log_file->_fileno, LOCK_UN);                                              \
    } while (0)

#define US_ERR(fmt, args...)          KAEZSTD_CRYPTO(KAE_ERROR, fmt, ##args)
#define US_WARN(fmt, args...)         KAEZSTD_CRYPTO(KAE_WARNING, fmt, ##args)
#define US_INFO(fmt, args...)         KAEZSTD_CRYPTO(KAE_INFO, fmt, ##args)
#define US_DEBUG(fmt, args...)        KAEZSTD_CRYPTO(KAE_DEBUG, fmt, ##args)

void kaezstd_debug_init_log();
void kaezstd_debug_close_log();
void kaezstd_save_log(FILE *src);

#endif
