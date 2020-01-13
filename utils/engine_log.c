/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the implemenation for log module
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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "engine_log.h"
#include "engine_config.h"
#include "engine_utils.h"

#define KAE_CONFIG_FILE_NAME "/kae.cnf"
#define MAX_LEVEL_LEN         10
#define MAX_CONFIG_LEN        512

static const char *g_kae_conf_env = "KAE_CONF_ENV";

FILE *g_kae_debug_log_file = (FILE *)NULL;
pthread_mutex_t g_debug_file_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_debug_file_ref_count = 0;
int g_log_init_times = 0;
int g_kae_log_level = 0;

const char *g_log_level[] = {
    "none",
    "error",
    "warning",
    "info",
    "debug",
};

static char *kae_getenv(const char *name)
{
    return getenv(name);
}

static void kae_set_conf_debuglevel()
{
    char *conf_path = kae_getenv(g_kae_conf_env);
    unsigned int i = 0;
    const char *filename = KAE_CONFIG_FILE_NAME;
    char *file_path = (char *)NULL;
    char *debuglev = (char *)NULL;
    if (conf_path == NULL || strlen(conf_path) > MAX_CONFIG_LEN) {
        goto err;
    }
    file_path = (char *)kae_malloc(strlen(conf_path) + strlen(filename) + 1);
    debuglev = (char *)kae_malloc(MAX_LEVEL_LEN);
    if (!file_path || !debuglev) {
        goto err;
    }
    memset(debuglev, 0, MAX_LEVEL_LEN);
    memset(file_path, 0, sizeof(conf_path) + sizeof(filename) + 1);
    strcat(file_path, conf_path);
    strcat(file_path, filename);
    int ret = kae_drv_get_item(file_path, "LogSection", "debug_level", debuglev);
    if (ret != 0) {
        goto err;
    }

    for (i = 0; i < sizeof(g_log_level) / sizeof(g_log_level[0]); i++) {
        if (strncmp(g_log_level[i], debuglev, strlen(debuglev) - 1) == 0) {
            g_kae_log_level = i;
            kae_free(file_path);
            kae_free(debuglev);
            return;
        }
    }

err:
    g_kae_log_level = KAE_ERROR;
    if (debuglev != NULL) {
        kae_free(debuglev);
        debuglev = (char *)NULL;
    }
    if (file_path != NULL) {
        kae_free(file_path);
        file_path = (char *)NULL;
    }

    return;
}

void kae_debug_init_log()
{
    pthread_mutex_lock(&g_debug_file_mutex);
    kae_set_conf_debuglevel();
    if (!g_debug_file_ref_count && g_kae_log_level != KAE_NONE) {
        g_kae_debug_log_file = fopen(KAE_DEBUG_FILE_PATH, "a+");
        if (g_kae_debug_log_file == NULL) {
            g_kae_debug_log_file = stderr;
            US_WARN("unable to open %s", KAE_DEBUG_FILE_PATH);
        } else {
            g_debug_file_ref_count++;
        }
    }
    g_log_init_times++;
    pthread_mutex_unlock(&g_debug_file_mutex);
}

void kae_debug_close_log()
{
    pthread_mutex_lock(&g_debug_file_mutex);
    g_log_init_times--;
    if (g_debug_file_ref_count && (g_log_init_times == 0)) {
        if (g_kae_debug_log_file != NULL) {
            fclose(g_kae_debug_log_file);
            g_debug_file_ref_count--;
            g_kae_debug_log_file = stderr;
        }
    }
    pthread_mutex_unlock(&g_debug_file_mutex);
}

void ENGINE_LOG_LIMIT(int level, int times, int limit, const char *fmt, ...)
{
    struct tm *log_tm_p = (struct tm *)NULL;
    static unsigned long ulpre = 0;
    static int is_should_print = 5;

    if (level > g_kae_log_level) {
        return;
    }
    // cppcheck-suppress *
    va_list args1 = { 0 };
    va_start(args1, fmt);
    time_t curr = time((time_t *)NULL);
    if (difftime(curr, ulpre) > limit) {
        is_should_print = times;
    }
    if (is_should_print <= 0) {
        is_should_print = 0;
    }
    if (is_should_print-- > 0) {
        log_tm_p = (struct tm *)localtime(&curr);
        flock(g_kae_debug_log_file->_fileno, LOCK_EX);
        pthread_mutex_lock(&g_debug_file_mutex);
        fseek(g_kae_debug_log_file, 0, SEEK_END);
        if (log_tm_p != NULL) {
            fprintf(g_kae_debug_log_file, "[%4d-%02d-%02d %02d:%02d:%02d][%s][%s:%d:%s()] ",
                    (1900 + log_tm_p->tm_year), (1 + log_tm_p->tm_mon), log_tm_p->tm_mday,   // base time 1900 year
                    log_tm_p->tm_hour, log_tm_p->tm_min, log_tm_p->tm_sec,
                    g_log_level[level], __FILE__, __LINE__, __func__);
        } else {
            fprintf(g_kae_debug_log_file, "[%s][%s:%d:%s()] ",
                    g_log_level[level], __FILE__, __LINE__, __func__);
        }
        vfprintf(g_kae_debug_log_file, fmt, args1);
        fprintf(g_kae_debug_log_file, "\n");
        if (ftell(g_kae_debug_log_file) > KAE_LOG_MAX_SIZE) {
            kae_save_log(g_kae_debug_log_file);
            ftruncate(g_kae_debug_log_file->_fileno, 0);
            fseek(g_kae_debug_log_file, 0, SEEK_SET);
        }
        pthread_mutex_unlock(&g_debug_file_mutex);
        flock(g_kae_debug_log_file->_fileno, LOCK_UN);
        ulpre = time((time_t *)NULL);
    }

    va_end(args1);
}

static int need_debug(void)
{
    if (g_kae_log_level >= KAE_DEBUG) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * desc: print data for debug
 * @param name the name of buf
 * @param buf  the buf msg when input
 * @param len bd len
 */
void dump_data(const char *name, unsigned char *buf, unsigned int len)
{
    unsigned int i;

    if (need_debug()) {
        US_DEBUG("DUMP ==> %s", name);
        for (i = 0; i + 8 <= len; i += 8) { // buf length:8
            US_DEBUG("0x%llx: \t%02x %02x %02x %02x %02x %02x %02x %02x",
                     (unsigned long long)(buf + i),
                     *(buf + i), (*(buf + i + 1)), *(buf + i + 2), *(buf + i + 3), // buf offset:0,1,2,3
                     *(buf + i + 4), *(buf + i + 5), *(buf + i + 6), *(buf + i + 7)); // buf offset:4,5,6,7
        }

        if (len % 8) { // remainder:divide by 8
            US_DEBUG ("0x%llx: \t", (unsigned long long)(buf + i));
            for (; i < len; i++) {
                US_DEBUG("%02x ", buf[i]);
            }
        }
    }
}

/*
 * desc: print bd for debug
 * @param bd  the buf msg when input
 * @param len bd len
 */
void dump_bd(unsigned int *bd, unsigned int len)
{
    unsigned int i;

    if (need_debug()) {
        for (i = 0; i < len; i++) {
            US_DEBUG("Word[%d] 0x%08x", i, bd[i]);
        }
    }
}

void kae_save_log(FILE *src)
{
    int size = 0;
    char buf[1024] = {0}; // buf length:1024

    if (src == NULL) {
        return;
    }

    FILE *dst = fopen(KAE_DEBUG_FILE_PATH_OLD, "w");
    if (dst == NULL) {
        return;
    }

    fseek(src, 0, SEEK_SET);
    while (1) {
        size = fread(buf, sizeof(char), 1024, src); // buf length:1024
        fwrite(buf, sizeof(char), size, dst);
        if (!size) {
            break;
        }
    }

    fclose(dst);
}

