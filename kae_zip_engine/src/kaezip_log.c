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
 * @file kaezip_log.c
 *
 * This file provides the log funtion;
 *
 *****************************************************************************/

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "kaezip_log.h"
#include "kaezip_conf.h"

#define KAE_CONFIG_FILE_NAME "/kaezip.cnf"
#define MAX_LEVEL_LEN         10
#define MAX_CONFIG_LEN        512

static const char *g_kaezip_conf_env = "KAEZIP_CONF_ENV";

FILE *g_kaezip_debug_log_file = (FILE *)NULL;
pthread_mutex_t g_kaezip_debug_file_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_kaezip_debug_file_ref_count = 0;
int g_kaezip_log_init_times = 0;
int g_kaezip_log_level = 0;

const char *g_kaezip_log_level_string[] = {
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
    char *conf_path = kae_getenv(g_kaezip_conf_env);
    unsigned int i = 0;
    const char *filename = KAE_CONFIG_FILE_NAME;
    char *file_path = (char *)NULL;
    char *debuglev = (char *)NULL;
    if (conf_path == NULL || strlen(conf_path) > MAX_CONFIG_LEN) {
        goto err;
    }
    file_path = (char *)malloc(strlen(conf_path) + strlen(filename) + 1);
    debuglev = (char *)malloc(MAX_LEVEL_LEN);
    if (!file_path || !debuglev) {
        goto err;
    }
    memset(debuglev, 0, MAX_LEVEL_LEN);
    memset(file_path, 0, sizeof(conf_path) + sizeof(filename) + 1);
    strcat(file_path, conf_path);
    strcat(file_path, filename);
    int ret = kaezip_drv_get_item(file_path, "LogSection", "debug_level", debuglev);
    if (ret != 0) {
        goto err;
    }

    for (i = 0; i < sizeof(g_kaezip_log_level_string) / sizeof(g_kaezip_log_level_string[0]); i++) {
        if (strncmp(g_kaezip_log_level_string[i], debuglev, strlen(debuglev) - 1) == 0) {
            g_kaezip_log_level = i;
            free(file_path);
            free(debuglev);
            return;
        }
    }

err:
    g_kaezip_log_level = KAE_NONE;
    if (debuglev != NULL) {
        free(debuglev);
        debuglev = (char *)NULL;
    }
    if (file_path != NULL) {
        free(file_path);
        file_path = (char *)NULL;
    }

    return;
}

void kaezip_debug_init_log()
{
    pthread_mutex_lock(&g_kaezip_debug_file_mutex);
    kae_set_conf_debuglevel();
    if (!g_kaezip_debug_file_ref_count && g_kaezip_log_level != KAE_NONE) {
        g_kaezip_debug_log_file = fopen(KAEZIP_DEBUG_FILE_PATH, "a+");
        if (g_kaezip_debug_log_file == NULL) {
            g_kaezip_debug_log_file = stderr;
            fprintf(stderr, "unable to open %s, %s\n", KAEZIP_DEBUG_FILE_PATH, strerror(errno));
        } else {
            g_kaezip_debug_file_ref_count++;
        }
    }
    g_kaezip_log_init_times++;
    pthread_mutex_unlock(&g_kaezip_debug_file_mutex);
}

void kaezip_debug_close_log()
{
    pthread_mutex_lock(&g_kaezip_debug_file_mutex);
    g_kaezip_log_init_times--;
    if (g_kaezip_debug_file_ref_count && (g_kaezip_log_init_times == 0)) {
        if (g_kaezip_debug_log_file != NULL) {
            fclose(g_kaezip_debug_log_file);
            g_kaezip_debug_file_ref_count--;
            g_kaezip_debug_log_file = stderr;
        }
    }
    pthread_mutex_unlock(&g_kaezip_debug_file_mutex);
}

void kaezip_save_log(FILE *src)
{
    int size = 0;
    char buf[1024] = {0}; // buf length:1024

    if (src == NULL) {
        return;
    }

    FILE *dst = fopen(KAEZIP_DEBUG_FILE_PATH_OLD, "w");
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
