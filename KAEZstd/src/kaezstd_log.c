/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: contain kae log
 * Author: liuyang
 * Create: 2023-5-30
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "kaezstd_log.h"

#define KAE_CONFIG_FILE_NAME "/kaezstd.cnf"
#define MAX_LEVEL_LEN         10
#define MAX_CONFIG_LEN        512

static const char *g_kaezstd_conf_env = "KAEZSTD_CONF_ENV";

FILE *g_kaezstd_debug_log_file = (FILE *)NULL;
pthread_mutex_t g_kaezstd_debug_file_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_kaezstd_debug_file_ref_count = 0;
int g_kaezstd_log_init_times = 0;
int g_kaezstd_log_level = 0;

const char *g_kaezstd_log_level_string[] = {
    "none",
    "error",
    "warning",
    "info",
    "debug",
};

int kaezstd_drv_findsection(FILE *stream, const char *v_pszSection)
{
    char line[256]; // array length:256
    char *pos = NULL;
    size_t section_len = strlen(v_pszSection);

    while (!feof(stream)) {
        if (fgets(line, sizeof(line), stream) == NULL) {
            return -1;
        }

        pos = line;
        if (*(pos++) != '[') {
            continue;
        }

        if (memcmp(pos, v_pszSection, section_len) == 0) {
            pos += section_len;
            if (*pos == ']') {
                return 0;
            }
        }
    }

    return -1;
}

void kaezstd_drv_get_value(char *pos, char *v_pszValue)
{
    while (*pos != '\0') {
        if (*pos == ' ') {
            pos++;
            continue;
        }

        if (*pos == ';') {
            *(v_pszValue++) = '\0';
            return;
        }

        *(v_pszValue++) = *(pos++);
    }
}

int kaezstd_drv_find_item(FILE *stream, const char *v_pszItem, char *v_pszValue)
{
    char line[256]; // array length:256
    char *pos = NULL;

    while (!feof(stream)) {
        if (fgets(line, sizeof(line), stream) == NULL) {
            return -1;
        }

        if (strstr(line, v_pszItem) != NULL) {
            pos = strstr(line, "=");
            if (pos != NULL) {
                pos++;
                kaezstd_drv_get_value(pos, v_pszValue);
                return 0;
            }
        }

        if ('[' == line[0]) {
            break;
        }
    }

    return -1;
}

int kaezstd_drv_get_item(const char *config_file, const char *v_pszSection, 
                     const char *v_pszItem, char *v_pszValue)
{
    FILE *stream;
    int retvalue = -1;

    stream = fopen(config_file, "r");
    if (stream == NULL) {
        return -1;
    }

    if (kaezstd_drv_findsection(stream, v_pszSection) == 0) {
        retvalue = kaezstd_drv_find_item(stream, v_pszItem, v_pszValue);
    }

    fclose(stream);

    return retvalue;
}

static char *kae_getenv(const char *name)
{
    return getenv(name);
}

static void kae_set_conf_debuglevel()
{
    char *conf_path = kae_getenv(g_kaezstd_conf_env);
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
    memset(file_path, 0, strlen(conf_path) + strlen(filename) + 1);
    strcat(file_path, conf_path);
    strcat(file_path, filename);
    int ret = kaezstd_drv_get_item(file_path, "LogSection", "debug_level", debuglev);
    if (ret != 0) {
        goto err;
    }

    for (i = 0; i < sizeof(g_kaezstd_log_level_string) / sizeof(g_kaezstd_log_level_string[0]); i++) {
        if (strncmp(g_kaezstd_log_level_string[i], debuglev, strlen(debuglev) - 1) == 0) {
            g_kaezstd_log_level = i;
            free(file_path);
            free(debuglev);
            return;
        }
    }

err:
    g_kaezstd_log_level = KAE_NONE;
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

void kaezstd_debug_init_log()
{
    pthread_mutex_lock(&g_kaezstd_debug_file_mutex);
    kae_set_conf_debuglevel();
    if (!g_kaezstd_debug_file_ref_count && g_kaezstd_log_level != KAE_NONE) {
        g_kaezstd_debug_log_file = fopen(KAEZSTD_DEBUG_FILE_PATH, "a+");
        if (g_kaezstd_debug_log_file == NULL) {
            g_kaezstd_debug_log_file = stderr;
            fprintf(stderr, "unable to open %s, %s\n", KAEZSTD_DEBUG_FILE_PATH, strerror(errno));
        } else {
            g_kaezstd_debug_file_ref_count++;
        }
    }
    g_kaezstd_log_init_times++;
    pthread_mutex_unlock(&g_kaezstd_debug_file_mutex);
}

void kaezstd_debug_close_log()
{
    pthread_mutex_lock(&g_kaezstd_debug_file_mutex);
    g_kaezstd_log_init_times--;
    if (g_kaezstd_debug_file_ref_count && (g_kaezstd_log_init_times == 0)) {
        if (g_kaezstd_debug_log_file != NULL) {
            fclose(g_kaezstd_debug_log_file);
            g_kaezstd_debug_file_ref_count--;
            g_kaezstd_debug_log_file = stderr;
        }
    }
    pthread_mutex_unlock(&g_kaezstd_debug_file_mutex);
}

void kaezstd_save_log(FILE *src)
{
    int size = 0;
    char buf[1024] = {0}; // buf length:1024

    if (src == NULL) {
        return;
    }

    FILE *dst = fopen(KAEZSTD_DEBUG_FILE_PATH_OLD, "w");
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
