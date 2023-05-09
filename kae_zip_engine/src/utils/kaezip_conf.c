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
 * @file kaezip_cnf.h
 *
 * This file provides configure funtion;
 *
 *****************************************************************************/

#include "kaezip_conf.h"

int kaezip_drv_findsection(FILE *stream, const char *v_pszSection)
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

void kaezip_drv_get_value(char *pos, char *v_pszValue)
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

int kaezip_drv_find_item(FILE *stream, const char *v_pszItem, char *v_pszValue)
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
                kaezip_drv_get_value(pos, v_pszValue);
                return 0;
            }
        }

        if ('[' == line[0]) {
            break;
        }
    }

    return -1;
}

int kaezip_drv_get_item(const char *config_file, const char *v_pszSection, 
                     const char *v_pszItem, char *v_pszValue)
{
    FILE *stream;
    int retvalue = -1;

    stream = fopen(config_file, "r");
    if (stream == NULL) {
        return -1;
    }

    if (kaezip_drv_findsection(stream, v_pszSection) == 0) {
        retvalue = kaezip_drv_find_item(stream, v_pszItem, v_pszValue);
    }

    fclose(stream);

    return retvalue;
}
