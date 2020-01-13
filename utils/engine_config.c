/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides implemenation of configuration file reading for the KAE engine
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

#include "engine_config.h"

int kae_drv_findsection(FILE *stream, const char *v_pszSection)
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

void kae_drv_get_value(char *pos, char *v_pszValue)
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

int kae_drv_find_item(FILE *stream, const char *v_pszItem, char *v_pszValue)
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
                kae_drv_get_value(pos, v_pszValue);
                return 0;
            }
        }

        if ('[' == line[0]) {
            break;
        }
    }

    return -1;
}

int kae_drv_get_item(const char *config_file, const char *v_pszSection, 
                     const char *v_pszItem, char *v_pszValue)
{
    FILE *stream;
    int retvalue = -1;

    stream = fopen(config_file, "r");
    if (stream == NULL) {
        return -1;
    }

    if (kae_drv_findsection(stream, v_pszSection) == 0) {
        retvalue = kae_drv_find_item(stream, v_pszItem, v_pszValue);
    }

    fclose(stream);

    return retvalue;
}
