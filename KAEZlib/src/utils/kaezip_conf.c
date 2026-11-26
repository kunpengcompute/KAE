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

#include "kaezip_conf.h"
#include "kaezip.h"

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

/*
 * Copy the value part of a "key = value;..." configuration line into
 * v_pszValue. value_len is the total size of the destination buffer and the
 * copy is truncated to value_len - 1 characters so that the result is always
 * NUL terminated.
 */
void kaezip_drv_get_value(char *pos, char *v_pszValue, size_t value_len)
{
    size_t i = 0;

    if (pos == NULL || v_pszValue == NULL || value_len == 0) {
        return;
    }

    while ((*pos != '\0') && (*pos != ';')) {
        if (*pos == ' ') {
            pos++;
            continue;
        }

        if (i >= (value_len - 1)) {
            break;
        }

        v_pszValue[i++] = *(pos++);
    }

    v_pszValue[i] = '\0';
}

int kaezip_drv_find_item(FILE *stream, const char *v_pszItem, char *v_pszValue, size_t value_len)
{
    char line[256]; // array length:256
    char *pos = NULL;

    if (stream == NULL || v_pszItem == NULL || v_pszValue == NULL || value_len == 0) {
        return -1;
    }

    while (!feof(stream)) {
        if (fgets(line, sizeof(line), stream) == NULL) {
            return -1;
        }

        if (strstr(line, v_pszItem) != NULL) {
            pos = strstr(line, "=");
            if (pos != NULL) {
                pos++;
                kaezip_drv_get_value(pos, v_pszValue, value_len);
                return 0;
            }
        }

        if ('[' == line[0]) {
            break;
        }
    }

    return -1;
}

int kaezip_drv_get_item(const char *config_file, const char *v_pszSection, const char *v_pszItem,
                        char *v_pszValue, size_t value_len)
{
    FILE *stream;
    int retvalue = -1;

    if (config_file == NULL || v_pszSection == NULL || v_pszItem == NULL ||
        v_pszValue == NULL || value_len == 0) {
        return -1;
    }

    stream = fopen(config_file, "r");
    if (stream == NULL) {
        return -1;
    }

    if (kaezip_drv_findsection(stream, v_pszSection) == 0) {
        retvalue = kaezip_drv_find_item(stream, v_pszItem, v_pszValue, value_len);
    }

    fclose(stream);

    return retvalue;
}

static inline void versionCpy(char s1[], const char s2[])
{
    int i = 0;
    while (i < VERSION_STRUCT_MAXLEN && (s1[i] = s2[i])) {
        ++i;
    }
    s1[i] = '\0';
}

int kaezlib_get_version(KAEZlibVersion *ver)
{
    if (ver == NULL) {
        return 1;
    }
    versionCpy(ver->productName, "Kunpeng Boostkit");
    versionCpy(ver->productVersion, "26.1.0");
    versionCpy(ver->componentName, "KAEZlib");
    versionCpy(ver->componentVersion, "2.2.0");
    return 0;
}
