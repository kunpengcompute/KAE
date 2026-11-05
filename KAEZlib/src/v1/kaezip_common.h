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

#ifndef KAEZIP_COMMON_H
#define KAEZIP_COMMON_H
#include "kaezip_ctx.h"

#define KAEZIP_STREAM_CHUNK_IN         ((COMP_BLOCK_SIZE) >> 3)  // change the input size would change the performace
#define KAEZIP_STREAM_CHUNK_OUT        (COMP_BLOCK_SIZE)

#define WCRYPTO_NONE            (-1)
#define WCRYPTO_RAW_DEFLATE     2
#define KAEZIP_FMT_HEADER_ERROR (-1)
#define KAEZIP_FMT_HEADER_INCOMPLETE 0
#define KAEZIP_FMT_HEADER_DONE 1

int kz_get_devices(void);
int kaezip_winbits2algtype(int windowBits);

const uint32_t kaezip_fmt_header_sz(int comp_alg_type, int comp_optype, const void* src);
int            kaezip_parse_fmt_header(kaezip_ctx_t *kz_ctx, uint32_t *skip_len);
const char*    kaezip_get_fmt_header(int comp_alg_type, int level, int windowBits);
char*          kaezip_get_fmt_header_zlib(int level, int windowBits);
void           kaezip_set_fmt_tail(kaezip_ctx_t *kz_ctx);
void           kaezip_deflate_addcrc(kaezip_ctx_t *kz_ctx);
#endif
