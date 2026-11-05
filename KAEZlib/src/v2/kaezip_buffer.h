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

#ifndef KAEZIP_BUFFER_H
#define KAEZIP_BUFFER_H

#define INPUT_CHUNK_V2  (1024 * 1024)
#define OUTPUT_CHUNK_V2 (INPUT_CHUNK_V2 << 3)

typedef struct kz_zlib_outbuffer {
    unsigned char *out;
    unsigned int produced;  //  how many bytes (un)compress produced
    unsigned int remained;  //  how many bytes (un)compress remained if no more avail_out space
} *outbuffer_ptr;

int  kz_outbuffer_init(z_streamp strm);
void kz_outbuffer_reset(z_streamp strm);
void kz_outbuffer_free(z_streamp strm);

#endif