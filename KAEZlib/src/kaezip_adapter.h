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

#ifndef KAEZIP_ADAPTER_H
#define KAEZIP_ADAPTER_H

/**
 * v1 interface, used for check hardware status
*/
extern int wd_get_available_dev_num(const char* alogrithm);

/**
 * adapter interface for zlib-open
 */
int kz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                const char *version, int stream_size);
int kz_deflate(z_streamp strm, int flush);
int kz_deflateEnd(z_streamp strm);
int kz_deflateReset(z_streamp strm);

int kz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
int kz_inflate(z_streamp strm, int flush);
int kz_inflateEnd(z_streamp strm);
int kz_inflateReset(z_streamp strm);

#endif
