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

#ifndef KAEZIP_DEFLATE_H
#define KAEZIP_DEFLATE_H

extern int kz_deflateInit2_v1(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                      const char *version, int stream_size);
extern int kz_deflate_v1(z_streamp strm, int flush);
extern int kz_deflateEnd_v1(z_streamp strm);
extern int kz_deflateReset_v1(z_streamp strm);

extern int lz_deflateEnd(z_streamp strm);
extern int lz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                      const char *version, int stream_size);
extern int lz_deflateReset(z_streamp strm);

extern unsigned long getDeflateKaezipCtx(z_streamp strm);
extern void setDeflateKaezipCtx(z_streamp strm, unsigned long kaezip_ctx);
#endif


