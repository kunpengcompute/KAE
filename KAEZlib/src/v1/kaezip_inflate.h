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

#ifndef KAEZIP_INFLATE_H
#define KAEZIP_INFLATE_H

extern int kz_inflateInit2_v1(z_streamp strm, int windowBits, const char *version, int stream_size);
extern int kz_inflate_v1(z_streamp strm, int flush);
extern int kz_inflateEnd_v1(z_streamp strm);
extern int kz_inflateReset_v1(z_streamp strm);
extern int kz_do_inflateInit(z_streamp strm, int alg_comp_type);

extern int lz_inflateEnd(z_streamp strm);
extern int lz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
extern int lz_inflateReset(z_streamp strm);

extern int getInflateStateWrap(z_streamp strm);
extern unsigned long getInflateKaezipCtx(z_streamp strm);
extern void setInflateKaezipCtx(z_streamp strm, unsigned long kaezip_ctx);
#endif


