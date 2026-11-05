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

#ifndef KAEZIP_INIT_H
#define KAEZIP_INIT_H

int kz_deflate_init(z_streamp strm, int level, int windowbits);
int kz_deflate_reset(z_streamp strm);
int kz_deflate_end(z_streamp strm);

int kz_inflate_init(z_streamp strm, int windowbits);
int kz_inflate_reset(z_streamp strm);
int kz_inflate_end(z_streamp strm);

#endif