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

#ifndef KAELZ4_INIT_H
#define KAELZ4_INIT_H

#include "kaelz4_common.h"

int  kaelz4_init_v1(LZ4_CCtx* zc, int is_sgl, operation_mode mode, const kaelz4_device_config_t *config);
void kaelz4_reset_v1(LZ4_CCtx* zc);
void kaelz4_release_v1(LZ4_CCtx* zc);

#endif