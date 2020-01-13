/*
 * Copyright (c) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the interface for an OpenSSL KAE engine
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

#ifndef ENGINE_KAE_H
#define ENGINE_KAE_H

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "engine_opensslerr.h"
#include "engine_log.h"

/* Engine id */
extern const char *g_engine_kae_id ;

int kae_get_device(const char *dev);

#endif  // !ENGINE_KAE_H

