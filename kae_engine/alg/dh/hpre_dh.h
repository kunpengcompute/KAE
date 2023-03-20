/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for KAE engine DH.
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

#ifndef HPRE_DH_H
#define HPRE_DH_H

#include <openssl/dh.h>

const DH_METHOD *hpre_get_dh_methods(void);

int hpre_module_dh_init();

void hpre_dh_destroy();

EVP_PKEY_METHOD *get_dh_pkey_meth(void);

EVP_PKEY_METHOD *get_dsa_pkey_meth(void);

#endif