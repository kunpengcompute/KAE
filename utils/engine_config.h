/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides interface of configuration file reading for the KAE engine
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

#ifndef HISI_ACC_OPENSSL_CONFIG_H
#define HISI_ACC_OPENSSL_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int kae_drv_get_item(const char *config_file, const char *v_pszSection, 
                     const char *v_pszItem, char *v_pszValue);

#endif  // HISI_ACC_OPENSSL_CONFIG_H
