/*
 * Copyright (C) 2019. Huawei Technologies Co., Ltd. All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the zlib License. 
 * You may obtain a copy of the License at
 * 
 *     https://www.zlib.net/zlib_license.html
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * zlib License for more details.
 */

/*****************************************************************************
 * @file kaezip_cnf.h
 *
 * This file provides configure funtion;
 *
 *****************************************************************************/

#ifndef KAEZIP_CONFIG_H
#define KAEZIP_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int kaezip_drv_get_item(const char *config_file, const char *v_pszSection, 
                     const char *v_pszItem, char *v_pszValue);

#endif  // HISI_ACC_OPENSSL_CONFIG_H
