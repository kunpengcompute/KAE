/*
 * Copyright (C) 2025. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:    This file provides the implementation for KAE engine rsa
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

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/crypto.h>

#include <openssl/rsa.h>
#include <openssl/base.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <ctype.h>
#include <signal.h>

#include "kae_bssl.h"
#include "bssl_custom.h"
#include "alg/bssl_rsa.h"
#include "../utils/engine_log.h"
#include "../v1/alg/pkey/hpre_rsa.h"
#include "../v1/alg/pkey/hpre_wd.h"

ENGINE *kae_bssl_engine = NULL;
static int uadk_rsa_nosva;
bool free_flag = false;

void exit_handle(void);

void *bssl_openssl_malloc(size_t size)
{
    void *addr = NULL;
    if ((addr = OPENSSL_malloc(size)) != NULL)
        memset(addr, 0, size);
    return addr;
}

void bind_fn_kae_bssl_alg(ENGINE *e)
{
    int dev_num;
    dev_num = wd_get_nosva_dev_num("rsa");
    if (dev_num > 0) {
        hpre_module_init();
        if (!ENGINE_set_RSA_method(e, hpre_get_rsa_methods(), sizeof(RSA_METHOD))) {
            fprintf(stderr, "uadk bind rsa failed\n");
        } else {
            uadk_rsa_nosva = 1;
            US_DEBUG("ENGINE_set_RSA successed (bind v1 rsa)");
        }
    } else if (dev_num == 0) {
        US_DEBUG("bssl rsa queue run out, switch to soft");
    } else {
        US_DEBUG("bssl rsa wd_get_nosva_dev_num faild, no availiable dev, switch to soft");
    }
}

void kae_free_func()
{
    hpre_destroy();
    wd_hpre_uninit_qnode_pool();
    ENGINE_free(kae_bssl_engine);
    kae_bssl_engine = NULL;
    US_DEBUG("kae bssl free success.");
    kae_debug_close_log();
}

void exit_handle(void)
{
    US_DEBUG("kae bssl free by exit handle.");
    kae_free_func();
}

ENGINE *ENGINE_init_kae()
{
    if (kae_bssl_engine != NULL) {
        return kae_bssl_engine;
    }
    kae_debug_init_log();
    kae_bssl_engine = ENGINE_new();
    if (kae_bssl_engine == NULL) {
        US_ERR("kae bssl engine init failed.");
        return NULL;
    }
    bind_fn_kae_bssl_alg(kae_bssl_engine);
    hpre_bssl_set_wd_init_flag();
    
    US_DEBUG("kae bssl init success.");
    return kae_bssl_engine;
}

void ENGINE_free_kae()
{
    wd_hpre_uninit_qnode_pool();
    hpre_bssl_unset_wd_init_flag();

    if (free_flag) {
        return;
    }
    atexit(exit_handle);
    free_flag = true;
    US_DEBUG("kae bssl manual free.");
}