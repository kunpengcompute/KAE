/*
 * Copyright (c) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for an OpenSSL KAE engine
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <time.h>
#include <sys/types.h>
#include <dirent.h>

#include "engine_kae.h"
#include "engine_check.h"
#include "engine_fork.h"
#include "engine_utils.h"
#include "async_poll.h"
#include "sec_ciphers.h"
#include "sec_digests.h"
#include "hpre_rsa.h"
#include "hpre_dh.h"

#define KAE_CMD_ENABLE_ASYNC   ENGINE_CMD_BASE
#define KAE_CMD_ENABLE_SM3   ENGINE_CMD_BASE + 1
#define KAE_CMD_ENABLE_SM4   ENGINE_CMD_BASE + 2
#define PKEY_METHOD_TYPE_NUM   3

/* Engine id */
const char *g_engine_kae_id = "kae";
/* Engine name */
const char *g_engine_kae_name = "Kunpeng Accelerator Engine";
/* Support pkey method types */
const int g_pkey_method_types[PKEY_METHOD_TYPE_NUM] = {EVP_PKEY_RSA, EVP_PKEY_DH, EVP_PKEY_DHX};

static int g_bind_ref_count = 0;

static int hpre_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
    const int **pnids, int nid);

static const ENGINE_CMD_DEFN g_kae_cmd_defns[] = {
    {
        KAE_CMD_ENABLE_ASYNC,
        "KAE_CMD_ENABLE_ASYNC",
        "Enable or Disable the engine async interface.",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        KAE_CMD_ENABLE_SM3,
        "KAE_CMD_ENABLE_SM3",
        "Enable or Disable the SM3.",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        KAE_CMD_ENABLE_SM4,
        "KAE_CMD_ENABLE_SM4",
        "Enable or Disable the SM4.",
        ENGINE_CMD_FLAG_NUMERIC},
    {
        0, NULL, NULL, 0
    }
};

/******************************************************************************
* function:
*         kae_engine_ctrl(ENGINE *e, int cmd, long i,void *p, void (*f)(void))
*
* @param e   [IN] - OpenSSL engine pointer
* @param cmd [IN] - Control Command
* @param i   [IN] - Input Parameters for the command
* @param p   [IN] - Parameters for the command
* @param f   [IN] - Callback function
*
* description:
*   Qat engine control functions.
*   Note: KAE_CMD_ENABLE_ASYNC should be called at the following
*         point during startup:
*         ENGINE_by_id
*    ---> ENGINE_ctrl_cmd(KAE_CMD_ENABLE_ASYNC)
*         ENGINE_init
******************************************************************************/
static int kae_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ret = 1;
    (void)p;
    (void)f;

    if (unlikely(e == NULL)) {
        US_ERR("Null Enigne\n");
        return 0;
    }

    switch (cmd) {
        case KAE_CMD_ENABLE_ASYNC:
            US_DEBUG("%s async polling\n", i == 0 ? "Disable" : "Enable");
            if (i == 0) {
                kae_disable_async();
            } else {
                kae_enable_async();
            }
            break;
        case KAE_CMD_ENABLE_SM3:
            US_DEBUG("%s SM3\n", i == 0 ? "Disable" : "Enable");
            if (i == 0) {
                sec_digests_set_enabled(NID_sm3, 0);
            } else {
                sec_digests_set_enabled(NID_sm3, 1);
            }
            break;
        case KAE_CMD_ENABLE_SM4:
            US_DEBUG("%s SM4\n", i == 0 ? "Disable" : "Enable");
            if (i == 0) {
                sec_ciphers_set_enabled(NID_sm4_ctr, 0);
                sec_ciphers_set_enabled(NID_sm4_cbc, 0);
                sec_ciphers_set_enabled(NID_sm4_ofb128, 0);
                sec_ciphers_set_enabled(NID_sm4_ecb, 0);
            } else {
                sec_ciphers_set_enabled(NID_sm4_ctr, 1);
                sec_ciphers_set_enabled(NID_sm4_cbc, 1);
                sec_ciphers_set_enabled(NID_sm4_ofb128, 1);
                sec_ciphers_set_enabled(NID_sm4_ecb, 1);
            }
            break;
        default:
            US_WARN("CTRL command not implemented\n");
            ret = 0;
            break;
    }

    return ret;
}

static int kae_engine_init(ENGINE *e)
{
    UNUSED(e);
    return 1;
}

static int kae_engine_destroy(ENGINE *e)
{
    UNUSED(e);

    if (__sync_sub_and_fetch(&g_bind_ref_count, 1) <= 0) {
        hpre_destroy();
        hpre_dh_destroy();
        sec_ciphers_free_ciphers();
        sec_digests_free_methods();
        err_unload_kae_strings();
        kae_debug_close_log();

        __sync_and_and_fetch(&g_bind_ref_count, 0);
    }

    return 1;
}

static int kae_engine_finish(ENGINE *e)
{
    UNUSED(e);
    return 1;
}

static int kae_engine_setup(void)
{
    if (__sync_add_and_fetch(&g_bind_ref_count, 1) == 1) {
        kae_debug_init_log();
        /* Ensure the kae error handling is set up */
        err_load_kae_strings();

        if (!cipher_module_init()) {
            __sync_and_and_fetch(&g_bind_ref_count, 0);
            return 0;
        }

        if (!digest_module_init()) {
            __sync_and_and_fetch(&g_bind_ref_count, 0);
            return 0;
        }

        if (!hpre_module_init()) {
            __sync_and_and_fetch(&g_bind_ref_count, 0);
            return 0;
        }

        if (!hpre_module_dh_init()) {
            __sync_and_and_fetch(&g_bind_ref_count, 0);
            return 0;
        }

        if (!kae_checking_q_thread_init()) {
            __sync_and_and_fetch(&g_bind_ref_count, 0);
            return 0;
        }

        async_module_init();
        pthread_atfork(engine_do_before_fork_handler, engine_init_parent_at_fork_handler,
                       engine_init_child_at_fork_handler);
    }

    return 1;
}

int kae_get_device(const char* dev)
{
    struct dirent *device = NULL;
    DIR *wd_class = NULL;
    int found = 0;
    const char* uacce_path = "/sys/class/uacce";

    if (access(uacce_path, 0) != 0 || (dev == NULL)) {
        US_WARN("WD framework is not enabled on the system!\n");
        return 0;
    }

    wd_class = opendir(uacce_path);
    if (wd_class == NULL) {
        US_WARN("uacce_path cant be opened!\n");
        return 0;
    }

    while ((device = readdir(wd_class)) != NULL) {
        if (strstr(device->d_name, dev)) {
            found = 1;
            break;
        }
    }
    closedir(wd_class);
    
    return found == 1 ? 1 : 0;
}

static int hpre_check_meth_args(EVP_PKEY_METHOD **pmeth,
    const int **pnids, int nid)
{
    if ((pnids == NULL) && ((pmeth == NULL) || (nid < 0))) {
        KAEerr(KAE_F_HPRE_PKEY_METHS, KAE_R_INPUT_PARAM_ERR);
        US_ERR("wd_engine_digests invalid input param.");
        if (pmeth != NULL) {
            *pmeth = NULL;
        }
        return OPENSSL_FAIL;
    }
    if (pmeth == NULL && pnids != NULL) {
        *pnids = g_pkey_method_types;
        return PKEY_METHOD_TYPE_NUM;
    }
    if (pmeth == NULL) {
        return OPENSSL_FAIL;
    }

    return HPRE_CONT;
}

static int hpre_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
    const int **pnids, int nid)
{
    UNUSED(e);
    int ret = hpre_check_meth_args(pmeth, pnids, nid);
    if (ret != HPRE_CONT) {
        return ret;
    }

    switch (nid) {
        case EVP_PKEY_RSA:
            *pmeth = get_rsa_pkey_meth();
            break;
        case EVP_PKEY_DH:
            *pmeth = get_dh_pkey_meth();
            break;
        case EVP_PKEY_DHX:
            *pmeth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_DHX);
            break;
        default:
            *pmeth = NULL;
            break;
    }
    
    return (*pmeth != NULL);
}

/******************************************************************************
* function:
*         bind_helper(ENGINE *e,
*                  const char *id)
*
* @param e  [IN] - OpenSSL engine pointer
* @param id [IN] - engine id
*
* description:
*    Connect KAE engine to OpenSSL engine library
******************************************************************************/
static int bind_kae(ENGINE *e, const char *id)
{
    int ret;
    (void)id;
    const char *sec_device = "hisi_sec";
    static int loaded = 0;
    if (loaded) {
        US_ERR("ENGINE defined already!\n");
        KAEerr(KAE_F_BIND_HELPER, KAE_R_ENGINE_ALREADY_DEFINED);
        return 0;
    }
    loaded = 1;

#undef RETURN_FAIL_IF
#define RETURN_FAIL_IF(cond, mesg, f, r) \
    if (cond) { \
        KAEerr(f, r); \
        US_ERR(mesg); \
        return 0; \
    }\

    if (!kae_engine_setup()) {
        US_ERR("ENGINE setup failed\n");
        return 0;
    }

    ret = ENGINE_set_id(e, g_engine_kae_id);
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_id failed.",
        KAE_F_BIND_HELPER, KAE_R_SET_ID_FAILURE);

    ret = ENGINE_set_name(e, g_engine_kae_name);
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_name failed.",
        KAE_F_BIND_HELPER, KAE_R_SET_NAME_FAILURE);

    ret = kae_get_device(sec_device);
    if (ret != 0) {
#ifndef KAE_NO_CIPHER_METH
        ret = ENGINE_set_ciphers(e, sec_engine_ciphers);
        RETURN_FAIL_IF(ret != 1, "ENGINE_set_ciphers failed.",
            KAE_F_BIND_HELPER, KAE_R_SET_CIPHERS_FAILURE);
#endif
#ifndef KAE_NO_DIGEST_METH
        ret = ENGINE_set_digests(e, sec_engine_digests);
        RETURN_FAIL_IF(ret != 1, "ENGINE_set_digests failed.",
            KAE_F_BIND_HELPER, KAE_R_SET_DIGESTS_FAILURE);
#endif        
    }

    ret = ENGINE_set_pkey_meths(e, hpre_pkey_meths);
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_finish_function failed",
        KAE_F_BIND_HELPER, KAE_R_SET_PKEYMETH_FAILURE);
#ifndef KAE_NO_RSA_METH
    ret = ENGINE_set_RSA(e, hpre_get_rsa_methods());
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_RSA failed.",
        KAE_F_BIND_HELPER, KAE_R_SET_RSA_FAILURE);
#endif
#ifndef KAE_NO_DH_METH
    ret = ENGINE_set_DH(e, hpre_get_dh_methods());
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_DH failed.",
        KAE_F_BIND_HELPER, KAE_R_SET_DH_FAILURE);
#endif
    ret = ENGINE_set_destroy_function(e, kae_engine_destroy);
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_destroy_function failed.",
        KAE_F_BIND_HELPER, KAE_R_SET_DESTORY_FAILURE);

    ret = ENGINE_set_init_function(e, kae_engine_init);
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_init_function failed.",
        KAE_F_BIND_HELPER, KAE_R_SET_INIT_FAILURE);

    ret = ENGINE_set_finish_function(e, kae_engine_finish);
    RETURN_FAIL_IF(ret != 1, "ENGINE_set_finish_function failed.",
        KAE_F_BIND_HELPER, KAE_R_SET_FINISH_FAILURE);

    ret &= ENGINE_set_ctrl_function(e, kae_engine_ctrl);
    ret &= ENGINE_set_cmd_defns(e, g_kae_cmd_defns);
    if (ret != 1) {
        US_ERR("Engine set ctrl function or defines failed\n");
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_kae)
IMPLEMENT_DYNAMIC_CHECK_FN()
/*lint -e(10)*/
