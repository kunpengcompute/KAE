/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the implemenation for error module
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
#include "engine_opensslerr.h"

#define ERR_FUNC(func)     ERR_PACK(0, func, 0)
#define ERR_REASON(reason) ERR_PACK(0, 0, reason)

static int g_kae_lib_error_code = 0;
static int g_kae_error_init = 1;

static ERR_STRING_DATA g_kae_str_functs[] = {
    { ERR_FUNC(KAE_F_HPRE_GET_RSA_METHODS),    "hpre_get_RSA_methods" },
    { ERR_FUNC(KAE_F_CHANGRSAMETHOD),          "changRsaMethod" },
    { ERR_FUNC(KAE_F_HPRE_PKEY_METHS),         "hpre_pkey_meths" },
    { ERR_FUNC(KAE_F_BIND_HELPER),             "bind_helper" },
    { ERR_FUNC(KAE_F_RSA_FILL_KENGEN_PARAM),   "rsa_fill_keygen_param" },
    { ERR_FUNC(KAE_F_HPRE_RSA_PUBENC),         "hpre_rsa_public_encrypt" },
    { ERR_FUNC(KAE_F_HPRE_RSA_PRIENC),         "hpre_rsa_private_encrypt" },
    { ERR_FUNC(KAE_F_HPRE_RSA_PUBDEC),         "hpre_rsa_public_decrypt" },
    { ERR_FUNC(KAE_F_HPRE_RSA_PRIDEC),         "hpre_rsa_private_decrypt" },
    { ERR_FUNC(KAE_F_HPRE_RSA_PRIMEGEN),       "hpre_rsa_primegen" },
    { ERR_FUNC(KAE_F_HPRE_RSA_KEYGEN),         "hpre_rsa_keygen" },
    { ERR_FUNC(KAE_F_CHECK_PUBKEY_PARAM),      "check_pubkey_param" },
    { ERR_FUNC(KAE_F_HPRE_PUBENC_PADDING),     "hpre_pubenc_padding" },
    { ERR_FUNC(KAE_F_HPRE_PRIENC_PADDING),     "hpre_prienc_padding" },
    { ERR_FUNC(KAE_F_CHECK_HPRE_PUBDEC_PADDING), "hpre_check_pubdec_padding" },
    { ERR_FUNC(KAE_F_CHECK_HPRE_PRIDEC_PADDING), "hpre_check_pridec_padding" },
    { ERR_FUNC(KAE_F_DIGEST_SOFT_INIT),         "sec_digest_soft_init" },
    { 0,                                        (const char *)NULL }
};

static ERR_STRING_DATA g_kae_str_reasons[] = {
    { ERR_REASON(KAE_R_NO_MATCH_DEVICE),            "get no match device.check the hw resource" },
    { ERR_REASON(KAE_R_MALLOC_FAILURE),             "no system memory to alloc" },
    { ERR_REASON(KAE_R_HWMEM_MALLOC_FAILURE),       "no hardware memory to alloc" },
    { ERR_REASON(KAE_R_INPUT_PARAM_ERR),            "input param is invaild" },
    { ERR_REASON(KAE_R_SET_ID_FAILURE),             "kae engine set id failure" },
    { ERR_REASON(KAE_R_SET_NAME_FAILURE),           "kae engine set name failure" },
    { ERR_REASON(KAE_R_SET_PKEYMETH_FAILURE),       "kae engine set pkeymeth function failure" },
    { ERR_REASON(KAE_R_SET_RSA_FAILURE),            "kae engine set rsa failure" },
    { ERR_REASON(KAE_R_SET_DESTORY_FAILURE),        "kae engine set destory function failure" },
    { ERR_REASON(KAE_R_SET_INIT_FAILURE),           "kae engine set init function failure" },
    { ERR_REASON(KAE_R_SET_CTRL_FAILURE),           "kae engine set ctrl function failure" },
    { ERR_REASON(KAE_R_SET_CMDDEF_FAILURE),         "kae engine set cmd define failure" },
    { ERR_REASON(KAE_R_SET_FINISH_FAILURE),         "kae engine set finish function failure" },
    { ERR_REASON(KAE_R_UNSUPPORT_HARDWARE_TYPE),    "unsupported hardware type" },
    { ERR_REASON(KAE_R_TIMEOUT),                    "Operation timeout" },
    { ERR_REASON(KAE_R_RSARECV_FAILURE),            "RSA receive failure" },
    { ERR_REASON(KAE_R_RSARECV_STATE_FAILURE),      "RSA received but status is failure" },
    { ERR_REASON(KAE_R_RSASEND_FAILURE),            "RSA send failure" },
    { ERR_REASON(KAE_R_GET_ALLOCED_HWMEM_FAILURE),  "get memory from reserve memory failure" },
    { ERR_REASON(KAE_R_FREE_ALLOCED_HWMEM_FAILURE), "free memory to reserve memory failure" },
    { ERR_REASON(KAE_R_RSA_KEY_NOT_COMPELET),       "rsa key param is not compeleted" },
    { ERR_REASON(KAE_R_RSA_PADDING_FAILURE),        "rsa padding failed" },
    { ERR_REASON(KAE_R_DATA_TOO_LARGE_FOR_MODULUS), "data too large for modules" },
    { ERR_REASON(KAE_R_DATA_GREATER_THEN_MOD_LEN),  "data greater than mod len" },
    { ERR_REASON(KAE_R_CHECKPADDING_FAILURE),       "check rsa padding failure" },
    { ERR_REASON(KAE_R_ERR_LIB_BN),                 "err in BN operation" },
    { ERR_REASON(KAE_R_RSA_KEY_SIZE_TOO_SMALL),     "data too small" },
    { ERR_REASON(KAE_R_MODULE_TOO_LARGE),           "data too large" },
    { ERR_REASON(KAE_R_INVAILED_E_VALUE),           "invailed e value" },
    { ERR_REASON(KAE_R_UNKNOW_PADDING_TYPE),        "unknow padding type" },
    { ERR_REASON(KAE_R_INPUT_FIKE_LENGTH_ZERO),     "input file length zero" },
    { ERR_REASON(KAE_R_NEW_ENGINE_FAILURE),         "get new engine failure" },
    { ERR_REASON(KAE_R_BIND_ENGINE_FAILURE),        "kae engine bind failure" },
    { ERR_REASON(KAE_R_RSA_SET_METHODS_FAILURE),    "rsa set kae methods failure" },
    { ERR_REASON(KAE_R_PUBLIC_KEY_INVALID),         "invalid public key" },
    { ERR_REASON(KAE_R_PUBLIC_ENCRYPTO_FAILURE),    "rsa public key encrypto failure" },
    { ERR_REASON(KAE_R_PUBLIC_DECRYPTO_FAILURE),    "rsa public key decrypto failure" },
    { ERR_REASON(KAE_R_GET_PRIMEKEY_FAILURE),       "rsa prime key generate failure" },
    { ERR_REASON(KAE_R_ENGINE_ALREADY_DEFINED),     "kae engine already defined, try to use engine id 'kae' instead." },
    { 0,                                             (const char *)NULL }
};

int err_load_kae_strings(void)
{
    if (g_kae_lib_error_code == 0) {
        g_kae_lib_error_code = ERR_get_next_error_library();
    }

    if (g_kae_error_init) {
        g_kae_error_init = 0;
        ERR_load_strings(g_kae_lib_error_code, g_kae_str_functs);
        ERR_load_strings(g_kae_lib_error_code, g_kae_str_reasons);
    }
    return 1;
}

void err_unload_kae_strings(void)
{
    if (g_kae_error_init == 0) {
        ERR_unload_strings(g_kae_lib_error_code, g_kae_str_functs);
        ERR_unload_strings(g_kae_lib_error_code, g_kae_str_reasons);
        g_kae_error_init = 1;
    }
}

void err_kae_error(int function, int reason, char *engine_file, int line)
{
    if (g_kae_lib_error_code == 0) {
        g_kae_lib_error_code = ERR_get_next_error_library();
    }
    ERR_PUT_error(g_kae_lib_error_code, function, reason, engine_file, line);
}
