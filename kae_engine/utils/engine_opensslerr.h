/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description: This file provides the interface for error module
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

#ifndef HISI_ACC_ENGINE_OPENSSLERR_H
#define HISI_ACC_ENGINE_OPENSSLERR_H

int err_load_kae_strings(void);
void err_unload_kae_strings(void);
void err_kae_error(int function, int reason, char *engine_file, int line);
#define KAEerr(f, r) err_kae_error((f), (r), OPENSSL_FILE, OPENSSL_LINE)

/* Function codes. */
enum HISI_FUNC_CODE {
    KAE_F_HPRE_GET_RSA_METHODS = 100,
    KAE_F_CHANGRSAMETHOD,
    KAE_F_HPRE_PKEY_METHS,
    KAE_F_BIND_HELPER,
    KAE_F_RSA_FILL_KENGEN_PARAM,
    KAE_F_HPRE_RSA_PUBENC,
    KAE_F_HPRE_RSA_PRIENC,
    KAE_F_HPRE_RSA_PUBDEC,
    KAE_F_HPRE_RSA_PRIDEC,
    KAE_F_HPRE_RSA_PRIMEGEN,
    KAE_F_HPRE_RSA_KEYGEN,
    KAE_F_CHECK_PUBKEY_PARAM,
    KAE_F_HPRE_PUBENC_PADDING,
    KAE_F_HPRE_PRIENC_PADDING,
    KAE_F_CHECK_HPRE_PUBDEC_PADDING,
    KAE_F_CHECK_HPRE_PRIDEC_PADDING,
    KAE_F_SEC_SM3_INIT,
    KAE_F_SEC_SM3_FINAL,
    KAE_F_DIGEST_SOFT_INIT,
    KAE_F_ENGINE_WD,
    KAE_F_BIND_FN,
    KAE_F_CHECK_DATA_VALID,
    KAE_F_CHECK_MALLOC_SUCC,
    KAE_F_HPRE_GET_DH_METHODS,
    KAE_F_HPRE_DH_KEYGEN,
    KAE_F_HPRE_DH_KEYCOMP,
    KAE_F_CHANGDHMETHOD
};

enum HISI_RESON_CODE {
    KAE_R_NO_MATCH_DEVICE = 100,
    KAE_R_MALLOC_FAILURE,
    KAE_R_HWMEM_MALLOC_FAILURE,
    KAE_R_INPUT_PARAM_ERR,
    KAE_R_SET_ID_FAILURE,
    KAE_R_SET_NAME_FAILURE,
    KAE_R_SET_PKEYMETH_FAILURE,
    KAE_R_SET_RSA_FAILURE,
    KAE_R_SET_DESTORY_FAILURE,
    KAE_R_SET_INIT_FAILURE,
    KAE_R_SET_CTRL_FAILURE,
    KAE_R_SET_CMDDEF_FAILURE,
    KAE_R_SET_FINISH_FAILURE,
    KAE_R_UNSUPPORT_HARDWARE_TYPE,
    KAE_R_TIMEOUT,
    KAE_R_RSARECV_FAILURE,
    KAE_R_RSARECV_STATE_FAILURE,
    KAE_R_RSASEND_FAILURE,
    KAE_R_GET_ALLOCED_HWMEM_FAILURE,
    KAE_R_FREE_ALLOCED_HWMEM_FAILURE,
    KAE_R_RSA_KEY_NOT_COMPELET,
    KAE_R_RSA_PADDING_FAILURE,
    KAE_R_DATA_TOO_LARGE_FOR_MODULUS,
    KAE_R_DATA_GREATER_THEN_MOD_LEN,
    KAE_R_CHECKPADDING_FAILURE,
    KAE_R_ERR_LIB_BN,
    KAE_R_RSA_KEY_SIZE_TOO_SMALL,
    KAE_R_MODULE_TOO_LARGE,
    KAE_R_INVAILED_E_VALUE,
    KAE_R_UNKNOW_PADDING_TYPE,
    KAE_R_INPUT_FIKE_LENGTH_ZERO,
    KAE_R_SET_CIPHERS_FAILURE,
    KAE_R_SET_DIGESTS_FAILURE,
    KAE_R_NEW_ENGINE_FAILURE,
    KAE_R_BIND_ENGINE_FAILURE,
    KAE_R_RSA_SET_METHODS_FAILURE,
    KAE_R_PUBLIC_KEY_INVALID,
    KAE_R_PUBLIC_ENCRYPTO_FAILURE,
    KAE_R_PUBLIC_DECRYPTO_FAILURE,
    KAE_R_GET_PRIMEKEY_FAILURE,
    KAE_R_DH_SET_METHODS_FAILURE,
    KAE_R_SET_DH_FAILURE,
    KAE_R_DH_KEY_SIZE_TOO_LARGE,
    KAE_R_DH_INVALID_PARAMETER,
    KAE_R_ENGINE_ALREADY_DEFINED,
};

#endif  // HISI_ACC_ENGINE_OPENSSLERR_H
