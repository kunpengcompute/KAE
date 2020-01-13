/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for switch to soft rsa
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

#include <openssl/rsa.h>
#include "hpre_rsa.h"
#include "engine_log.h"

/**
 *   succ: > 0
 *   fail: 0
 */
int hpre_rsa_soft_calc(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding, int type)
{
    US_DEBUG("hpre_rsa_soft_calc.\n");
    int ret = 0;
    const RSA_METHOD *soft_rsa = RSA_PKCS1_OpenSSL();
    switch (type) {
        case PUB_ENC:
            ret = RSA_meth_get_pub_enc(soft_rsa)(flen, from, to, rsa, padding);
            break;
        case PUB_DEC:
            ret = RSA_meth_get_pub_dec(soft_rsa)(flen, from, to, rsa, padding);
            break;
        case PRI_ENC:
            ret = RSA_meth_get_priv_enc(soft_rsa)(flen, from, to, rsa, padding);
            break;
        case PRI_DEC:
            ret = RSA_meth_get_priv_dec(soft_rsa)(flen, from, to, rsa, padding);
            break;
        default:
            return 0;
    }
    return ret;
}

/**
 *   succ: 1
 *   fail: 0
 */
int hpre_rsa_soft_genkey(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    US_DEBUG("hpre_rsa_soft_genkey.\n");
    UNUSED(cb);
    const RSA_METHOD *default_meth = RSA_PKCS1_OpenSSL();
    RSA_set_method(rsa, default_meth);
    int ret = RSA_generate_key_ex(rsa, bits, e, (BN_GENCB *)NULL);
    if (ret != 1) {
        US_ERR("rsa soft key generate fail!");
        return 0;
    }

    return 1;
}
