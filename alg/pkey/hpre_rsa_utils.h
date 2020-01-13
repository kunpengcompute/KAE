/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the rsa interface for KAE engine utils dealing
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

#ifndef HPRE_RSA_UTILS_H
#define HPRE_RSA_UTILS_H

BN_ULONG *bn_get_words(const BIGNUM *a);

void hpre_free_bn_ctx_buf(BN_CTX *bn_ctx, unsigned char *in_buf, int num);

int hpre_rsa_check_para(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa);

int hpre_get_prienc_res(int padding, BIGNUM *f, const BIGNUM *n, BIGNUM *bn_ret, BIGNUM **res);

int check_bit_useful(const int bit);

int check_pubkey_param(const BIGNUM *n, const BIGNUM *e);

int hpre_rsa_padding(int flen, const unsigned char *from, unsigned char *buf,
                     int num, int padding, int type);

int check_rsa_padding(unsigned char *to, int num,
                      const unsigned char *buf, int len, int padding, int type);

int hpre_rsa_primegen(int bits, BIGNUM *e_value, BIGNUM *p, BIGNUM *q, BN_GENCB *cb);

#endif
