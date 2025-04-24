/*-
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef RSA_DEMO_H
#define RSA_DEMO_H

#ifdef __cplusplus  
extern "C" {  
#endif  

int kae_bssl_rsa_sign(RSA *rsa, unsigned char *srcStr, size_t in_len, unsigned char *encData, unsigned int padding_mode);

int bssl_rsa_verify(RSA *rsa, unsigned char *encData, size_t enclen, unsigned char *decData, unsigned int padding_mode);

int bssl_rsa_public_enc(RSA *rsa, unsigned char *srcStr, size_t in_len, unsigned char *encData, unsigned int padding_mode);

int kae_bssl_rsa_private_dec(RSA *rsa, unsigned char *encData, size_t enclen, unsigned char *decData, unsigned int padding_mode);

#ifdef __cplusplus  
}  
#endif  
#endif

