/*
 * Copyright 2012-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM authenticated encryption with additional data (AEAD)
 * demonstration program.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
// #include <openssl/core_names.h>

/* AES-GCM test data obtained from NIST public test vectors */

/* AES key */
static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

/* Unique initialisation vector */
static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

/* Expected AEAD Tag value */
static const unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

/*
 * A library context and property query can be used to select & filter
 * algorithm implementations. If they are NULL then the default library
 * context and properties are used.
 */
// static OSSL_LIB_CTX *libctx = NULL;
// static const char *propq = NULL;

int kae_gcm_encrypt(ENGINE *engine, unsigned char *plaintext, int plaintext_len,
                    unsigned char *outbuf, int *outlen,
                    unsigned char *outtag)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int tmplen;

    // OSSL_PARAM params[2] = {
    //     OSSL_PARAM_END, OSSL_PARAM_END
    // };

    printf("AES GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, plaintext, plaintext_len);

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    // if ((cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq)) == NULL)
    //     goto err;
    if ((cipher = EVP_aes_256_gcm()) == NULL)
        goto err;

    /* Set IV length if default 96 bits is not appropriate */
    // params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
    //                                         &gcm_ivlen);

    /*
     * Initialise an encrypt operation with the cipher/mode, key, IV and
     * IV length parameter.
     * For demonstration purposes the IV is being set here. In a compliant
     * application the IV would be generated internally so the iv passed in
     * would be NULL. 
     */
    // if (!EVP_EncryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
    //     goto err;
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto err;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL))
        goto err;;

    
    if (!EVP_EncryptInit_ex(ctx, cipher, engine, gcm_key, gcm_iv))
        goto err;

    /* Zero or more calls to specify any AAD */
    if (!EVP_EncryptUpdate(ctx, NULL, &tmplen, gcm_aad, sizeof(gcm_aad)))
        goto err;

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, outbuf, &tmplen, plaintext, plaintext_len))
        goto err;
    *outlen = tmplen;



    /* Finalise: note get no output for GCM */
    ret = EVP_EncryptFinal_ex(ctx, outbuf + tmplen, &tmplen);
        // goto err;
    *outlen += tmplen;

    // /* Get tag */
    // params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
    //                                               outtag, 16);

    // if (!EVP_CIPHER_CTX_get_params(ctx, params))
    //     goto err;

     if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outtag))
        goto err;

    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, *outlen);

    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outtag, 16);

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    // EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int kae_gcm_decrypt(ENGINE *engine, unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *outbuf, int *outlen)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int rv;
    int len;

    // OSSL_PARAM params[2] = {
    //     OSSL_PARAM_END, OSSL_PARAM_END
    // };

    printf("AES GCM Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ciphertext, ciphertext_len);

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    // if ((cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq)) == NULL)
    //     goto err;
     if ((cipher = EVP_aes_256_gcm()) == NULL)
        goto err;

    /* Set IV length if default 96 bits is not appropriate */
    // params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
    //                                         &gcm_ivlen);

    /*
     * Initialise an encrypt operation with the cipher/mode, key, IV and
     * IV length parameter.
     */
    // if (!EVP_DecryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
    //     goto err;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto err;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL))
        goto err;

    if (!EVP_DecryptInit_ex(ctx, cipher, engine, gcm_key, gcm_iv))
        goto err;

    /* Zero or more calls to specify any AAD */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, gcm_aad, sizeof(gcm_aad)))
        goto err;

    /* Decrypt plaintext engine块模式update阶段只拼包，不计算，传出len为0*/
    if (!EVP_DecryptUpdate(ctx, outbuf, &len, ciphertext, ciphertext_len))
        goto err;
    *outlen = len;

    /* Set expected tag value. */
    // params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
    //                                               (void*)gcm_tag, sizeof(gcm_tag));

    // if (!EVP_CIPHER_CTX_set_params(ctx, params))
    //     goto err;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        goto err;

    /* 尾包才做最后的计算*/
    rv = EVP_DecryptFinal_ex(ctx, outbuf + len, &len);
    *outlen += len;

    /* Output decrypted block */
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, outbuf, len);

    printf("Tag:\n");
    BIO_dump_fp(stdout, tag, 16);


    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    
    if(rv > 0) {
        /* Success */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    ret = 1;
    } else {
        /* Verify failed */
        ret = -1;
    }
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    // EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

