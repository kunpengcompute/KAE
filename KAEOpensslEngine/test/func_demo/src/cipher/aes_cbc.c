/*
 * Copyright 2012-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple ARIA CBC encryption demonstration program.
 */
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
// #include <openssl/core_names.h>// openssl 3.0

/* ARIA key */
const unsigned char cbc_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

/* Unique initialisation vector */
const unsigned char cbc_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
    0x99, 0xaa, 0x3e, 0x68,
};

/*
 * A library context and property query can be used to select & filter
 * algorithm implementations. If they are NULL then the default library
 * context and properties are used.
 */
// static OSSL_LIB_CTX *libctx = NULL;
// static const char *propq = NULL;

int kae_cbc_encrypt(ENGINE *engine, const unsigned char *plantext, int plen, unsigned char *outbuf, int * outlen)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int tmplen;

    printf("[ARIA CBC Encrypt]\n");
    printf("Plaintext(plen %d):\n", plen);
    // BIO_dump_fp(stdout, plantext, plen);

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    // if ((cipher = EVP_CIPHER_fetch(libctx, "ARIA-256-CBC", propq)) == NULL)
    //     goto err;
    if ((cipher = EVP_aes_256_cbc()) == NULL)
        goto err;

    /*
     * Initialise an encrypt operation with the cipher/mode, key and IV.
     * We are not setting any custom params so let params be just NULL.
     */
    // if (!EVP_EncryptInit_ex2(ctx, cipher, cbc_key, cbc_iv, /* params */ NULL))
    //     goto err;
    if (!EVP_EncryptInit_ex(ctx, cipher, engine, cbc_key, cbc_iv))
        goto err;

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, outbuf, outlen, plantext, plen))
        goto err;

    /* Finalise: there can be some additional output from padding */
    if (!EVP_EncryptFinal_ex(ctx, outbuf + *outlen, &tmplen))
        goto err;
    *outlen += tmplen;

    /* Output encrypted block */
    printf("Ciphertext (outlen:%d):\n", *outlen);
    // BIO_dump_fp(stdout, outbuf, *outlen);

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    // EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int kae_cbc_decrypt(ENGINE *engine, const unsigned char *ciphertext, int clen, unsigned char *outbuf, int * outlen)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int tmplen;

    printf("[ARIA CBC Decrypt:]\n");
    printf("Ciphertext:\n");
    // BIO_dump_fp(stdout, ciphertext, clen);

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    // if ((cipher = EVP_CIPHER_fetch(libctx, "ARIA-256-CBC", propq)) == NULL)
    //     goto err;
    if ((cipher = EVP_aes_256_cbc()) == NULL)
        goto err;

    /*
     * Initialise an encrypt operation with the cipher/mode, key and IV.
     * We are not setting any custom params so let params be just NULL.
     */
    // if (!EVP_DecryptInit_ex2(ctx, cipher, cbc_key, cbc_iv, /* params */ NULL))
    //     goto err;
    if (!EVP_DecryptInit_ex(ctx, cipher, engine, cbc_key, cbc_iv))
        goto err;

    /* Decrypt plaintext */
    if (!EVP_DecryptUpdate(ctx, outbuf, outlen, ciphertext, clen))
        goto err;

    /* Finalise: there can be some additional output from padding */
    if (!EVP_DecryptFinal_ex(ctx, outbuf + *outlen, &tmplen))
        goto err;
    *outlen += tmplen;

    /* Output decrypted block */
    printf("Plaintext (outlen:%d):\n", *outlen);
    // BIO_dump_fp(stdout, outbuf, *outlen);

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    // EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

