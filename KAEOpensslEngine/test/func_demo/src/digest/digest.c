/*-
 * Copyright 2021-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example of using EVP_MD_fetch and EVP_Digest* methods to calculate
 * a digest of static buffers
 */

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include"demo_utils.h"

/*-
 * This demonstration will show how to digest data using
 * the soliloqy from Hamlet scene 1 act 3
 * The soliloqy is split into two parts to demonstrate using EVP_DigestUpdate
 * more than once.
 */
int demonstrate_digest(const EVP_MD *message_digest, char * msg1, char * msg2, unsigned char *digest_value,  unsigned int *digest_length)
{
    int ret = 0;
    const char *option_properties = NULL;

    EVP_MD_CTX *digest_context = NULL;
    unsigned int j;

    /*
     * Make a message digest context to hold temporary state
     * during digest creation
     */
    digest_context = EVP_MD_CTX_new();
    if (digest_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }
    /*
     * Initialize the message digest context to use the fetched 
     * digest provider
     */
    if (EVP_DigestInit(digest_context, message_digest) != 1) {
        fprintf(stderr, "EVP_DigestInit failed.\n");
        goto cleanup;
    }

    /* Digest parts one and two of the soliloqy */
    if (EVP_DigestUpdate(digest_context, msg1, strlen(msg1)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestUpdate(digest_context, msg2, strlen(msg2)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate(hamlet_2) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestFinal(digest_context, digest_value, digest_length) != 1) {
        fprintf(stderr, "EVP_DigestFinal() failed.\n");
        goto cleanup;
    }

    printf("[DIGEST VALUE]\n");
    PRINTMSG(digest_value, *digest_length);


cleanup:
    if (ret != 1)
        ERR_print_errors_fp(stderr);
    /* OpenSSL free functions will ignore NULL arguments */
    EVP_MD_CTX_free(digest_context);

    return ret;
}