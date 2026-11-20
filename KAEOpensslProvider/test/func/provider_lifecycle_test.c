/* Copyright 2026 Huawei Technologies Co.,Ltd.All rights reserved.
 * Licensed under the Apache License, Version 2.0.
 */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

struct instance {
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *def;
    OSSL_PROVIDER *kae;
};

static int open_instance(struct instance *instance)
{
    instance->ctx = OSSL_LIB_CTX_new();
    if (instance->ctx == NULL)
        return 0;
    instance->def = OSSL_PROVIDER_load(instance->ctx, "default");
    instance->kae = OSSL_PROVIDER_load(instance->ctx, "kae_provider");
    return instance->def != NULL && instance->kae != NULL;
}

static void close_instance(struct instance *instance)
{
    OSSL_PROVIDER_unload(instance->kae);
    OSSL_PROVIDER_unload(instance->def);
    OSSL_LIB_CTX_free(instance->ctx);
    memset(instance, 0, sizeof(*instance));
}

static int exercise(struct instance *instance)
{
    unsigned char message[32] = {1}, signature[128];
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_name(instance->ctx, "SM2", "provider=kae_provider");
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sign = EVP_MD_CTX_new(), *verify = EVP_MD_CTX_new();
    size_t length = sizeof(signature);
    int ok = gen && sign && verify && EVP_PKEY_keygen_init(gen) > 0 &&
        EVP_PKEY_generate(gen, &key) > 0 &&
        EVP_DigestSignInit_ex(sign, NULL, "SM3", instance->ctx, "provider=kae_provider", key, NULL) > 0 &&
        EVP_DigestSign(sign, signature, &length, message, sizeof(message)) > 0 &&
        EVP_DigestVerifyInit_ex(verify, NULL, "SM3", instance->ctx, "provider=kae_provider", key, NULL) > 0 &&
        EVP_DigestVerify(verify, signature, length, message, sizeof(message)) == 1;
    EVP_MD_CTX_free(sign);
    EVP_MD_CTX_free(verify);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gen);
    return ok;
}

static int selection_unchanged(void)
{
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    EVP_CIPHER *hw = NULL, *implicit = NULL;
    int ok = def && kae && EVP_set_default_properties(NULL, "provider=default");

    if (ok) {
        /* A KAE query must not replace the application's selection policy. */
        hw = EVP_CIPHER_fetch(NULL, "AES-256-CTR", "provider=kae_provider");
        implicit = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
        ok = hw && implicit &&
            !strcmp(OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(hw)), "kae_provider") &&
            !strcmp(OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(implicit)), "default");
    }
    EVP_CIPHER_free(hw);
    EVP_CIPHER_free(implicit);
    EVP_set_default_properties(NULL, NULL);
    OSSL_PROVIDER_unload(kae);
    OSSL_PROVIDER_unload(def);
    return ok;
}

int main(int argc, char **argv)
{
    struct instance a = {0}, b = {0};
    int ok = 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2)
        return 2;
    if (!strcmp(argv[1], "selection")) {
        ok = selection_unchanged();
    } else if (!strcmp(argv[1], "simple")) {
        unsigned char random[32];
        OSSL_PROVIDER *kae = OSSL_PROVIDER_load(NULL, "kae_provider");
        EVP_KEYMGMT *method = EVP_KEYMGMT_fetch(NULL, "RSA", NULL);
        ok = kae && method && RAND_bytes(random, sizeof(random)) == 1 &&
            !strcmp(OSSL_PROVIDER_get0_name(EVP_KEYMGMT_get0_provider(method)), "kae_provider");
        EVP_KEYMGMT_free(method);
        OSSL_PROVIDER_unload(kae);
    } else if (!strcmp(argv[1], "reload")) {
        for (int i = 0; i < 20 && ok; i++) {
            ok = open_instance(&a) && exercise(&a);
            close_instance(&a);
        }
    } else if (!strcmp(argv[1], "contexts")) {
        ok = open_instance(&a) && open_instance(&b) && exercise(&a) && exercise(&b);
        close_instance(&a);
        if (ok)
            ok = exercise(&b);
        close_instance(&b);
    } else {
        return 2;
    }
    if (!ok)
        ERR_print_errors_fp(stderr);
    printf("%s lifecycle %s\n", ok ? "PASS" : "FAIL", argv[1]);
    return ok ? 0 : 1;
}
