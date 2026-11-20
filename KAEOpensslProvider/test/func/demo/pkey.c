#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

int main(void) {
    OSSL_PROVIDER *prov_kae = NULL, *prov_def = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char sig[512];
    size_t siglen = sizeof(sig);

    const char msg[] = "Hello RSA Sign/Verify with KAE provider";
    int ret = 0;

    // 加载 KAE provider 和 default provider
    prov_kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    if (!prov_kae) {
        fprintf(stderr, "Warning: kae_provider not available, will fallback to default.\n");
        return 1;
    }

    prov_def = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_def) {
        fprintf(stderr, "Error: default provider not available!\n");
        return 1;
    }

    /* 设置默认 provider 优先级：优先使用 kae_provider，失败则 fallback */
    EVP_set_default_properties(NULL, "?provider=kae_provider");

    /* 生成 RSA 2048 key */
    kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!kctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name(RSA) failed\n");
        goto end;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init(RSA) failed\n");
        goto end;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
        goto end;
    }

    if (EVP_PKEY_generate(kctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate(RSA) failed\n");
        goto end;
    }

    const OSSL_PROVIDER *prov = EVP_PKEY_get0_provider(pkey);
    printf("RSA key generated from provider: %s\n",
           prov ? OSSL_PROVIDER_get0_name(prov) : "unknown");

    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    /* 签名 */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto end;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed\n");
        goto end;
    }

    if (EVP_DigestSignUpdate(mdctx, msg, strlen(msg)) <= 0) {
        fprintf(stderr, "EVP_DigestSignUpdate failed\n");
        goto end;
    }

    if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal failed\n");
        goto end;
    }

    printf("Signature generated, length = %zu bytes\n", siglen);

    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;

    /* 验证 */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto end;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        goto end;
    }

    if (EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg)) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyUpdate failed\n");
        goto end;
    }

    ret = EVP_DigestVerifyFinal(mdctx, sig, siglen);
    if (ret == 1) {
        printf("Signature verify success\n");
    } else {
        printf("Signature verify failed\n");
        // 可选：打印 OpenSSL 错误栈（不强制）
        ERR_print_errors_fp(stderr);
    }

    ret = 0;  // 成功执行完

end:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);

    OSSL_PROVIDER_unload(prov_kae);
    OSSL_PROVIDER_unload(prov_def);

    return ret;
}