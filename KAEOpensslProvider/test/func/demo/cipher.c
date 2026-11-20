#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define DATA_SIZE (16 * 1024)  // 16KB

int main(void)
{
    OSSL_PROVIDER *prov_kae = NULL, *prov_def = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;

    // 加载 KAE provider 和 default provider
    prov_kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    if (!prov_kae) {
        fprintf(stderr, "Warning: kae_provider not available, will fallback.\n");
        return 1;
    }

    // 加载 default provider 作为 fallback
    prov_def = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_def) {
        fprintf(stderr, "Error: default provider not available!\n");
        return 1;
    }

    // 设置属性：优先使用 kae_provider，如果是kae不支持的算法，则使用default provider
    EVP_set_default_properties(NULL, "?provider=kae_provider");

    // 获取 SM4-CBC 算法（优先 kae_provider, fallback 到 default）
    cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", NULL);
    if (!cipher) {
        fprintf(stderr, "EVP_CIPHER_fetch(SM4-CBC) failed\n");
        goto end;
    }
    printf("SM4-CBC fetched from provider: %s\n",
           EVP_CIPHER_get0_provider(cipher)
               ? OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(cipher))
               : "unknown");

    // 创建上下文并初始化
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto end;
    }

    unsigned char key[16] = {0};  // 128-bit key
    unsigned char iv[16]  = {0};  // 128-bit IV
    unsigned char *in  = OPENSSL_malloc(DATA_SIZE);
    unsigned char *out = OPENSSL_malloc(DATA_SIZE + 16); // 可能有padding
    if (!in || !out) {
        fprintf(stderr, "malloc failed\n");
        goto end;
    }

    // 填充输入数据（16KB）
    for (int i = 0; i < DATA_SIZE; i++) {
        in[i] = (unsigned char)(i & 0xFF);
    }

    int outlen = 0, tmplen = 0;

    if (!EVP_CipherInit_ex2(ctx, cipher, key, iv, 1, NULL)) {
        fprintf(stderr, "EVP_CipherInit_ex2 failed\n");
        goto end;
    }

    if (!EVP_CipherUpdate(ctx, out, &outlen, in, DATA_SIZE)) {
        fprintf(stderr, "EVP_CipherUpdate failed\n");
        goto end;
    }

    if (!EVP_CipherFinal_ex(ctx, out + outlen, &tmplen)) {
        fprintf(stderr, "EVP_CipherFinal_ex failed\n");
        goto end;
    }
    outlen += tmplen;

    printf("Input size = %d bytes, Ciphertext length = %d\n", DATA_SIZE, outlen);

end:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(prov_kae);
    OSSL_PROVIDER_unload(prov_def);
    return 0;
}
