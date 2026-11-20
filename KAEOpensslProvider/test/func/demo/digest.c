#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define DATA_SIZE (16 * 1024)  // 16KB input

int main(void)
{
    OSSL_PROVIDER *prov_kae = NULL, *prov_def = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char *data = NULL;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int i;

    // 加载 KAE provider（硬件加速）
    prov_kae = OSSL_PROVIDER_load(NULL, "kae_provider");
    if (!prov_kae) {
        fprintf(stderr, "Warning: kae_provider not available, will fallback to default.\n");
        return 1;
    }

    // 加载 default provider 作为 fallback
    prov_def = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_def) {
        fprintf(stderr, "Error: default provider not available!\n");
        return 1;
    }

    // 设置默认属性：优先使用 kae_provider
    if (EVP_set_default_properties(NULL, "?provider=kae_provider") != 1) {
        fprintf(stderr, "EVP_set_default_properties failed\n");
        goto end;
    }

    // 获取 SM3 算法实现（优先 kae，fallback default）
    md = EVP_MD_fetch(NULL, "SM3", NULL);
    if (!md) {
        fprintf(stderr, "EVP_MD_fetch(SM3) failed\n");
        goto end;
    }

    const OSSL_PROVIDER *prov = EVP_MD_get0_provider(md);
    printf("SM3 algorithm fetched from provider: %s\n",
           prov ? OSSL_PROVIDER_get0_name(prov) : "unknown");

    // 创建哈希上下文
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto end;
    }

    // 初始化数据（16KB，可替换为真实数据）
    data = OPENSSL_malloc(DATA_SIZE);
    if (!data) {
        fprintf(stderr, "OPENSSL_malloc failed\n");
        goto end;
    }
    for (int i = 0; i < DATA_SIZE; i++) {
        data[i] = (unsigned char)(i & 0xFF);  // 填充测试数据
    }

    // 开始哈希计算
    if (EVP_DigestInit_ex2(mdctx, md, NULL) <= 0) {
        fprintf(stderr, "EVP_DigestInit_ex2 failed\n");
        goto end;
    }

    if (EVP_DigestUpdate(mdctx, data, DATA_SIZE) <= 0) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        goto end;
    }

    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) <= 0) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        goto end;
    }

    // 输出结果
    printf("Input size: %d bytes\n", DATA_SIZE);
    printf("SM3 digest: ");
    for (i = 0; i < md_len; i++) {
        printf("%02x", md_value[i]);
    }
    printf("\n");

    // 成功
    printf("SM3 calculation completed.\n");

end:
    // 清理资源
    OPENSSL_free(data);
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free((EVP_MD *)md);
    OSSL_PROVIDER_unload(prov_kae);
    OSSL_PROVIDER_unload(prov_def);

    return 0;
}