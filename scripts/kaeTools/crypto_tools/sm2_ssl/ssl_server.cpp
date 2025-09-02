// 使用指南参考：https://docs.openeuler.org/zh/docs/22.09/docs/ShangMi/TLCP%E5%8D%8F%E8%AE%AE%E6%A0%88.html
// 服务端代码
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
int main()
{
    // 变量定义
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1, client_sock = -1;
    struct sockaddr_in addr;
    const char *sign_cert_file = "SS.crt";
    const char *sign_key_file = "SS.key";
    const char *enc_cert_file = "SE.crt";
    const char *enc_key_file = "SE.key";
    const int port = 4433;
    int bytes;
    // 初始化OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    // 创建TCP套接字
    sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    // 绑定和监听
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(sock, 5) != 0) {
        perror("Socket setup failed");
        goto err;
    }
    // 创建SSL上下文
    if (!(ctx = SSL_CTX_new(TLS_server_method()))) {
        ERR_print_errors_fp(stderr);
        goto err;
    }
    // 加载证书和密钥
    if (!SSL_CTX_use_gm_certificate_file(ctx, sign_cert_file, SSL_FILETYPE_PEM, SSL_USAGE_SIG) ||
        !SSL_CTX_use_gm_PrivateKey_file(ctx, sign_key_file, SSL_FILETYPE_PEM, SSL_USAGE_SIG) ||
        !SSL_CTX_use_gm_certificate_file(ctx, enc_cert_file, SSL_FILETYPE_PEM, SSL_USAGE_ENC) ||
        !SSL_CTX_use_gm_PrivateKey_file(ctx, enc_key_file, SSL_FILETYPE_PEM, SSL_USAGE_ENC)) {
        ERR_print_errors_fp(stderr);
        goto err;
    }
    SSL_CTX_set_options(ctx, SSL_OP_ENCCERT_SECOND_POSITION);
    // 等待客户端连接
    printf("Server listening on port %d...\n", port);
    if ((client_sock = accept(sock, NULL, NULL)) < 0) {
        perror("Accept failed");
        goto err;
    }
    // 创建SSL对象并进行握手
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto err;
    }
    printf("SSL handshake completed\n");
    // 数据通信示例
    char buf[1024];
    bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes > 0) {
        printf("Received: %.*s\n", bytes, buf);
        SSL_write(ssl, "Hello Client!", 13);
    }
    // 清理资源
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
err:
    if (sock != -1)
        close(sock);
    if (ctx)
        SSL_CTX_free(ctx);
    return 0;
}