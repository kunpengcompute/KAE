// 客户端代码
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
    int bytes;
    int sock = -1;
    struct sockaddr_in addr;
    const char *sign_cert_file = "CS.crt";
    const char *sign_key_file = "CS.key";
    const char *enc_cert_file = "CE.crt";
    const char *enc_key_file = "CE.key";
    const char *server_ip = "127.0.0.1";
    const int port = 4433;
    // 初始化OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    // 创建TCP套接字并连接
    sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("Connection failed");
        goto err;
    }
    // 创建SSL上下文
    if (!(ctx = SSL_CTX_new(TLCP_client_method()))) {
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
    // 设置密码套件
    if (SSL_CTX_set_cipher_list(ctx, "ECC-SM4-CBC-SM3:ECDHE-SM4-CBC-SM3") <= 0) {
        ERR_print_errors_fp(stderr);
        goto err;
    }
    // 创建SSL对象并进行握手
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto err;
    }
    printf("SSL handshake completed\n");
    // 数据通信示例
    SSL_write(ssl, "Hello Server!", 13);
    char buf[1024];
    bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes > 0)
        printf("Received: %.*s\n", bytes, buf);
    // 清理资源
    SSL_shutdown(ssl);
    SSL_free(ssl);
err:
    if (sock != -1)
        close(sock);
    if (ctx)
        SSL_CTX_free(ctx);
    return 0;
}