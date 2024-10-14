#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXBUF 1024  // 注意宏定义格式
void ShowCerts(SSL *ssl) {
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    printf("数字证书信息：\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("证书：%s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("颁发者：%s\n", line);
    free(line);
    X509_free(cert);
  } else
    printf("无证书信息！\n");
}

int main(int argc, char **argv) {
  int sockfd, len;
  struct sockaddr_in dest;
  char buffer[MAXBUF + 1];
  SSL_CTX *
      ctx;  // 定义两个结构体数据https://www.cnblogs.com/274914765qq/p/4513236.html
  SSL *ssl;
  if (argc != 3) {
    printf("please input correct parameter,just like:\n./a.out ipaddress port");
    exit(0);
  }
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  int ret;
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
  ENGINE *e = ENGINE_by_id("kae");
  if (e) {
          printf("engine kae set\n");
  } else {
          printf("engine kae not set\n");
          exit(1);
  }
  ENGINE_ctrl_cmd_string(e, "KAE_CMD_ENABLE_ASYNC", "1", 0);
  ENGINE_init(e);
  ret = ENGINE_set_default_ciphers(e);
  printf("engine ret = %d\n", ret);
  //ret = ENGINE_set_default_digests(e);
  //printf("engine ret = %d\n", ret);
  //ret = ENGINE_set_default_DH(e);
  //printf("engine ret = %d\n", ret);
  ctx = SSL_CTX_new(SSLv23_client_method());
//  ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-SM2-WITH-SMS4-SHA256");
  char *kae_tls = getenv("KAE_TLS");
  if (kae_tls) {
        ret = SSL_CTX_set_cipher_list(ctx, kae_tls);
        printf("engine ret = %s %d\n", kae_tls, ret);
  }
  if (ctx == NULL) {
    ERR_print_errors_fp(stdout);  //  将错误打印到FILE中
    exit(1);
  }
  // 创建socket用于tcp通信
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    exit(errno);
  }
  printf("socket created\n");
  memset(&dest, 0, sizeof(struct sockaddr_in));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(atoi(argv[2]));  // ascii to integer  字符串转化为整形数
  // inet_aton 将字符串IP地址转化为32位的网络序列地址
  if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0) {
    printf("error ");
    exit(errno);
  }
  printf("socket created");
  // 连接服务器
  if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
    perror("Connect ");
    exit(errno);
  }
  printf("server connected\n");

  // 基于ctx产生一个新的ssl,建立SSL连接
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);
  if (SSL_connect(ssl) == -1)
    ERR_print_errors_fp(stderr);
  else {
    printf("connect with %s encryption\n", SSL_get_cipher(ssl));
    ShowCerts(ssl);
  }
  bzero(buffer, MAXBUF + 1);
  fgets(buffer, MAXBUF + 1, stdin);
  len = SSL_write(ssl, buffer, strlen(buffer));
  if (len < 0)
    printf("memsage send failure");
  else
    printf("memsage '%s' send success\n", buffer);
  memset(buffer, 0, MAXBUF + 1);
  len = SSL_read(ssl, buffer, MAXBUF);
  if (len > 0)
    printf("receive '%s' successful!\n total %d bytes data\n", buffer, len);
  else {
    printf("receive data failure ,error reason:\n%d :%s ", errno,
           strerror(errno));
    goto finish;
  }
finish:
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sockfd);
  SSL_CTX_free(ctx);
  return 0;
}
