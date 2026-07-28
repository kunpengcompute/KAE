# KAEZlib GTest说明

## 构建

```sh
sh build.sh
sh build.sh clean
```

首次构建会自动下载并编译GoogleTest 1.11.0。脚本优先使用GoogleTest官方
GitHub release，官方地址不可达时会切换到Gitee镜像。也可以通过
`GTEST_DOWNLOAD_URL`指定其他可信下载地址。

下载默认使用系统CA信任库验证TLS证书。如果内网通过企业CA代理HTTPS，
请将企业根证书安装到系统信任库，或通过`GTEST_CA_CERT`指定证书文件：

```sh
GTEST_CA_CERT=/path/to/internal-root-ca.pem sh build.sh
```

使用内网制品镜像时，可以同时指定下载地址和企业CA证书：

```sh
GTEST_DOWNLOAD_URL=https://mirror.example.com/googletest-release-1.11.0.zip \
GTEST_CA_CERT=/path/to/internal-root-ca.pem \
sh build.sh
```
