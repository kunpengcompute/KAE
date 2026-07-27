sh build.sh
sh build.sh clean

首次构建会自动下载并编译GoogleTest 1.11.0。脚本优先使用GoogleTest官方
GitHub release，官方地址不可达时会切换到Gitee镜像。也可以通过
`GTEST_DOWNLOAD_URL`指定其他可信下载地址。
