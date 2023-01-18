### 一、准备目录结构以及所需文件
1. **进入操作系统（例如：OpenEuler20.03），在/home下构建出包目录结构**
- 将scripts/package目录下对应操作系统文件夹（比如：OpenEuler20.03文件夹）复制到操作系统的/home目录下并重命名为taishan
- .spec后缀的文件为出包文件，执行出包的脚本在build目录下
- output目录下存放打包完成之后的\*.rpm包
2. **执行codedownload脚本，自动下载kae源码到hisi_acc目录下；或者也可以手动下载源码复制到hisi_acc目录下即可**
3. **需要单独下载zlib-1.2.13.tar.gz包到taishan目录下，下载地址：https://www.zlib.net/zlib.html**

### 二、编译出包
1. **taishan_spec/build/下面存放编译脚本，此目录执行build.sh脚本编译代码。**
2. **taishan_spec/output/下面存放编译出来的包。**