<!--Metadata
targetUser:"开发工程师、测试工程师等开发者"
keywords:"KAE,鲲鹏加速引擎,硬件加速引擎,快速入门,KAE2.0"
searchTitle:"如何使用KAE,KAE快速入门,KAE测试用例"
status:"stable"
-->
  
# 快速入门

本文基于鲲鹏920处理器和OpenSSL 1.1.1x版本，介绍KAE2.0的源码一键安装方式。一键安装将自动安装`KAEKernelDriver`、`UADK框架`、`KAEOpensslEngine`和`KAEZlib`组件，指导用户快速上手使用基于OpenSSL的KAE加解密库和KAEZlib压缩库。

## 特性简介

KAE（Kunpeng Accelerator Engine，鲲鹏加速引擎）是基于鲲鹏处理器提供的硬件加速解决方案，包含了KAE加解密和KAE解压缩。KAE加解密用于加速SSL（Secure Sockets Layer）/TLS（Transport Layer Security）应用，KAE解压缩用于加速数据压缩、解压缩，可以显著降低处理器消耗，提高处理器效率。此外，加速引擎对应用层屏蔽了其内部实现细节，用户通过OpenSSL、Tongsuo、BoringSSL、Zlib等标准接口即可实现快速迁移现有业务，为分布式存储、Web服务、数据库等场景提供高性能、低成本的加速方案，助力企业提升业务效率、降低成本并保障安全合规。

>![](public_sys-resources/icon-note.gif) **须知：**
>
> - 鲲鹏920处理器只支持KAEZlib库（提供Gzip和Zlib格式），本文只给出KAE加解密和KAEZlib的压缩库的快速入门。
> - 鲲鹏920新型号处理器和鲲鹏950处理器支持更多的KAE加解密和KAE压缩库，请参考《README》的[算法支持与规格](./../../README.md#算法支持与规格)选择合适的算法。

## 环境部署

- 安装前请确保使用的环境满足KAE支持的环境配套信息，具体请参考《安装指南》[环境要求](./installation_guide.md#环境要求)。
- 安装前需要获取License，判断系统是否需要申请License，具体请参考《安装指南》[获取License](./installation_guide.md#获取license)。
- 使用`openssl version`命令检查OpenSSL是否为1.1.1x版本，若不符合请参考《安装指南》[安装OpenSSL/Tongsuo](./installation_guide.md#安装openssltongsuo)安装对应版本的OpenSSL。

    ```bash
    openssl version
    ```

    显示如下格式内容即为版本正确（以OpenSSL 1.1.1a为例）。

    ```output
    OpenSSL 1.1.1a 20 Nov 2018 
    ```

- 使用以下命令安装相关依赖。

    ```bash
    yum install -y make kernel-devel-`uname -r` libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath cmake libunwind-devel patch
    ```

- 设置环境变量。
    - 设置OpenSSL 1.1.1x环境变量`OPENSSL_ENGINES`为KAE动态库所在目录，使OpenSSL能够识别到KAE引擎。
        
        ```bash
        export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
        ```   

    - 设置`LD_LIBRARY_PATH`环境变量，使KAE能够识别到UADK驱动动态库。

        ```bash
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
        ```

## 源码安装KAE

当OpenSSL为1.1.1x系列时，我们支持基于源码的一键安装。如果需要了解更多的安装方式，请参考[《安装指南》](./installation_guide.md)。下面给出一键安装的具体步骤。

1. 使用远程登录工具，以root账号进入Linux操作系统命令行界面。
2. 获取KAE 2.0源码包，其分支名是`kae2`。假设KAE安装到`/root`目录下，其中`KAE_PATH`表示KAE的绝对路径。

    ```bash
    cd /root/
    git clone https://gitcode.com/boostkit/KAE.git -b kae2
    KAE_PATH=/root/KAE
    ```

3. 进入KAE目录，使用源码包中的`build.sh`脚本一键安装KAE所有模块。

    ```bash
    cd $KAE_PATH
    sh build.sh all
    ```

4. 安装后验证。
    1. 查看KAEKernelDriver（KAE Kernel Driver，KAE内核驱动）是否安装成功。

        ```bash
        lsmod | grep hisi_qm
        ```

        回显信息如下，表示驱动安装成功。

        ```output
        hisi_qm               262144  3 hisi_sec2,hisi_zip,hisi_hpre
        uacce                 262144  1 hisi_qm
        ```
    
    2. 查看UADK（User Space Accelerator Development Kit，用户空间加速器开发套件）是否安装成功。

        ```bash
        ll /usr/local/lib/libwd*
        ```

        回显信息如下，表示安装成功。

        ```output
        -rwxr-xr-x. 1 root root     961 Aug 22 17:23 /usr/local/lib/libwd_comp.la
        lrwxrwxrwx. 1 root root      19 Aug 22 17:23 /usr/local/lib/libwd_comp.so -> libwd_comp.so.2.5.0
        lrwxrwxrwx. 1 root root      19 Aug 22 17:23 /usr/local/lib/libwd_comp.so.2 -> libwd_comp.so.2.5.0
        -rwxr-xr-x. 1 root root  377872 Aug 22 17:23 /usr/local/lib/libwd_comp.so.2.5.0
        -rwxr-xr-x. 1 root root     973 Aug 22 17:23 /usr/local/lib/libwd_crypto.la
        lrwxrwxrwx. 1 root root      21 Aug 22 17:23 /usr/local/lib/libwd_crypto.so -> libwd_crypto.so.2.5.0
        lrwxrwxrwx. 1 root root      21 Aug 22 17:23 /usr/local/lib/libwd_crypto.so.2 -> libwd_crypto.so.2.5.0
        -rwxr-xr-x. 1 root root  715616 Aug 22 17:23 /usr/local/lib/libwd_crypto.so.2.5.0
        -rwxr-xr-x. 1 root root     907 Aug 22 17:23 /usr/local/lib/libwd.la
        lrwxrwxrwx. 1 root root      14 Aug 22 17:23 /usr/local/lib/libwd.so -> libwd.so.2.5.0
        lrwxrwxrwx. 1 root root      14 Aug 22 17:23 /usr/local/lib/libwd.so.2 -> libwd.so.2.5.0
        -rwxr-xr-x. 1 root root 1342080 Aug 22 17:23 /usr/local/lib/libwd.so.2.5.0

    3. 查看KAE硬件加速引擎是否安装成功。

        ```bash
        ll /usr/local/lib/engines-1.1
        ```
        
        回显信息如下，显示KAE的静态库和动态库，表示安装成功。

        ```output
        total 5644
        -rw-r--r--. 1 root root 3846524 Aug 22 17:28 kae.a
        -rwxr-xr-x. 1 root root     995 Aug 22 17:28 kae.la
        lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so -> kae.so.2.0.0
        lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so.2 -> kae.so.2.0.0
        -rwxr-xr-x. 1 root root 1967736 Aug 22 17:28 kae.so.2.0.0
        ```

    4. 查看zlib加速压缩库是否安装成功。

        ```bash
        ll /usr/local/kaezip/lib/
        ```

        回显信息如下所示，表示安装成功。

        ```output
        lrwxrwxrwx. 1 root root     40 Aug 29 10:20 libkaezip.so -> /usr/local/kaezip/lib/libkaezip.so.2.0.0
        lrwxrwxrwx. 1 root root     40 Aug 29 10:20 libkaezip.so.0 -> /usr/local/kaezip/lib/libkaezip.so.2.0.0
        -rwxr-xr-x. 1 root root 148096 Aug 29 10:20 libkaezip.so.2.0.0
        -rw-r--r--. 1 root root 145674 Aug 29 10:20 libz.a
        lrwxrwxrwx. 1 root root     14 Aug 29 10:20 libz.so -> libz.so.1.2.11
        lrwxrwxrwx. 1 root root     14 Aug 29 10:20 libz.so.1 -> libz.so.1.2.11
        -rwxr-xr-x. 1 root root 144784 Aug 29 10:20 libz.so.1.2.11
        drwxr-xr-x. 2 root root   4096 Aug 29 10:20 pkgconfig
        ```

    5. 查看KAEGzip解压缩工具是否安装成功。

        ```bash
        ldd /usr/local/kaegzip/gzip
        ```

        回显信息如下所示，表示安装成功。

        ```output        
        linux-vdso.so.1 (0x0000ffff7fbc1000)
        libz.so.1 => /usr/local/kaezip/lib/libz.so.1 (0x0000ffff7fb50000)
        libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff7fae0000)
        libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffff7fa90000)
        libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff7f8e0000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffff7fb84000)
        libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff7f8a0000)
        libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff7f870000)
        ```

## 使用KAE加解密库

本文以验证RSA同步/异步模式性能为例，通过与OpenSSL的软件算法测试结果进行对比，展示使用KAE加解密库前后的RSA算法的性能提升效果。
  
### RSA同步性能测试

- 使用OpenSSL的软件算法测试RSA同步性能。

    ```bash
    openssl speed -elapsed rsa2048
    ```

    显示结果如下。

    ```output
    ...
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.001384s 0.000035s   724.1  28365.8.
    ```

- 使用KAE加解密库测试RSA同步性能。

    ```bash
    openssl speed -elapsed -engine kae rsa2048
    ```

    显示结果如下。

    ```output
    ...
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.000355s 0.000022s   2819.0  45478.4
    ```

使用KAE加解密库加速后RSA同步签名性能从**724.1sign/s**提升到**2819sign/s**。

### RSA异步性能测试

- 使用OpenSSL的软件算法测试RSA异步性能。

    ```bash
    openssl speed -elapsed -async_jobs 36 rsa2048
    ```

    显示结果如下。

    ```output
    ...
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.001318s 0.000032s    735.7  28555
    ```

- 使用KAE加解密库测试RSA异步性能。

    ```bash
    openssl speed -engine kae -elapsed -async_jobs 36 rsa2048
    ```

    显示结果如下。

    ```output
    ...
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.000018s 0.000009s  54384.1 105317.0
    ```

    使用KAE加解密库加速后RSA异步签名性能从**735.7sign/s**提升到**54384.1sign/s**。

## 使用KAE压缩库

以KAEZlib压缩库为例，通过与系统自带zlib库的解压缩性能进行对比，展示使用KAEZlib压缩库前后的性能提升效果。
    
1. 进入性能测试目录。

    ```bash    
    cd $KAE_PATH/KAEZlib/test/perftest
    ```

2. 编译性能测试工具，生成`zip_perf`和`kaezip_perf`。

    ```bash
    make
    ```

3. 生成解压缩性能测试的输入文件。

    ```bash
    ./zip_perf -f ../../../scripts/compressTestDataset/itemdata -o itemdata.zlib -m 1 -n 1
    ```

4. 测试压缩性能。

    - 使用系统自带zip库测试压缩性能。

        ```bash
        ./zip_perf -m 8 -l 10240 -n 1000
        ```

        显示结果如下。

        ```output
        kaezip perf parameter: multi process 8, stream length: 10240(KB), loop times: 1000, windowBits : 15, level : 6
        input_size is 10485760B
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        ...
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        kaezip compress perf result:
             time used: 256539951 us, speed = 0.305 GB/s
        ```

    - 使用KAEZlib压缩库测试压缩性能。

        ```bash
        ./kaezip_perf -m 8 -l 10240 -n 1000
        ```

        显示结果如下。

        ```output
        kaezip perf parameter: multi process 8, stream length: 10240(KB), loop times: 1000
        kaezip compress perf result:
             time used: 10631524 us, speed = 7.348 GB/s
        ```

    可以看到压缩速度从**0.305GB/s**提升到了**7.348GB/s**。

5. 测试解压缩性能。

    - 使用系统自带zip库测试解压缩性能。

        ```bash
        ./zip_perf -d -m 8 -f itemdata.zlib -n 1000
        ```

        显示结果如下。

        ```output
        kaezip perf parameter: multi process 8, stream length: 1024(KB), loop times: 1000, windowBits : 15, level : 6
        g_kae_device_num 2
        uncompress filename : itemdata.zlib
        input_size is 3539153B
        [169064]uncompress_size is 7316868B = 6.978MB
        ...
        [169065]uncompress_size is 7316868B = 6.978MB
        8 multi process kaezip decompress perf result:
                 time used: 36786657 us, speed = 1.482 GB/s
        ```

    - 使用KAEZlib压缩库测试解压缩性能。

        ```bash
        ./kaezip_perf -d -m 8 -f itemdata.zlib -n 1000
        ```

        显示结果如下。

        ```output
        kaezip perf parameter: multi process 8, stream length: 1024(KB), loop times: 1000, windowBits : 15, level : 6
        g_kae_device_num 2
        uncompress filename : itemdata.zlib
        input_size is 3539153B
        [168826]uncompress_size is 7316868B = 6.978MB
        ...
        [168824]uncompress_size is 7316868B = 6.978MB
        8 multi process kaezip decompress perf result:
                 time used: 5785818 us, speed = 9.422 GB/s
        ```

    可以看到解压缩速度从**1.482GB/s**提升到了**9.422GB/s**。

## 更多功能

如果你想了解更多的KAE加解密库和KAE压缩库使用样例，请参考《用户指南》的[使用KAE加解密库](./user_guide.md#使用kae加解密库)和[使用KAE压缩库](./user_guide.md#使用kae压缩库)的内容。
如果你想了解KAE常见问题和故障案例，请参考[《常见问题和故障案例》](./faq.md)。

## 修订记录

|文档版本|发布日期|修改说明|
|---|---|---|
|02|2026-09-10| 第二次正式发布。<br>文档优化：补充摘要、缩略语、修订记录、更多功能等内容，优化特性简介、环境部署、源码安装KAE、使用KAE加解密库、使用KAE压缩库等章节描述。|
|01|2026-06-30| 第一次正式发布。<br>文档内容继承上个版本未进行修改，跟随鲲鹏BoostKit 26.1.RC1版本发布文档。|
