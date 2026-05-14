# 快速入门

## 简介

KAE（Kunpeng Accelerator Engine，鲲鹏加速引擎）是基于鲲鹏处理器提供的硬件加速解决方案，包含了KAE加解密和KAE解压缩。KAE加解密用于加速SSL（Secure Sockets Layer）/TLS（Transport Layer Security）应用，KAE解压缩用于加速数据压缩、解压，可以显著降低处理器消耗，提高处理器效率。此外，加速引擎对应用层屏蔽了其内部实现细节，用户通过OpenSSL、Tongsuo、BoringSSL、Zlib、ZSTD、LZ4标准接口即可实现快速迁移现有业务。  
本文基于OpenSSL 1.1.1x版本，提供基于KAE源码的一键安装方式，指导用户快速上手使用KAE加解密库和KAE压缩库。

## 前提条件

- 安装前系统环境已满足[环境要求](./installation_guide.md/#环境要求)中的要求。
- 安装前判断系统是否需要申请License，具体请参考[获取License](./installation_guide.md/#获取license)。
- 使用openssl version命令检查OpenSSL是否为1.1.1x版本，若不符合请参见[安装OpenSSL/Tongsuo](./installation_guide.md/#安装openssltongsuo)。
- 使用以下命令安装相关依赖。

    ```shell
    yum install -y make kernel-devel-`uname -r` libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath cmake libunwind-devel patch
    ```

- 设置OpenSSL 1.1.1x环境变量“OPENSSL\_ENGINES”为KAE动态库所在目录，使OpenSSL能够识别到KAE引擎。
    
    ```shell
    export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
    ```   

- 设置LD\_LIBRARY\_PATH环境变量，使KAE能够识别到UADK驱动动态库。

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

## 安装步骤

当OpenSSL为1.1.1x系列，我们支持一键安装。如果需要了解更多的安装方式，请参考[安装指南](./installation_guide.md)。下面给出一键安装的具体步骤。

1. 使用远程登录工具，以root账号进入Linux操作系统命令行界面。
2. 获取源码包。

    ```shell
    git clone https://gitcode.com/boostkit/KAE.git -b kae2
    ```

3. 使用源码包中的build.sh脚本一键安装KAE所有模块。

    ```shell
    cd KAE
    sh build.sh all
    ```

## 使用KAE加解密库

以验证RSA同步/异步模式性能为例。通过与OpenSSL的软算算法测试结果进行对比，展示使用KAE加解密库前后的RSA算法的性能提升效果。

**RSA同步性能测试**

- 使用OpenSSL的软件算法测试RSA同步性能。

    ```shell
    openssl speed -elapsed rsa2048
    ```

    显示结果如下。

    ```text
    ...
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.001384s 0.000035s   724.1  28365.8.
    ```

- 使用KAE加解密库测试RSA同步性能。

    ```shell
    openssl speed -elapsed -engine kae rsa2048
    ```

    显示结果如下。

    ```text
    ....
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.000355s 0.000022s   2819.0  45478.4
    ```

使用KAE加解密库加速后RSA同步签名性能从724.1sign/s提升到2819sign/s。

**RSA异步性能测试**

- 使用OpenSSL的软件算法测试RSA异步性能。

    ```shell
    openssl speed -elapsed -async_jobs 36 rsa2048 
    ```

    显示结果如下。

    ```text
    ....
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.001318s 0.000032s    735.7  28555
    ```

- 使用KAE加解密库测试RSA异步性能。

    ```shell
    openssl speed -engine kae -elapsed -async_jobs 36 rsa2048 
    ```

    显示结果如下。

    ```text
    .... 
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.000018s 0.000009s  54384.1 105317.0
    ```

    使用KAE加解密库加速后RSA异步签名性能从735.7sign/s提升到54384.1sign/s。

## 使用KAE压缩库

以KAEZlib压缩库为例，通过与系统自带的zlib库的解压缩性能进行对比，展示使用KAEZlib压缩库前后的性能提升效果。

1. 进入性能测试目录。

    ```shell
    cd KAEZlib/test/perftest
    ```

2. 编译性能测试工具。

    ```shell
    make
    ```

3. 生成解压缩性能测试的输入文件。

    ```shell
    ./zip_perf -f ../../../scripts/compressTestDataset/itemdata -o itemdata.zlib -m 1 -n 1
    ```

4. 测试压缩性能。

    - 使用系统自带zip库测试压缩性能。

        ```shell
        ./zip_perf -m 8 -l 10240 -n 1000
        ```

        显示结果如下。

        ```text
        kaezip perf parameter: multi process 8, stream length: 10240(KB), loop times: 1000, windowBits : 15, level : 6
        input_size is 10485760B
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        compress_size is 10488786B = 10.003MB, compress_rate is 100.029%
        kaezip compress perf result:
             time used: 256539951 us, speed = 0.305 GB/s
        ```

    - 使用KAEZlib压缩库测试压缩性能。

        ```shell
        ./kaezip_perf -m 8 -l 10240 -n 1000
        ```

        显示结果如下。

        ```text
        kaezip perf parameter: multi process 8, stream length: 10240(KB), loop times: 1000
        kaezip compress perf result:
             time used: 10631524 us, speed = 7.348 GB/s
        ```

    可以看到压缩速度从0.305GB/s提升到了7.348GB/s。

5. 测试解压缩性能。

    - 使用系统自带zip库测试解压缩性能。

        ```shell
        ./zip_perf -d -m 8 -f itemdata.zlib -n 1000
        ```

        显示结果如下。

        ```text
        kaezip perf parameter: multi process 8, stream length: 1024(KB), loop times: 1000, windowBits : 15, level : 6
        g_kae_device_num 2
        uncompress filename : itemdata.zlib
        input_size is 3539153B
        [169064]uncompress_size is 7316868B = 6.978MB
        [169063]uncompress_size is 7316868B = 6.978MB
        [169061]uncompress_size is 7316868B = 6.978MB
        [169062]uncompress_size is 7316868B = 6.978MB
        [169060]uncompress_size is 7316868B = 6.978MB
        [169058]uncompress_size is 7316868B = 6.978MB
        [169059]uncompress_size is 7316868B = 6.978MB
        [169065]uncompress_size is 7316868B = 6.978MB
        8 multi process kaezip decompress perf result:
                 time used: 36786657 us, speed = 1.482 GB/s
        ```

    - 使用KAEZlib压缩库测试解压缩性能。

        ```shell
        ./kaezip_perf -d -m 8 -f itemdata.zlib -n 1000
        ```

        显示结果如下。

        ```text
        kaezip perf parameter: multi process 8, stream length: 1024(KB), loop times: 1000, windowBits : 15, level : 6
        g_kae_device_num 2
        uncompress filename : itemdata.zlib
        input_size is 3539153B
        [168826]uncompress_size is 7316868B = 6.978MB
        [168825]uncompress_size is 7316868B = 6.978MB
        [168830]uncompress_size is 7316868B = 6.978MB
        [168827]uncompress_size is 7316868B = 6.978MB
        [168823]uncompress_size is 7316868B = 6.978MB
        [168829]uncompress_size is 7316868B = 6.978MB
        [168828]uncompress_size is 7316868B = 6.978MB
        [168824]uncompress_size is 7316868B = 6.978MB
        8 multi process kaezip decompress perf result:
                 time used: 5785818 us, speed = 9.422 GB/s
        ```

    可以看到解压缩速度从1.482GB/s提升到了9.422GB/s。
