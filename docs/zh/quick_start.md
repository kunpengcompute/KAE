# 快速入门

## 简介**

本指南通过源码方式快速安装KAE2.0，指导用户快速上手使用KAE加解密库和KAE压缩库。

## 环境准备**

1. 获取License。
    1. License申请和安装操作请参见《[华为服务器iBMC许可证 使用指导](https://support.huawei.com/enterprise/zh/management-software/ibmc-pid-8060757?category=operation-maintenance)》。
    2. 安装成功后，通过**lspci**命令查看操作系统是否有加速器设备。

        ```shell
        lspci | grep HPRE
        lspci | grep SEC
        lspci | grep ZIP
        ```

        若执行以上命令后没有任何回显信息打印，说明操作系统中没有KAE加速器设备，请检查License是否安装成功。

2. 安装OpenSSL。

    1. 检查OpenSSL版本。

        ```shell
        openssl version
        ```

        OpenSSL需为1.1.1x或3.0.x系列版本，Tongsuo 8.4.0版本。若不符合，需先安装合规版本。

    2. 设置OpenSSL环境变量“OPENSSL\_ENGINES”为KAE动态库所在目录，使OpenSSL能够识别到KAE引擎。
        - OpenSSL 1.1.1x系列：

            ```shell
            export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
            ```

        - OpenSSL 3.0.x系列：

            ```shell
            export OPENSSL_ENGINES=/usr/local/lib/engines-3.0
            ```

        - Tongsuo：

            ```shell
            export OPENSSL_ENGINES=/usr/local/tongsuo/lib/engines-3.0
            ```

3. 设置LD\_LIBRARY\_PATH环境变量，使KAE能够识别到UADK驱动动态库。

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

4. 安装环境依赖。

    ```shell
    yum install -y make kernel-devel-`uname -r` libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath cmake libunwind-devel patch
    ```

5. 获取KAE2.0源码包。

    ```shell
    git clone https://gitcode.com/boostkit/KAE.git -b kae2
    ```

6. 使用源码包中的build.sh脚本一键安装KAE2.0所有模块。

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
