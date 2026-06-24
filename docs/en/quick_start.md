# Quick Start

## Introduction

The Kunpeng Accelerator Engine (KAE) is a hardware-based acceleration solution built on Kunpeng processors. It supports encryption, decryption, and decompression. The KAE encryption and decryption module accelerates Secure Sockets Layer (SSL) and Transport Layer Security (TLS) applications. The KAE decompression modules accelerate data compression and decompression, greatly reducing processor consumption and improving efficiency. In addition, KAE abstracts the internal processing details from the application layer. You can quickly migrate services by using the standard OpenSSL, Tongsuo, BoringSSL, zlib, zstd, and LZ4 interfaces.
Based on OpenSSL 1.1.1x, this document provides a one-click installation method using KAE source code to help you get started quickly with the KAE libraries.

## Prerequisites

- The system environment meets the requirements specified in [Environment Requirements](./installation_guide.md#environment-requirements) before installation.
- Determine whether the system requires a license before installation. For details, see [Obtaining the License](./installation_guide.md#obtaining-the-license).
- Run the **openssl version** command to check whether the OpenSSL version is 1.1.1x. If not, see [Installing OpenSSL/Tongsuo](./installation_guide.md#installing-openssltongsuo).
- Run the following command to install the required dependencies.

    ```shell
    yum install -y make kernel-devel-`uname -r` libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath cmake libunwind-devel patch
    ```

- Set the OpenSSL 1.1.1x environment variable **OPENSSL\_ENGINES** to the directory where the KAE dynamic library is stored so that OpenSSL can detect KAE.
    
    ```shell
    export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
    ```   

- Set the **LD\_LIBRARY\_PATH** environment variable so that KAE can detect the UADK driver dynamic library.

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

## Installation Procedure

If the OpenSSL version is 1.1.1x, one-click installation is supported. For more installation methods, see [Installation Guide](./installation_guide.md). The specific steps for the one-click installation method are as follows:

1. Use a remote login tool to log in to the Linux CLI as the **root** user.
2. Obtain the source package.

    ```shell
    git clone https://gitcode.com/boostkit/KAE.git -b kae2
    ```

3. Use the **build.sh** script in the source package to install all KAE modules in one click.

    ```shell
    cd KAE
    sh build.sh all
    ```

## Using the KAE Encryption and Decryption Library

The following uses the verification of RSA synchronous/asynchronous performance as an example. The test results of the OpenSSL software algorithm are compared to those of the KAE encryption and decryption library to show the performance improvement of the RSA algorithm before and after the KAE encryption and decryption library is used.

**Testing the RSA Synchronous Performance**

- Use the OpenSSL software algorithm to test the RSA synchronous performance.

    ```shell
    openssl speed -elapsed rsa2048
    ```

    Command output:

    ```text
    ...
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.001384s 0.000035s   724.1  28365.8.
    ```

- Use the KAE encryption and decryption library to test the RSA synchronous performance.

    ```shell
    openssl speed -elapsed -engine kae rsa2048
    ```

    Command output:

    ```text
    ....
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.000355s 0.000022s   2819.0  45478.4
    ```

After KAE encryption and decryption library is used, the RSA synchronous signing speed is improved from 724.1 signs/s to 2,819 signs/s.

**Testing the RSA Asynchronous Performance**

- Use the OpenSSL software algorithm to test the RSA asynchronous performance.

    ```shell
    openssl speed -elapsed -async_jobs 36 rsa2048 
    ```

    Command output:

    ```text
    ....
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.001318s 0.000032s    735.7  28555
    ```

- Use the KAE encryption and decryption library to test the RSA asynchronous performance.

    ```shell
    openssl speed -engine kae -elapsed -async_jobs 36 rsa2048 
    ```

    Command output:

    ```text
    .... 
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.000018s 0.000009s  54384.1 105317.0
    ```

    After KAE encryption and decryption library is used, the RSA asynchronous signing speed is improved from 735.7 signs/s to 54,384.1 signs/s.

## Using the KAE Compression Library

The KAEZlib compression library is used as an example. The compression and decompression performance of the KAEZlib compression library is compared with that of the built-in zlib library to show the performance improvement after the KAEZlib compression library is used.

1. Go to the performance test directory.

    ```shell
    cd KAEZlib/test/perftest
    ```

2. Compile the performance test tool.

    ```shell
    make
    ```

3. Generate an input file for the decompression performance test.

    ```shell
    ./zip_perf -f ../../../scripts/compressTestDataset/itemdata -o itemdata.zlib -m 1 -n 1
    ```

4. Test the compression performance.

    - Test the compression performance using the built-in ZIP library.

        ```shell
        ./zip_perf -m 8 -l 10240 -n 1000
        ```

        Command output:

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

    - Test the compression performance using the KAEZlib library.

        ```shell
        ./kaezip_perf -m 8 -l 10240 -n 1000
        ```

        Command output:

        ```text
        kaezip perf parameter: multi process 8, stream length: 10240(KB), loop times: 1000
        kaezip compress perf result:
             time used: 10631524 us, speed = 7.348 GB/s
        ```

    It shows that the compression speed rises from 0.305 GB/s to 7.348 GB/s.

5. Test the decompression performance.

    - Test the decompression performance using the built-in ZIP library.

        ```shell
        ./zip_perf -d -m 8 -f itemdata.zlib -n 1000
        ```

        Command output:

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

    - Test the decompression performance using the KAEZlib library.

        ```shell
        ./kaezip_perf -d -m 8 -f itemdata.zlib -n 1000
        ```

        Command output:

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

    It shows that the decompression speed rises from 1.482 GB/s to 9.422 GB/s.
