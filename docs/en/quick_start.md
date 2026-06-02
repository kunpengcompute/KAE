# Quick Start

## Introduction

This document describes how to use the source code to quickly install KAE 2.0 quickly and how to use the KAE encryption and decryption library and KAE compression library.

## Environment Preparation

1. Obtain the license.
    1. For details about how to apply for and install a license, see [Huawei Server iBMC License User Guide](https://support.huawei.com/enterprise/en/management-software/ibmc-pid-8060757?category=operation-maintenance).
    2. Run the **lspci** commands to check whether the OS has an accelerator device.

        ```shell
        lspci | grep HPRE
        lspci | grep SEC
        lspci | grep ZIP
        ```

        If no command output is displayed, no KAE accelerator device exists in the OS. Check whether the license has been installed.

2. Install OpenSSL.
    1. Check the OpenSSL version.

        ```shell
        openssl version
        ```

        The OpenSSL version must be 1.1.1x or 3.0.x, and the Tongsuo version must be 8.4.0. If not, install a compliant version.

    2. Set the OpenSSL environment variable **OPENSSL\_ENGINES** to the directory where the KAE dynamic library is stored so that OpenSSL can detect KAE.
        - OpenSSL 1.1.1x:

            ```shell
            export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
            ```

        - OpenSSL 3.0.x:

            ```shell
            export OPENSSL_ENGINES=/usr/local/lib/engines-3.0
            ```

        - Tongsuo:

            ```shell
            export OPENSSL_ENGINES=/usr/local/tongsuo/lib/engines-3.0
            ```

3. Set the **LD\_LIBRARY\_PATH** environment variable so that KAE can detect the UADK driver dynamic library.

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

4. Install environment dependencies.

    ```shell
    yum install -y make kernel-devel-`uname -r` libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath cmake libunwind-devel patch
    ```

5. Obtain the KAE 2.0 source package.

    ```shell
    git clone https://gitcode.com/boostkit/KAE.git -b kae2
    ```

6. Use the **build.sh** script in the source package to install all KAE 2.0 modules in one click.

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

## Testing the RSA Asynchronous Performance

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
