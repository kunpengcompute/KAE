# Installation Guide

## Environment Deployment

### Environment Requirements

Before the installation, ensure that the environment meets the verified requirements for hardware and software supported by KAE.

**Hardware Requirements<a name="section1158372015342"></a>**

**Table 1** Hardware requirements<a id="hardware-requirements"></a>

|Item|Description|
|--|--|
|Server|Kunpeng server (with KAE enabled)<sup>a</sup>|
|Processor|Kunpeng 920 processors, new Kunpeng 920 processor model<sup>b</sup>, or Kunpeng 950 processors<sup>c</sup>|
|iBMC|V365 or later|
|BIOS|V105 or later|

>![](public_sys-resources/icon-note.gif) **NOTE**<br>
>a: To use the accelerator in the non-virtualization scenario, you need to disable SMMU. Enabling the SMMU will affect the accelerator performance. For details, see [BIOS Parameter Reference (Kunpeng 920 Processor)](https://support.huawei.com/enterprise/en/doc/EDOC1100088647/426cffd9/about-this-document).<br>
>b: KAEZstd, KAELz4, and KAESnappy can only be used on the new Kunpeng 920 processor model and Kunpeng 950 processors. Encryption and compression algorithms vary with processor models. For details, see [README_EN](../../README_EN.md#supported-algorithms-and-specifications).<br>
>c: Kunpeng 950 processors support only KAE 2.0.

**Obtaining and Verifying Software Packages<a name="section1796432494313"></a>**

**Table 2** Obtaining and verifying KAE software packages<a id="obtaining-and-verifying-software-packages"></a>

|Package Type|Applicable OS|Applicable OpenSSL Version|How to Obtain|
|--|--|--|--|
|Source package|openEuler 22.03 LTS SP1/SP2/SP3/SP4aEulerOS-V2.0 SP12, and TencentOS 5.4|OpenSSL 1.1.1x, OpenSSL 3.0.x, Tongsuo 8.4.0, and BoringSSL|[Link](https://gitcode.com/boostkit/KAE)|
|RPM package|openEuler 22.03 LTS SP1/SP2/SP3/SP4a|OpenSSL 1.1.1x|[Link](https://gitcode.com/boostkit/KAE/releases) (If the KAE code repository does not contain the RPM package for the corresponding OS, create an RPM package by referring to Method 2: Creating an RPM Package.)|

>![](public_sys-resources/icon-note.gif) **NOTE**
>a: openEuler 22.03 LTS SP1 supports only KAE v2.0.3 and earlier versions.
>Note: You can obtain the software packages of earlier versions from [Release](https://gitcode.com/boostkit/KAE/releases). The name of each RPM package contains its corresponding OS version. Select a proper package based on the actual OS version in use. For example, **openeuler22.03\_sp1.zip** is the RPM installation package for openEuler 22.03 LTS SP1.

**Other Requirements<a name="section0733155717512"></a>**

- An SSH remote login tool has been installed on the local PC.
- The root account is required for KAE installation.
- Both root and non-root accounts can run KAE.

### Obtaining the License

Before the installation, ensure that the environment meets the hardware and software requirements of KAE and a license has been correctly installed. The OS can detect the accelerator devices only after the license has been installed.

>![](public_sys-resources/icon-note.gif) **NOTE**
>
>- KAE is enabled by default on Kunpeng K series servers. You do not need to apply for a license.
>- The new Kunpeng 920 processor model can use KAE without a license after the BIOS is upgraded to 21.23 or later.

1. For details about how to apply for and install a license, see [Huawei Server iBMC License User Guide](https://support.huawei.com/enterprise/en/management-software/ibmc-pid-8060757?category=operation-maintenance).
2. Run the **lspci** command to check whether the OS has an accelerator device.

    >![](public_sys-resources/icon-note.gif) **NOTE**
    >The accelerator description returned by the **lspci** command varies depending on the OS. In addition to filtering by keywords, you can also check whether the HPRE/SEC/ZIP accelerator SBDF information exists.

    1. Check whether the high-performance RSA accelerator engine HPRE exists in the system.

        ```shell
        lspci | grep HPRE
        ```

        If the following information is displayed, HPRE exists in the OS:

        ```text
        79:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)
        b9:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)
        ```

    2. Check for the Security Engine (SEC).

        ```shell
        lspci | grep SEC
        ```

        If the following information is displayed, SEC exists in the OS:

        ```text
        76:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
        b6:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
        ```

    3. Check for the ZIP compression acceleration engine.

        ```shell
        lspci | grep ZIP
        ```

        If the following information is displayed, ZIP exists in the OS:

        ```text
        75:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)
        b5:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)
        ```

    If no command output is displayed, no KAE accelerator device exists in the OS. Check whether the license has been installed.

### Installing OpenSSL/Tongsuo

The KAE encryption and decryption module relies on OpenSSL. Before installing and using this module, install OpenSSL. OpenSSL 1.1.1x or 3.0.x, or Tongsuo 8.4.0 must be used.

>![](public_sys-resources/icon-notice.gif) **NOTICE**
>If you do not want to use the default OpenSSL/Tongsuo, specify the installation path during OpenSSL/Tongsuo installation and enter the path in the steps in [Installation Using the Source Code](#installation-using-the-source-code).

**Prerequisites<a name="en-us_topic_0200576865_section17733210143520"></a>**

- The **kernel-devel** package matching your OS version has been installed.

    Query the current kernel version.

    ```shell
    uname -r
    ```

- Perl and bzip2 have been installed.

    Query Perl and bzip2 versions.

    ```shell
    perl --version
    bzip2 --version
    ```

- The GCC and Make tools have been installed. The performance varies depending on the GCC version. Recommended versions are GCC 7.4.1 or later and Make 3.82 or later.

    Query GCC and Make versions.

    ```shell
    gcc --version
    make --version
    ```

- Automake, Autoconf, and libtool have been installed.

    Query Automake, Autoconf, and libtool versions.

    ```shell
    automake --version
    autoconf --version
    libtool --version
    ```

For software that has not been installed, use the command-line tool of the OS to install it. For example, use Yum for CentOS/EulerOS/openEuler and Zypper for SUSE.

**Installation Procedure<a name="section1426493710530"></a>**

>![](public_sys-resources/icon-notice.gif) **NOTICE**
>Run the **openssl version** command to query the OpenSSL/Tongsuo version. If the OpenSSL version is 1.1.1x or 3.0.x, or the Tongsuo version is 8.4.0, you can skip the following OpenSSL/Tongsuo installation steps.

1. Use SSH to copy the OpenSSL/Tongsuo source package to a custom directory.

    Download the OpenSSL source code package: [1.1.1x](https://openssl-library.org/source/old/1.1.1/index.html), [3.0.x](https://openssl-library.org/source/old/3.0/index.html), or [Tongsuo 8.4.0](https://github.com/Tongsuo-Project/Tongsuo/tags).

    >![](public_sys-resources/icon-note.gif) **NOTE**
    >If Tongsuo calls a custom engine by running the **speed** command, related resources cannot be released after the encryption and decryption tasks are complete, and a segmentation fault is reported. An [issue](https://github.com/Tongsuo-Project/Tongsuo/issues/688) has been submitted to the upstream community for tracking. Before using Tongsuo, you need to apply the patch and then compile it.

2. Compile and install OpenSSL/Tongsuo in the OpenSSL/Tongsuo source code directory.

    If the installed OpenSSL/Tongsuo version is different from the default OpenSSL version of the OS, you are advised to specify another directory, for example, **/usr/local/ssl3\_0\_14**, to prevent version conflicts.

    - Use the default installation directory **/usr/local**.

        ```shell
        ./config
        ```

    - Specify another installation path.
        - OpenSSL

            ```shell
            ./config --prefix=/usr/local/ssl1_1_1a
            ```

        - Tongsuo

            ```shell
            ./config --prefix=/opt/tongsuo
            ```

    >![](public_sys-resources/icon-note.gif) **NOTE**
    >This step automatically generates a Makefile based on the compilation platform and environment. You can use **./config --prefix** to specify the installation path and use **-Wl** and **-rpath** to specify the paths to the libcrypto and libssl libraries that OpenSSL depends on.

    ```shell
    make
    make install
    ```

    OpenSSL/Tongsuo is installed in **/usr/local** by default. For details, see *README* in the source code directory.

**Verifying the Installation<a name="section17265037195318"></a>**

- Set the **PATH** environment variable to enable the global use of the **openssl** command.

    ```shell
    export PATH=/usr/local/bin:$PATH
    ```

- Check the OpenSSL version.

    ```shell
    openssl version
    ```

    If the following information is displayed, the installation is complete (OpenSSL 1.1.1a is used as an example):

    ```text
    OpenSSL 1.1.1a 20 Nov 2018 
    ```

## Installation Methods

KAE 2.0 supports installation using the source code and RPM packages. Select an appropriate installation method based on the OS.

**Table 1** Installation methods and OSs supported by KAE 2.0<a id="installation-methods-and-OSs-supported-by-KAE-2.0"></a>

|Installation Method|Description|Supported OS|Advantage and Disadvantage|
|--|--|--|--|
|Installation using the source code|Run the **build.sh** script to install KAE.|openEuler 22.03 LTS-SP1/SP2/SP3/SP4EulerOS-V2.0 SP12TencentOS 5.4|Advantage: The source code can be modified for compilation and installation. Disadvantage: The operation is complex and extra configuration is required.|
|Installation using RPM packages|To facilitate user operations, Huawei provides RPM installation packages for some commercial OSs.|openEuler 22.03 LTS-SP1/SP2/SP3/SP4EulerOS-V2.0 SP12|Advantage: After installation, you can use the KAE software without compiling the source code. Disadvantage: Only certain OSs are supported.|

## Installation Using the Source Code

The KAE 2.0 source code package contains the KAE kernel driver, UADK framework, KAEOpensslEngine, KAEZstd, KAELz4, and KAEZlib. The KAE kernel driver and UADK are mandatory, and the other modules are optional. To upgrade KAE, uninstall the old version and then install the new version.

**Prerequisites<a name="section14710172717351"></a>**

- Before the installation, the system environment has met the requirements described in [Environment Requirements](#environment-requirements).
- The OpenSSL version is 1.1.1x or 3.0.x (run the **openssl version** command to check the version), or the Tongsuo version is 8.4.0. If not, [install OpenSSL or Tongsuo](#installing-openssltongsuo).
- Install the dependencies.

    ```shell
    yum install -y make kernel-devel-`uname -r` libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath cmake libunwind-devel patch
    ```

- Set the OpenSSL environment variable **OPENSSL\_ENGINES** to the directory where the KAE dynamic library is stored so that OpenSSL can detect KAE.
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

- Set the **LD\_LIBRARY\_PATH** environment variable so that KAE can detect the UADK driver dynamic library.

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

**Installation Procedure<a name="section1415911025615"></a>**

1. Use a remote login tool to log in to the Linux CLI as the **root** user.
2. Download the KAE 2.0 source code package provided in [Obtaining Software Packages](#environment-deployment), copy the package to a custom path, and decompress the package. Alternatively, run the following command to download the source code package:

    ```shell
    git clone https://gitcode.com/boostkit/KAE.git -b kae2
    ```

3. (Optional) Install all modules using a script.

    If OpenSSL 1.1.1x is used, the script provides a one-click installation command. Go to the KAE source package directory and run the **sh build.sh all** command to install all the modules.

    ```shell
    cd KAE
    sh build.sh all
    ```

4. Install the kernel driver.
    1. Go to the directory where the KAE source package is stored and run the installation script.

        ```shell
        cd KAE
        sh build.sh driver
        ```

        Compile the accelerator driver to generate **uacce.ko**, **hisi\_qm.ko**, **hisi\_sec2.ko**, **hisi\_hpre.ko**, and **hisi\_zip.ko**. The installation path is **/lib/modules/\`uname -r\`/extra**.

    2. Check whether the driver is installed.

        - Check whether the accelerator engine file system exists in **/sys/class/uacce**.

            ```shell
            ll /sys/class/uacce/
            ```

            If the following information is displayed, the driver has been installed:

            ```text
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec2-0
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec2-1
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-4 -> ../../devices/pci0000:74/0000:74:00.0/0000:75:00.0/uacce/hisi_zip-4
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-5 -> ../../devices/pci0000:b4/0000:b4:00.0/0000:b5:00.0/uacce/hisi_zip-5
            ```

        - Run **lsmod** to check whether the driver has been installed.

            ```shell
            lsmod | grep hisi_qm
            ```

            If the following information is displayed, the driver has been installed:

            ```text
            hisi_qm               262144  3 hisi_sec2,hisi_zip,hisi_hpre
            uacce                 262144  1 hisi_qm
            ```

        >![](public_sys-resources/icon-note.gif) **NOTE**
        >- If no device file is found after a driver is installed or the device is restarted, a possible cause is that the OS has a built-in accelerator driver. You can unload the installed driver and then reload it. Alternatively, add the command for reloading the driver to the startup script **rc.local** to ensure that the driver can be properly loaded after the device is restarted.
        >- The following commands use **hisi\_sec2** as an example.<br>
        rmmod hisi_sec2<br>
        modprobe hisi_sec2
        >- On a Kunpeng 920 server, if no device file is found after the **sh build.sh cleanup** command is executed and a driver is reinstalled, check whether the license has been installed. If no license is available, the driver installation fails. For details, see [Obtaining the License](#obtaining-the-license).
        >- In KAE 2.0, both the encryption and decryption driver and the decompression driver are installed by default. You can manually uninstall unnecessary driver files.

5. Install the UADK framework.
    1. Run the following command to install the UADK framework:

        ```shell
        sh build.sh uadk
        ```

        The UADK framework contains user-space drivers whose dynamic library files are **libwd.so** and **libwd\_crypto.so**. The default UADK installation path is **/usr/include/uadk**. The dynamic library files are stored in **/usr/local/lib**.

        >![](public_sys-resources/icon-note.gif) **NOTE**
        >If the UADK installation fails and a message is displayed indicating that header files are missing, install the related dependency packages and run the installation command again.

    2. Check whether the UADK framework has been installed.

        ```shell
        ll /usr/local/lib/libwd*
        ```

        If the following information is displayed, the installation is successful:

        ```text
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
        ```

6. Compile and install KAEOpensslEngine.

    - OpenSSL 1.1.1x:
        - Use OpenSSL in the default path.

            ```shell
            sh build.sh engine
            ```

        - Use OpenSSL in a custom path.

            ```shell
            sh build.sh engine /usr/local/ssl1_1_1w
            ```

    - OpenSSL 3.0.x:
        - Use OpenSSL in the default path.

            ```shell
            sh build.sh engine3
            ```

        - Use OpenSSL in a custom path.

            ```shell
            sh build.sh engine3 /usr/local/ssl3_0_14
            ```

    - Tongsuo:
        - Use Tongsuo in the default path.

            ```shell
            sh build.sh engine3_tongsuo
            ```

        - Use Tongsuo in a custom path.

            ```shell
            sh build.sh engine3_tongsuo /opt/tongsuo
            ```

    The KAE dynamic library file is **libkae.so**. The dynamic library file is in **/usr/local/lib/engines-x.x** or **/usr/local/tongsuo/lib/engines-3.0**.

7. Check whether KAE has been installed.

    - OpenSSL 1.1.1x:

        ```shell
        ll /usr/local/lib/engines-1.1
        ```

    - OpenSSL 3.0.x:

        ```shell
        ll /usr/local/lib/engines-3.0
        ```

    - Tongsuo 8.4.0:

        ```shell
        ll /usr/local/tongsuo/lib/engines-3.0
        ```

    If the following information is displayed, the installation is successful:

    ```text
    total 5644
    -rw-r--r--. 1 root root 3846524 Aug 22 17:28 kae.a
    -rwxr-xr-x. 1 root root     995 Aug 22 17:28 kae.la
    lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so -> kae.so.2.0.0
    lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so.2 -> kae.so.2.0.0
    -rwxr-xr-x. 1 root root 1967736 Aug 22 17:28 kae.so.2.0.0
    ```

8. Compile and install the KAEZlib library.

    >![](public_sys-resources/icon-notice.gif) **NOTICE**
    >After installing KAEZlib, you can compile and install the KAEGzip decompression tool as required. The tool integrates the KAE hardware-based acceleration API, enabling you to compress and decompress files more conveniently.

    1. Perform compilation and installation.

        ```shell
        sh build.sh zlib
        ```

        The zlib library is installed in **/usr/local/kaezip**.

    2. Check whether the zlib compression library has been installed.

        ```shell
        ll /usr/local/kaezip/lib/
        ```

        If the following information is displayed, the installation is successful:

        ```text
        lrwxrwxrwx. 1 root root     40 Aug 29 10:20 libkaezip.so -> /usr/local/kaezip/lib/libkaezip.so.2.0.0
        lrwxrwxrwx. 1 root root     40 Aug 29 10:20 libkaezip.so.0 -> /usr/local/kaezip/lib/libkaezip.so.2.0.0
        -rwxr-xr-x. 1 root root 148096 Aug 29 10:20 libkaezip.so.2.0.0
        -rw-r--r--. 1 root root 145674 Aug 29 10:20 libz.a
        lrwxrwxrwx. 1 root root     14 Aug 29 10:20 libz.so -> libz.so.1.2.11
        lrwxrwxrwx. 1 root root     14 Aug 29 10:20 libz.so.1 -> libz.so.1.2.11
        -rwxr-xr-x. 1 root root 144784 Aug 29 10:20 libz.so.1.2.11
        drwxr-xr-x. 2 root root   4096 Aug 29 10:20 pkgconfig
        ```

    3. <a name="li20414340916"></a>Compile and install KAEGzip.

        ```shell
        sh build.sh gzip
        ```

        The tool is installed in **/usr/local/kaegzip**.

    4. <a name="li5793114715813"></a>Check whether KAEGzip has been installed.

        ```shell
        ldd /usr/local/kaegzip/gzip
        ```

        If the following information is displayed, the installation is successful:

        ```text
        [root@localhost /]# ldd /usr/local/kaegzip/gzip 
         linux-vdso.so.1 (0x0000ffff7fbc1000)
         libz.so.1 => /usr/local/kaezip/lib/libz.so.1 (0x0000ffff7fb50000)
         libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff7fae0000)
         libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffff7fa90000)
         libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff7f8e0000)
         /lib/ld-linux-aarch64.so.1 (0x0000ffff7fb84000)
         libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff7f8a0000)
         libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff7f870000)
        ```

9. Compile and install the KAEZstd library.
    1. Perform compilation and installation.

        ```shell
        sh build.sh zstd
        ```

        The KAEZstd library is installed in **/usr/local/kaezstd**.

    2. Check whether the installation is successful.

        ```shell
        ll /usr/local/kaezstd/lib/
        ```

        If the following information is displayed, the installation is successful:

        ```text
        -rwxr-xr-x. 1 root root  82688 Aug 29 10:40 libkaezstd.a
        lrwxrwxrwx. 1 root root     42 Aug 29 10:40 libkaezstd.so -> /usr/local/kaezstd/lib/libkaezstd.so.2.0.0
        lrwxrwxrwx. 1 root root     42 Aug 29 10:40 libkaezstd.so.0 -> /usr/local/kaezstd/lib/libkaezstd.so.2.0.0
        -rwxr-xr-x. 1 root root  76880 Aug 29 10:40 libkaezstd.so.2.0.0
        -rw-r--r--. 1 root root 996750 Aug 29 10:40 libzstd.a
        lrwxrwxrwx. 1 root root     16 Aug 29 10:40 libzstd.so -> libzstd.so.1.5.2
        lrwxrwxrwx. 1 root root     16 Aug 29 10:40 libzstd.so.1 -> libzstd.so.1.5.2
        -rwxr-xr-x. 1 root root 908616 Aug 29 10:40 libzstd.so.1.5.2
        drwxr-xr-x. 2 root root   4096 Aug 29 10:40 pkgconfig
        ```

10. Compile and install the KAELz4 library.
    1. Perform compilation and installation.

        ```shell
        sh build.sh lz4
        ```

        The KAELz4 library is installed in **/usr/local/kaelz4**.

    2. Check whether the installation is successful.

        ```shell
        ll /usr/local/kaelz4/lib/
        ```

        If the following information is displayed, the installation is successful:

        ```text
        -rwxr-xr-x 1 root root 208716 Oct 24 14:26 libkaelz4.a
        lrwxrwxrwx 1 root root     40 Oct 24 14:26 libkaelz4.so -> /usr/local/kaelz4/lib/libkaelz4.so.1.0.0
        lrwxrwxrwx 1 root root     40 Oct 24 14:26 libkaelz4.so.0 -> /usr/local/kaelz4/lib/libkaelz4.so.1.0.0
        -rwxr-xr-x 1 root root 145296 Oct 24 14:26 libkaelz4.so.1.0.0
        -rw-r--r-- 1 root root 318592 Oct 24 14:27 liblz4.a
        lrwxrwxrwx 1 root root     15 Oct 24 14:27 liblz4.so -> liblz4.so.1.9.4
        lrwxrwxrwx 1 root root     15 Oct 24 14:27 liblz4.so.1 -> liblz4.so.1.9.4
        -rwxr-xr-x 1 root root 276320 Oct 24 14:27 liblz4.so.1.9.4
        drwxr-xr-x 2 root root   4096 Oct 24 14:27 pkgconfig
        ```

11. Compile and install the KAESnappy library.
    1. Perform compilation and installation.

        ```shell
        sh build.sh snappy
        ```

        The KAESnappy library is installed in **/usr/local/kaesnappy**.

    2. Check whether the installation is successful.

        ```shell
        ll /usr/local/kaesnappy/lib/
        ```

        If the following information is displayed, the installation is successful:

        ```text
        -rwxr-xr-x 1 root root 142918 Oct 24 14:26 libkaessnappy.a
        lrwxrwxrwx 1 root root     46 Oct 24 14:26 libkaesnappy.so -> /usr/local/kaesnappy/lib/libkaesnappy.so.2.0.4
        lrwxrwxrwx 1 root root     46 Oct 24 14:26 libkaesnappy.so.0 -> /usr/local/kaesnappy/lib/libkaesnappy.so.2.0.4
        -rwxr-xr-x 1 root root  77472 Oct 24 14:26 libkaesnappy.so.2.0.4
        lrwxrwxrwx 1 root root     14 Oct 24 14:27 libsnappy.so -> libsnappy.so.1
        lrwxrwxrwx 1 root root     19 Oct 24 14:27 libsnappy.so.1 -> libsnappy.so.1.1.10
        -rwxr-xr-x 1 root root  78568 Oct 24 14:27 libsnappy.so.1.1.10
        ```

**Verifying the Installation<a name="section196217415295"></a>**

1. Check whether KAEOpensslEngine takes effect.

    The RSA performance is used as an example. For details about the verification procedure, see [Testing the Synchronous RSA Performance](#testing-after-installation). The command output shows that the RSA performance is significantly improved after KAE is used.

    In addition, during the execution of the RSA performance verification command, you can view the hardware queue resource usage of the **hisi\_hpre** device on a new terminal. Similarly, you can view the hardware queue resource usage of the **hisi\_sec2** device when verifying the SM3/SM4 algorithm performance.

    ```shell
    cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    You can also run the following command during RSA performance verification to refresh the hardware queue consumption of **hisi\_hpre** every 0.1 second:

    ```shell
    watch -n 0.1 cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    If the value changes from **256** to **255**, the RSA algorithm consumes a hardware queue of the HPRE accelerator, indicating that KAEOpensslEngine has taken effect.

2. Check whether the accelerator engines of the KAEZlib library take effect. Run the **ldd** command to check whether the KAEZlib library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaezip/lib/libz.so.1.2.11
    ```

    If the information below is displayed, the KAEZlib library has been installed. You can also run the **ldd** command to check whether the libwd library is used.

    ```text
     linux-vdso.so.1 (0x0000ffffa631d000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffa6110000)
     libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffffa60df000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffffa607e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffffa605d000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffffa62e0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffffa6038000)
    ```

3. Check whether the accelerator engines of the KAEZstd library take effect. Run the **ldd** command to check whether the KAEZstd library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaezstd/lib/libkaezstd.so
    ```

    If the following information is displayed, the KAEZstd library has been installed:

    ```text
        linux-vdso.so.1 (0x0000ffff89774000)
        libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff896b5000)
        libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff89684000)
        libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff894d5000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffff89737000)
        libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff894b0000)
    ```

4. Check whether the accelerator engines of the KAELz4 library take effect. Run the **ldd** command to check whether the KAELz4 library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaelz4/lib/libkaelz4.so
    ```

    If the following information is displayed, the KAELz4 library has been installed:

    ```shell
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

5. Check whether the accelerator engines of the KAESnappy library take effect. Run the **ldd** command to check whether the KAESnappy library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaesnappy/lib/libkaesnappy.so
    ```

    If the following information is displayed, the KAESnappy library has been installed:

    ```text
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

## Installation Using RPM Packages

KAE 2.0 RPM packages include **kae-driver**, **kae-openssl**, and **kae-zip**. To use encryption and decryption algorithms, install **kae-driver** and **kae-openssl**. To use KAEZip algorithms, install **kae-driver** and **kae-zip**. You are advised to install KAE 2.0 using source code. If KAE 2.0 needs to be installed on an OS other than openEuler using RPM packages, create RPM packages from source code and then install KAE 2.0. To upgrade KAE, uninstall the old version and then install the new version.

>![](public_sys-resources/icon-notice.gif) **NOTICE**
>Currently, each RPM package of KAE 2.0 is built on a specified tag and dedicated to a specific OS, and does not offer the latest features of KAE 2.0.

**Prerequisites<a name="section9968616173616"></a>**

- The RPM is running normally.
- Run the **openssl version** command to check whether the OpenSSL version is 1.1.1x. If not, install OpenSSL by referring to [Installing OpenSSL/Tongsuo](#installing-openssltongsuo).
- Install the dependencies.

    ```shell
    yum install -y make kernel-devel libtool numactl-devel openssl-devel chrpath  lz4-devel
    ```

- Set the OpenSSL environment variable **OPENSSL\_ENGINES** to the directory where the KAE dynamic library is stored so that OpenSSL can detect KAE.

    ```shell
    export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
    ```

- Set the **LD\_LIBRARY\_PATH** environment variable so that KAE can detect the UADK driver dynamic library.

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

**Installation Procedure<a name="section954494455617"></a>**

1. Use SSH to remotely log in to the Linux CLI as the **root** user.
2. Copy the KAE 2.0 RPM packages obtained from [Obtaining Software Packages](#environment-deployment) to a custom directory.

    If the KAE code repository does not contain RPM packages for a specific OS, perform the following operations to create RPM packages:

    1. Obtain the KAE 2.0 source code package from [GitCode](https://gitcode.com/boostkit/KAE.git) or run the following command to download it:

        ```shell
        git clone https://gitcode.com/boostkit/KAE.git -b kae2
        ```

    2. Create RPM packages in the KAE source code directory.

        ```shell
        sh build.sh rpmpack
        ```

3. Install the accelerator driver RPM package **kae-driver**.

    ```shell
    rpm -ivh kae-driver-2.0.1-1.aarch64.rpm
    ```

    If the following information is displayed, the installation is successful:

    ```text
    Verifying...                          ################################# [100%]
    Preparing...                          ################################# [100%]
    Preprocessing before installing the driver
    checking installed modules
    uacce modules start to install
    checking installed modules
    hisi_sec2 modules start to install
    checking installed modules
    hisi_hpre modules start to install
    checking installed modules
    hisi_zip modules start to install
    Updating / installing...
       1:kae-driver-2.0.1-1               ################################# [100%]
    installing driver...
    uacce modules installed
    hisi_sec2 modules installed
    hisi_hpre modules installed
    hisi_zip modules installed
    ```

    >![](public_sys-resources/icon-note.gif) **NOTE**
    >If no device file is found after a driver is installed or the device is restarted, a possible cause is that the OS has a built-in accelerator driver. You can unload the installed driver and then reload it. Alternatively, add the command for reloading the driver to the startup script **rc.local** to ensure that the driver can be properly loaded after the device is restarted. The following commands use **hisi\_sec2** as an example.
    >
    >```bash
    >rmmod hisi_sec2
    >modprobe hisi_sec2
    >```

4. Install the engine library RPM package **kae-openssl**.

    ```shell
    rpm -ivh kae-openssl-2.0.1-1.aarch64.rpm
    ```

    If the following information is displayed, the installation is successful:

    ```text
    Verifying...                          ################################# [100%]
    Preparing...                          ################################# [100%]
    Updating / installing...
       1:kae-openssl-2.0.1-1              ################################# [100%]
    installing openssl engine...
    ```

5. Install the KAEZip RPM package **kae-zip**.

    ```shell
    rpm -ivh kae-zip-2.0.1-1.aarch64.rpm
    ```

    If the following information is displayed, the installation is successful:

    ```text
    Verifying...                          ################################# [100%]
    Preparing...                          ################################# [100%]
    installing pre zip...
    Updating / installing...
       1:kae-zip-2.0.1-1                  ################################# [100%]
    installing post zip...
    ```

6. Check whether related software has been installed in the system.
    1. Check whether the driver is installed.
        - Check whether the accelerator engine file system exists in **/sys/class/uacce**.

            ```shell
            ll /sys/class/uacce/
            ```

            If the following information is displayed, the driver has been installed:

            ```text
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec2-0
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec2-1
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-4 -> ../../devices/pci0000:74/0000:74:00.0/0000:75:00.0/uacce/hisi_zip-4
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-5 -> ../../devices/pci0000:b4/0000:b4:00.0/0000:b5:00.0/uacce/hisi_zip-5
            ```

        - Run **lsmod** to check whether the driver has been installed.

            ```shell
            lsmod | grep uacce
            ```

            If the following information is displayed, the driver has been installed:

            ```text
            uacce                  32768  3 hisi_sec2,hisi_qm,hisi_zip
            ```

    2. Check whether the UADK framework has been installed.

        ```shell
        ll /usr/local/lib/libwd*
        ```

        If the following information is displayed, the installation is successful:

        ```text
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
        ```

    3. Check whether KAE has been installed.

        ```shell
         ll /usr/local/lib/engines-1.1
        ```

        If the following information is displayed, the installation is successful:

        ```text
        total 5644
        -rw-r--r--. 1 root root 3846524 Aug 22 17:28 kae.a
        -rwxr-xr-x. 1 root root     995 Aug 22 17:28 kae.la
        lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so -> kae.so.2.0.0
        lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so.2 -> kae.so.2.0.0
        -rwxr-xr-x. 1 root root 1967736 Aug 22 17:28 kae.so.2.0.0
        ```

    4. Check whether the KAEZip decompression module has been installed.

        ```shell
        ll /usr/local/kaezip/lib
        ```

        If the following information is displayed, the installation is successful:

        ```text
        total 440
        lrwxrwxrwx. 1 root root     40 Jan 12  2024 libkaezip.so -> /usr/local/kaezip/lib/libkaezip.so.2.0.1
        lrwxrwxrwx. 1 root root     40 Jan 12  2024 libkaezip.so.0 -> /usr/local/kaezip/lib/libkaezip.so.2.0.1
        -rwxr-xr-x. 1 root root 148096 Jan 12  2024 libkaezip.so.2.0.1
        -rwxr-xr-x. 1 root root 146306 Jan 12  2024 libz.a
        lrwxrwxrwx. 1 root root     14 Jan 12  2024 libz.so -> libz.so.1.2.11
        lrwxrwxrwx. 1 root root     14 Jan 12  2024 libz.so.1 -> libz.so.1.2.11
        -rwxr-xr-x. 1 root root 143656 Jan 12  2024 libz.so.1.2.11
        drwxr-xr-x. 2 root root   4096 Dec  5 18:48 pkgconfig
        ```

**Verifying the Installation<a name="section13545944105612"></a>**

1. Check RPM packages of KAE.

    ```shell
    rpm -qa kae-driver kae-openssl kae-zip
    ```

    If the following information is displayed, the installation is successful:

    ```text
    kae-openssl-2.0.1-1.aarch64
    kae-driver-2.0.1-1.aarch64
    kae-zip-2.0.1-1.aarch64
    ```

2. Check the accelerator devices in the virtual file system.

    ```shell
    ls -al /sys/class/uacce/
    ```

    Command output:

    ```text
    total 0
    lrwxrwxrwx. 1 root root 0 Nov 14 03:45 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
    lrwxrwxrwx. 1 root root 0 Nov 14 03:45 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
    lrwxrwxrwx. 1 root root 0 Nov 14 08:39 hisi_sec-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec-0
    lrwxrwxrwx. 1 root root 0 Nov 14 08:39 hisi_sec-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec-1
    lrwxrwxrwx.  1 root root 0 Dec  5 18:59 hisi_zip-4 -> ../../devices/pci0000:74/0000:74:00.0/0000:75:00.0/uacce/hisi_zip-4
    lrwxrwxrwx.  1 root root 0 Dec  5 18:59 hisi_zip-5 -> ../../devices/pci0000:b4/0000:b4:00.0/0000:b5:00.0/uacce/hisi_zip-5
    ```

3. Check whether KAEOpensslEngine takes effect.

    The RSA performance is used as an example. For details about the verification procedure, see [Testing the Synchronous RSA Performance](#testing-after-installation). The command output shows that the RSA performance is significantly improved after KAE is used.

    In addition, during the execution of the RSA performance verification command, you can view the hardware queue resource usage of the **hisi\_hpre** device on a new terminal. Similarly, you can view the hardware queue resource usage of the **hisi\_sec2** device when verifying the SM3/SM4 algorithm performance.

    ```shell
    cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    You can also run the following command to refresh the hardware queue consumption of **hisi\_hpre** every 0.1 second:

    ```shell
    watch -n 0.1 cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    If the value changes from **256** to **255**, the RSA algorithm consumes a hardware queue of the HPRE accelerator, indicating that KAEOpensslEngine has taken effect.

4. Check whether the accelerator engines of the KAEZip library take effect. Run the **ldd** command to check whether the KAEZip library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaezip/lib/libz.so.1.2.11
    ```

    If the information below is displayed, the KAEZlib library has been installed. You can also run the **ldd** command to check whether the libwd library is used.

    ```shell
    linux-vdso.so.1 (0x0000ffffa631d000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffa6110000)
     libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffffa60df000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffffa607e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffffa605d000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffffa62e0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffffa6038000)
    ```

5. Check whether the accelerator engines of the KAEZstd library take effect. Run the **ldd** command to check whether the KAEZstd library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaezstd/lib/libkaezstd.so
    ```

    If the following information is displayed, the KAEZstd library has been installed:

    ```text
            linux-vdso.so.1 (0x0000ffff89774000)
            libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff896b5000)
            libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff89684000)
            libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff894d5000)
            /lib/ld-linux-aarch64.so.1 (0x0000ffff89737000)
            libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff894b0000)
    ```

6. Check whether the accelerator engines of the KAELz4 library take effect. Run the **ldd** command to check whether the KAELz4 library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaelz4/lib/libkaelz4.so
    ```

    If the following information is displayed, the KAELz4 library has been installed:

    ```shell
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

7. Check whether the accelerator engines of the KAESnappy library take effect. Run the **ldd** command to check whether the KAESnappy library is linked to the libwd library.

    ```shell
    ldd /usr/local/kaesnappy/lib/libkaesnappy.so
    ```

    If the following information is displayed, the KAESnappy library has been installed:

    ```text
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

## Testing After Installation

### Testing the KAE Encryption and Decryption Library

You can run commands provided in this section to test the performance before and after the KAE encryption and decryption library is invoked in RSA (synchronous and asynchronous modes), SM3, SM4 (CBC mode), and AES (asynchronous CBC mode).

>![](public_sys-resources/icon-note.gif) **NOTE**
>If Tongsuo is used for encryption and decryption, the test method is the same as that of OpenSSL.
>The test data is obtained from an environment using the Kunpeng 920 processor and CentOS 7.6.

**Checking OpenSSL<a name="section33586710151"></a>**

Check the OpenSSL version.

```shell
openssl version
```

If the OpenSSL version is not the one used during KAE installation, set the environment variables below to specify OpenSSL. In the following commands, **/path/install** indicates the OpenSSL installation path.

```shell
export PATH=/path/install/bin:$PATH
export LD_LIBRARY_PATH=/path/install/lib:$LD_LIBRARY_PATH
```

**Testing the Synchronous RSA Performance<a name="section54081455216"></a>**

- Use the OpenSSL software algorithm to test the RSA performance.

    ```shell
    openssl speed -elapsed rsa2048
    ```

    Command output:

    ```text
    ...
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.001384s 0.000035s   724.1  28365.8.
    ```

- Enable KAE to test the performance of the RSA algorithm.

    ```shell
    openssl speed -elapsed -engine kae rsa2048
    ```

    Command output:

    ```text
    ....
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.000355s 0.000022s   2819.0  45478.4
    ```

>![](public_sys-resources/icon-note.gif) **NOTE**
>After KAE is used, the signing speed is improved from 724.1 signs/s to 2,819 signs/s.

**Testing the Asynchronous RSA Performance<a name="section115401118424"></a>**

- Use the OpenSSL software algorithm to test the asynchronous RSA performance.

    ```shell
    openssl speed -elapsed -async_jobs 36 rsa2048 
    ```

    Command output:

    ```text
    ....
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.001318s 0.000032s    735.7  28555
    ```

- Enable KAE to test the asynchronous RSA algorithm performance.

    ```shell
    openssl speed -engine kae -elapsed -async_jobs 36 rsa2048 
    ```

    Command output:

    ```text
    .... 
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.000018s 0.000009s  54384.1 105317.0
    ```

>![](public_sys-resources/icon-note.gif) **NOTE**
>After KAE is used, the asynchronous RSA signing speed is improved from 735.7 signs/s to 54,384.1 signs/s.

**Testing the SM4 Algorithm Performance in CBC Mode<a name="section059717381527"></a>**

- Use the OpenSSL software to test the performance of the SM4 algorithm in CBC mode.

    ```shell
    openssl speed -elapsed -evp sm4-cbc
    ```

    Command output:

    ```text
    You have chosen to measure elapsed time instead of user CPU time.
    ....
    Doing sm4-cbc for 3s on 10240 size blocks: 2196 sm4-cbc's in 3.00s  ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm4-cbc          82312.53k    85196.80k    85284.18k    85000.85k    85284.18k    85261.26k
    ```

- Enable KAE to test the performance of the SM4 algorithm in CBC mode.

    ```shell
    openssl speed -elapsed -engine kae -evp sm4-cbc
    ```

    Command output:

    ```text
    engine "kae" set. 
    You have chosen to measure elapsed time instead of user CPU time.
    ...
    Doing sm4-cbc for 3s on 1048576 size blocks: 11409 sm4-cbc's in 3.00s
    ...
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm4-cbc         383317.33k   389427.20k   395313.15k   392954.73k   394264.58k   394264.58k
    ```

>![](public_sys-resources/icon-note.gif) **NOTE**
>After KAE acceleration, the operational speed of the SM4 algorithm in CBC mode increases from 82,312.53 KB/s to 383,317.33 KB/s when the input data block size is 8 MB.

**Testing the Performance of the SM3 Algorithm<a name="section1220591319313"></a>**

- Use the OpenSSL software to test the performance of the SM3 algorithm.

    ```shell
    openssl speed -elapsed -evp sm3
    ```

    Command output:

    ```text
    You have chosen to measure elapsed time instead of user CPU time.
    Doing sm3 for 3s on 102400 size blocks: 1536 sm3's in 3.00s
    ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm3              50568.53k    52428.80k    52428.80k    52428.80k    52428.80k    52428.80k
    ```

- Enable KAE to test the performance of the SM3 algorithm.

    ```shell
    openssl speed -elapsed -engine kae -evp sm3
    ```

    Command output:

    ```text
    engine "kae" set.
    You have chosen to measure elapsed time instead of user CPU time.
    Doing sm3 for 3s on 102400 size blocks: 19540 sm3's in 3.00s
    ....
    type            51200 bytes  102400 bytes  1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm3             648243.20k   666965.33k   677030.57k   678778.20k   676681.05k   668292.44k
    ```

>![](public_sys-resources/icon-note.gif) **NOTE**
>After KAE acceleration, the operational speed of the SM3 algorithm increases from 52,428.80 KB/s to 668,292.44 KB/s when the input data block size is 8 MB.

**Testing the Asynchronous Performance of the AES Algorithm in CBC Mode<a name="section1018002911311"></a>**

- Use the OpenSSL software to test the asynchronous performance of the AES algorithm in CBC mode.

    ```shell
    openssl speed -elapsed -evp aes-128-cbc -async_jobs 4
    ```

    Command output:

    ```text
    You have chosen to measure elapsed time instead of user CPU time.
    Doing aes-128-cbc for 3s on 51200 size blocks: 65773 aes-128-cbc's in 3.00s
    Doing aes-128-cbc for 3s on 102400 size blocks: 32910 aes-128-cbc's in 3.00s
    ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    aes-128-cbc    1122525.87k  1123328.00k  1120578.22k  1121277.27k  1119879.17k  1115684.86k
    ```

- Enable KAE to test the asynchronous performance of the AES algorithm in CBC mode.

    ```shell
    openssl speed -elapsed -evp aes-128-cbc -async_jobs 4 -engine kae
    ```

    Command output:

    ```text
    engine "kae" set.
    You have chosen to measure elapsed time instead of user CPU time.
    Doing aes-128-cbc for 3s on 51200 size blocks: 219553 aes-128-cbc's in 3.00s
    Doing aes-128-cbc for 3s on 102400 size blocks: 117093 aes-128-cbc's in 3.00s
    ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    aes-128-cbc    3747037.87k  3996774.40k  1189085.18k  1196774.74k  1196979.11k  1199570.94k
    ```

>![](public_sys-resources/icon-note.gif) **NOTE**
>
>- The OpenSSL test data length is defined in the lengths\_list array in the **speed.c** file (in the **app** directory of the OpenSSL source code package, for example, **openssl-1.1.1a/apps/speed.c**). Testers can modify the data here and compile and [install OpenSSL](#installing-openssltongsuo). That is how the length of the test data (such as 51,200 bytes and 102,400 bytes) is calculated.
>- The AES algorithm supports only asynchronous operations with a data length of 256 KB or less.
>- After KAE acceleration, the operational speed of the AES algorithm increases from 1,123,328.00 KB/s to 3,996,774.40 KB/s when the input data block size is 100 KB.

### Testing the KAEZlib Compression Library

After installing the KAEZlib library, you can test the library functions and performance based on the operations provided in this section.

>![](public_sys-resources/icon-notice.gif) **NOTICE**
>Perform the test procedure in the source code directory. If KAE is installed using RPM packages, download and decompress the KAE source code package before the test.

1. Install KAEZlib by referring to [Installation Using the Source Code](#installation-using-the-source-code) or [Installation Using RPM Packages](#installation-using-rpm-packages).
2. Go to the test directory.

    ```shell
    cd KAEZlib/test/gtest/
    ```

3. Test the KAEZlib library functions.

    ```shell
    sh build.sh
    ./kaezlibtest --gtest_filter=*Case*
    ```

    In the command output, if the execution results of both SmallCase and LargeCase are **passed**, the KAEZlib library functions are normal.

    ```text
    [==========] Running 2 tests from 1 test suite.
    [----------] Global test environment set-up.
    [----------] 2 tests from ZlibTest
    [ RUN      ] ZlibTest.CompressAndDecompress_SmallCase
    [       OK ] ZlibTest.CompressAndDecompress_SmallCase (116 ms)
    [ RUN      ] ZlibTest.CompressAndDecompress_LargeCase
    [       OK ] ZlibTest.CompressAndDecompress_LargeCase (89915 ms)
    [----------] 2 tests from ZlibTest (90031 ms total)
    
    [----------] Global test environment tear-down
    [==========] 2 tests from 1 test suite ran. (90031 ms total)
    [  PASSED  ] 2 tests.
    ```

4. Test the performance.
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

        - Testing the compression performance of ZIP

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

        - Testing the compression performance of the KAEZip library

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

        - Testing the decompression performance of ZIP

            ```shell
            ./zip_perf -d -m 8 -f itemdata.zlib -n 1000
            ```

            Command output:

            ```text
            kaezip perf parameter: multi process 8, stream length: 1024(KB), loop times: 1000, windowBits : 15, level : 6
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

        - Testing the decompression performance of the KAEZip library

            ```shell
            ./kaezip_perf -d -m 8 -f itemdata.zlib -n 1000
            ```

            Command output:

            ```text
            kaezip perf parameter: multi process 8, stream length: 1024(KB), loop times: 1000, windowBits : 15, level : 6
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

5. If the KAEGzip tool is installed, perform the following operations to verify its functions and performance:
    1. Obtain help information.

        ```shell
        /usr/local/kaegzip/gzip -h
        ```

    2. Test the functions.

        1. Use KAEGzip to compress the **itemdata** file into **itemdata.gz** while retaining the original file **itemdata**.

            ```shell
            /usr/local/kaegzip/gzip -k itemdata
            ```

        2. Rename the source file **itemdata** to **itemdata.orig**.

            ```shell
            mv itemdata itemdata.orig
            ```

        3. Use KAEGzip to decompress the **itemdata.gz** file.

            ```shell
            /usr/local/kaegzip/gzip -d itemdata.gz 
            ```

        4. Compare the file generated after decompression with the original file **itemdata.orig**.

            ```shell
            diff itemdata itemdata.orig 
            ```

        If no command output is displayed, KAEGzip has correctly compressed and decompressed the file.

    3. Test the compression performance.

        - Using gzip

            ```shell
            time gzip itemdata
            ```

            Command output:

            ```text
            real 0m0.348s
            user 0m0.343s
            sys 0m0.004s
            ```

        - Using KAEGzip

            ```shell
            time /usr/local/kaegzip/gzip itemdata
            ```

            Command output:

            ```text
            real 0m0.016s
            user 0m0.005s
            sys 0m0.010s
            ```

        Compared with the built-in gzip tool, the compression time using KAEGzip is significantly reduced.

    4. Test the decompression performance.

        - Using gzip

            ```shell
            time gzip -d itemdata.gz 
            ```

            Command output:

            ```text
            real 0m0.038s
            user 0m0.031s
            sys 0m0.008s
            ```

        - Using KAEGzip

            ```shell
            time /usr/local/kaegzip/gzip -d itemdata.gz 
            ```

        - Command output:

            ```text
            real 0m0.017s
            user 0m0.004s
            sys 0m0.012s
            ```

        Compared with the built-in gzip tool, the decompression time using KAEGzip is significantly reduced.

6. To use and test the asynchronous APIs, refer to [README_EN](../../KAEZlib/README_EN.md) in the KAEZlib directory.

### Testing the KAEZstd Compression Library

After installing the KAEZstd library, you can test the library functions and performance based on the operations provided in this section.

1. Install KAEZstd by referring to [Installation Using the Source Code](#installation-using-the-source-code) or [Installation Using RPM Packages](#installation-using-rpm-packages).
2. Test the functions of the zstd compression library.

    ```shell
    cd /KAE/KAEZstd/test/gtest
    mkdir build && cd build
    cmake ..
    make
    ./zstd_functest
    ```

3. Test the performance.
    - Use the built-in zstd compression library for the test.

        ```shell
        zstd -b3 /home/KAE/scripts/compressTestDataset/itemdata
        ```

        Command output:

        ```text
        3#itemdata   :  7316868   ->  1977124 (x3.701),  201.7 MB/s, 845.0 MB/s
        ```

    - Use the KAEZstd compression library for the test.

        ```shell
        /usr/local/kaezstd/bin/zstd -b3 /home/KAE/scripts/compressTestDataset/itemdata
        ```

        Command output:

        ```text
        3#itemdata   :  7316868   ->  2158294 (x3.390), 438.5 MB/s, 1233.2 MB/s
        ```

        As shown above, the compression speed increases from 201.7 MB/s to 438.5 MB/s when KAEZstd is used, demonstrating a clear performance improvement.

### Testing the KAELz4 Compression Library

After installing the KAELz4 library, you can test the library functions and performance based on the operations provided in this section.

**Synchronization Test<a name="section371134572320"></a>**

After installing the KAELz4 library, use the test script of the open-source compression algorithm stored in **/KAE/KAELz4/open\_source/lz4-1.9.4/test** and the kunpeng-lzbench test tool to test the synchronization function and performance of the KAELz4 compression library.

1. Install KAELz4 by referring to [Installation Using the Source Code](#installation-using-the-source-code) or [Installation Using RPM Packages](#installation-using-rpm-packages).
2. Obtain lzbench source code from [Gitee](https://gitee.com/kunpeng_compute/lzbench) and run the **make** command in the source code path to compile the source code to generate a binary tool.
3. Test the functions of the LZ4 compression library.

    ```shell
    cd /KAE/KAELz4/open_source/lz4-1.9.4/tests
    make
    ./fullbench datagen
    ```

4. Test the performance.
    1. Go to the lzbench source code path and check the algorithm library used by the test tool.

        ```shell
        ldd lzbench
        ```

        If the following information is displayed, the open source Lz4 algorithm library is used:

        ```shell
         linux-vdso.so.1 (0x0000ffffae181000)
         libz.so.1 => /usr/lib64/libz.so.1 (0x0000ffffae113000)
         libzstd.so.1 => /usr/lib64/libzstd.so.1 (0x0000ffffae012000)
         liblz4.so.1 => /usr/lib64/liblz4.so.1 (0x0000ffffadfe1000)
         libsnappy.so.1 => /usr/lib64/libsnappy.so.1 (0x0000ffffad7ad000)
         libstdc++.so.6 => /usr/lib64/libstdc++.so.6 (0x0000ffffaddeb000)
         libm.so.6 => /usr/lib64/libm.so.6 (0x0000ffffadd4a000)
         libgcc_s.so.1 => /usr/lib64/libgcc_s.so.1 (0x0000ffffadd19000)
         libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffadb6a000)
         /lib/ld-linux-aarch64.so.1 (0x0000ffffae144000)
        ```

    2. Test the decompression performance of the open source Lz4 algorithm library. The test file is stored in **KAE/scripts/compressTestDataset**.

        ```shell
        taskset -c 1 ./lzbench -relz4 -b8 -i1 -j -m1024 /pathtoKAE/scripts/compressTestDataset/
        ```

        Command output:

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26722 MB/s 27211 MB/s   102760022    102760022 100.00 8 files
        lz4 1.9.4                 472 MB/s  2900 MB/s   102760022     61462487  59.81 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

    3. Set the environment variable **LD\_LIBRARY\_PATH** to enable the KAELz4 library, and check the algorithm library used by the test tool.

        ```shell
        export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:$LD_LIBRARY_PATH
        ldd lzbench
        ```

        If the following information is displayed, the KAELz4 algorithm library is used:

        ```text
        linux-vdso.so.1 (0x0000ffffac665000)
        libz.so.1 => /usr/lib64/libz.so.1 (0x0000ffffac5f7000)
        libzstd.so.1 => /usr/lib64/libzstd.so.1 (0x0000ffffac4f6000)
        liblz4.so.1 => /usr/local/kaelz4/lib/liblz4.so.1 (0x0000ffffac4b5000)
        libsnappy.so.1 => /usr/lib64/libsnappy.so.1 (0x0000ffffad7ad000)
        libstdc++.so.6 => /usr/lib64/libstdc++.so.6 (0x0000ffffac2bf000)
        libm.so.6 => /usr/lib64/libm.so.6 (0x0000ffffac21e000)
        libgcc_s.so.1 => /usr/lib64/libgcc_s.so.1 (0x0000ffffac1ed000)
        libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffac03e000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffffac628000)
        libkaelz4.so.2.0.4 => /usr/local/kaelz4/lib/libkaelz4.so.2.0.4 (0x0000ffffac00b000)
        libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffffabfaa000)
        libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffffabf79000)
        libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffffabf54000)
        ```

    4. Test the decompression performance of KAELz4.

        ```shell
        taskset -c 1 ./lzbench -relz4 -b8 -i1 -j -m1024 ../../../../scripts/compressTestDataset/
        ```

        Command output:

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26929 MB/s 26177 MB/s   102760022    102760022 100.00 8 files
        lz4 1.9.4                 840 MB/s  3030 MB/s   102760022     58783964  57.21 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

5. Test the compression bandwidth.
    1. Set the environment variable **LD\_LIBRARY\_PATH** and enable the LZ4 library.

        ```shell
        export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:$LD_LIBRARY_PATH
        ```

    2. Compile the bandwidth test tool in the **/KAE/KAELz4/test/perftest** directory.

        ```shell
        cd KAE/KAELz4/test/perftest
        make
        ```

    3. Test the compression bandwidth of the LZ4 library.

        ```shell
        ./kaelz4_perf -m 80 -b 32 -l 640000
        ```

        Command output:

        ```text
        kaelz4 perf parameter: multi process 64, stream length: 640000(KB), block size: 32(KB), compress level: 1, compress function: 0, loop times: 1, g_threadnum: 15, core sequence: 0 ~ 63
        kaelz4 compress perf result:
             time used: 82891615 us, speed = 7.069 GB/s
        ```

**Asynchronous Test<a name="section3413841245"></a>**

After installing the KAELz4 library, use the test script stored in **/KAE/scripts/perftest/kzip** to test the asynchronous function and performance of the KAELz4 compression library.

1. Install KAELz4 by referring to [Installation Using the Source Code](#installation-using-the-source-code) or [Installation Using RPM Packages](#installation-using-rpm-packages).
2. Test the functions of asynchronous APIs of the KAELz4 library.

    ```shell
    cd KAE/scripts/perftest/kzip
    sh scripts/runFunc.sh
    ```

3. Enable the fast mode of the driver and set a specific valid compression window length to achieve the maximum performance.

    ```shell
    rmmod hisi_zip  
    modprobe hisi_zip perf_mode=1 uacce_mode=2 pf_q_num=256
    export KAE_LZ4_WINTYPE=8 
    export KAE_LZ4_COMP_TYPE=8
    ```

4. Test the performance of asynchronous APIs of the KAELz4 library.
    1. Test the performance of the asynchronous API for the 8 KB block.

        ```shell
        cd KAE/scripts/perftest/kzip
        sh runPerf.sh -A kaelz4async_block -m 1 -n 270000 -s 8
        ```

        Command output:

        ```text
        kzip perf parameter: algorithm: kaelz4async_block, multi process 1, threadNum 1, stream length: 1024(KB), loop times: 270000, window_bits : 15, level : 6, chunk: 8
        compress filename : ../../../scripts/compressTestDataset/calgary
        kaelz4async_block compress perf result when loop 270000 times: file:../../../scripts/compressTestDataset/calgary. chunk 8 kb. time used: 58649811 us, speed = 13.941 GB/s iops = 1827.627k, compress latency avg = 0.547us, latency avg per io = 35.018us
        compress_size is 495878498755B = 472906.594MB, compress_rate is 1.770
        ```

    2. Test the performance of the asynchronous API for the 8 KB frame.

        ```shell
        cd KAE/scripts/perftest/kzip
        sh runPerf.sh -A kaelz4async_frame -m 1 -n 270000 -s 8
        ```

        Command output:

        ```text
        kzip perf parameter: algorithm: kaelz4async_frame, multi process 1, threadNum 1, stream length: 1024(KB), loop times: 270000, window_bits : 15, level : 6, chunk: 8
        compress filename : ../../../scripts/compressTestDataset/calgary
        kaelz4async_frame compress perf result when loop 270000 times: file:../../../scripts/compressTestDataset/calgary. chunk 8 kb. time used: 58952173 us, speed = 13.869 GB/s iops = 1818.254k, compress latency avg = 0.550us, latency avg per io = 35.199us
        compress_size is 497489513676B = 474442.969MB, compress_rate is 1.765
        ```

### Testing the KAESnappy Compression Library

After installing the KAESnappy library, you can test the library functions and performance based on the operations provided in this section.

1. Install KAESnappy by referring to [Installation Using the Source Code](#installation-using-the-source-code) or [Installation Using RPM Packages](#installation-using-rpm-packages).
   
2. Obtain lzbench source code from [Gitee](https://gitee.com/kunpeng_compute/lzbench) and run the **make** command in the source code path to compile the source code to generate a binary tool.

3. Test the performance.
    1. Go to the lzbench source code path and check the algorithm library used by the test tool.

        ```shell
        ldd lzbench
        ```

        If the following information is displayed, the open-source Snappy algorithm library is used:

        ```shell
         linux-vdso.so.1 (0x0000ffffae181000)
         libz.so.1 => /usr/lib64/libz.so.1 (0x0000ffffae113000)
         libzstd.so.1 => /usr/lib64/libzstd.so.1 (0x0000ffffae012000)
         liblz4.so.1 => /usr/lib64/liblz4.so.1 (0x0000ffffadfe1000)
         libsnappy.so.1 => /usr/lib64/libsnappy.so.1 (0x0000ffffad7ad000)
         libstdc++.so.6 => /usr/lib64/libstdc++.so.6 (0x0000ffffaddeb000)
         libm.so.6 => /usr/lib64/libm.so.6 (0x0000ffffadd4a000)
         libgcc_s.so.1 => /usr/lib64/libgcc_s.so.1 (0x0000ffffadd19000)
         libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffadb6a000)
         /lib/ld-linux-aarch64.so.1 (0x0000ffffae144000)
        ```

    2. Test the decompression performance of the open source Snappy algorithm library. The test file is stored in **KAE/scripts/compressTestDataset**.

        ```shell
        taskset -c 1 ./lzbench -resnappy -b8 -i1 -j -m1024 /pathtoKAE/scripts/compressTestDataset/
        ```

        Command output:

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26722 MB/s 27211 MB/s   102760022    102760022 100.00 8 files
        snappy 2020-07-11         475 MB/s  1518 MB/s   102760022     61338103  59.69 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

    3. Set the environment variable **LD\_LIBRARY\_PATH** to enable the KAESnappy library, and check the algorithm library used by the test tool.

        ```shell
        export LD_LIBRARY_PATH=/usr/local/kaesnappy/lib:$LD_LIBRARY_PATH
        ldd lzbench
        ```

        If the following information is displayed, the KAESnappy algorithm library is used:

        ```shell
        linux-vdso.so.1 (0x0000ffffac665000)
        libz.so.1 => /usr/lib64/libz.so.1 (0x0000ffffac5f7000)
        libzstd.so.1 => /usr/lib64/libzstd.so.1 (0x0000ffffac4f6000)
        liblz4.so.1 => /usr/lib64/liblz4.so.1 (0x0000ffffadfe1000)
        libsnappy.so.1 => /usr/local/kaesnappy/lib/libsnappy.so.1 (0x0000ffffac4b5000)
        libstdc++.so.6 => /usr/lib64/libstdc++.so.6 (0x0000ffffac2bf000)
        libm.so.6 => /usr/lib64/libm.so.6 (0x0000ffffac21e000)
        libgcc_s.so.1 => /usr/lib64/libgcc_s.so.1 (0x0000ffffac1ed000)
        libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffac03e000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffffac628000)
        libkaesnappy.so.2.0.4 => /usr/local/kaesnappy/lib/libkaesnappy.so.2.0.4 (0x0000ffffac00b000)
        libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffffabfaa000)
        libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffffabf79000)
        libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffffabf54000)
        ```

    4. Test the decompression performance of KAESnappy.

        ```shell
        taskset -c 1 ./lzbench -resnappy -b8 -i1 -j -m1024 /pathtoKAE/scripts/compressTestDataset/
        ```

        Command output:

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26929 MB/s 26177 MB/s   102760022    102760022 100.00 8 files
        snappy 2020-07-11         738 MB/s  1570 MB/s   102760022     57612940  56.07 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

## Uninstalling KAE

This section describes how to uninstall KAE if you no longer require it or want to install KAE of a new version.

**Uninstalling KAE 2.0 Installed from Source Code<a name="section126341424597"></a>**

1. Use SSH to remotely log in to the Linux CLI as the **root** user.
2. Use a script to uninstall the accelerator driver packages and the KAE library packages that are installed using source code.

    - Uninstall the driver.

        ```shell
        cd KAE
        sh build.sh driver clean
        ```

    - Uninstall UADK.

        ```shell
        sh build.sh uadk clean
        ```

    - Uninstall KAE.
        - OpenSSL 1.1.1x:

            ```shell
            sh build.sh engine clean
            ```

        - OpenSSL 3.0.x:

            ```shell
            sh build.sh engine3 clean
            ```

        - Tongsuo 8.4.0:

            ```shell
            sh build.sh engine3_tongsuo clean
            ```

    - Uninstall KAEZlib.

        ```shell
        sh build.sh zlib clean
        ```

        If KAEGzip has been installed, run the following command to uninstall it:

        ```shell
        sh build.sh gzip clean
        ```

    - Uninstall KAEZstd.

        ```shell
        sh build.sh zstd clean
        ```

    - Uninstall KAELz4.

        ```shell
        sh build.sh lz4 clean
        ```

    - Uninstall KAESnappy.

        ```shell
        sh build.sh snappy clean
        ```

    >![](public_sys-resources/icon-note.gif) **NOTE**
    >You can also run **sh build.sh cleanup** to uninstall the KAE modules in the default installation paths.

**Uninstalling KAE 2.0 Installed Using RPM Packages<a name="section963562418918"></a>**

1. Use SSH to remotely log in to the Linux CLI as the **root** user.
2. Uninstall the KAE software packages and check the uninstallation result.
    1. Run the **rpm -e  _**Software_package_name**_** command to uninstall kae-openssl, kae-driver, and kae-zip.

        ```shell
        rpm -e kae-openssl
        rpm -e kae-driver
        rpm -e kae-zip
        ```

    2. Check whether the uninstallation is successful.

        Run the **rpm -qa | grep  _**Software_package_name**_** command.

        ```shell
        rpm -qa | grep kae-openssl 
        rpm -qa | grep kae-driver
        rpm -qa | grep kae-zip
        ```

3. Check whether KAE is uninstalled.
    1. Check whether the KAE library is uninstalled. If "No such file or directory" is displayed in the command output, the uninstallation is successful.

        ```shell
        ll /usr/local/lib/engines-1.1
        ```

    2. Check whether the KAEZip library is uninstalled. If "No such file or directory" is displayed in the command output, the uninstallation is successful.

        ```shell
        ll /usr/local/kaezip/lib
        ```

    3. Check whether the KAE driver is uninstalled. If no command output is displayed, the uninstallation is successful.

        ```shell
        lsmod | grep uacce
        ```
