# 安装指南

## 环境部署

### 环境要求

安装前请确保使用的环境满足KAE支持的已验证软硬件环境。请仔细阅读本章节内容了解适配信息。

**硬件要求<a name="section1158372015342"></a>**

**表 1** 硬件要求<a id="硬件要求"></a>

|项目|说明|
|--|--|
|服务器|鲲鹏服务器（开启KAE功能）|
|处理器|鲲鹏920处理器、鲲鹏920新型号处理器b、鲲鹏950处理器c|
|iBMC|V365及以上版本|
|BIOS|V105及以上版本|

>![](public_sys-resources/icon-note.gif) **说明：** <br>
>a：非虚拟化场景使用加速器建议关闭SMMU，开启SMMU会影响加速器性能，具体操作请参见《[BIOS 参数参考（鲲鹏920处理器）](https://support.huawei.com/enterprise/zh/doc/EDOC1100088653/ca8d53c6)》。<br>
>b：KAEZstd、KAELz4和KAESnappy目前仅支持在鲲鹏920新型号处理器及鲲鹏950处理器上使用。不同处理器型号支持的加密/压缩算法存在不同，详情请参见[README](../../README.md#算法支持与规格)。<br>
>c：鲲鹏950处理器仅支持使用KAE2.0。

**软件包的获取与已验证环境<a name="section1796432494313"></a>**

**表 2** KAE软件包的获取与已验证环境<a id="KAE软件包的获取与已验证环境"></a>

|软件包类型|适配的OS|适配的OpenSSL版本|获取方式|
|--|--|--|--|
|源码包|openEuler 22.03 LTS SP1/SP2/SP3/SP4aEulerOS-V2.0 SP12TencentOS 5.4|OpenSSL 1.1.1x系列OpenSSL 3.0.x系列Tongsuo 8.4.0BoringSSL|[获取链接](https://gitcode.com/boostkit/KAE)|
|RPM包|openEuler 22.03 LTS SP1/SP2/SP3/SP4a|OpenSSL 1.1.1x系列|[获取链接](https://gitcode.com/boostkit/KAE/releases)<br>若KAE代码仓没有相应OS的RPM，请参见[方式二：RPM包安装制作RPM包](#方式二rpm包安装)。|

>![](public_sys-resources/icon-note.gif) **说明：** 
>
>a：openEuler 22.03 LTS SP1仅支持KAE v2.0.3及以前版本。
>
>b：历史版本软件包请通过[Release](https://gitcode.com/boostkit/KAE/releases)获取。

**其他要求<a name="section0733155717512"></a>**

- 远程SSH登录工具已经在本地安装。
- KAE安装权限：root账户。
- KAE使用权限：root账户与非root账户。

### 获取License

由于KAE是针对硬件的加速解决方案，因此安装KAE前请确正确安装相应的License，License安装成功之后，操作系统才能识别到加速器设备。

>![](public_sys-resources/icon-note.gif) **说明：** 
>
>- 鲲鹏服务器K系列硬件KAE加速引擎已默认开启，无需申请License。
>- 鲲鹏920新型号处理器在BIOS升级至21.23及更新版本的情况下，可实现免License使用KAE加速引擎。

1. License申请和安装操作，请根据实际场景选择对应版本的《[华为服务器 iBMC 许可证 使用指导](https://support.huawei.com/enterprise/zh/management-software/ibmc-pid-8060757?category=operation-maintenance)》。

2. 安装成功后，通过**lspci**命令查看操作系统是否有加速器设备，如下所示。

    >![](public_sys-resources/icon-note.gif) **说明：** 
    >不同的操作系统**lspci**查到的加速器描述信息可能不同，除了通过关键字进行过滤，用户还可以查看是否存在HPRE/SEC/ZIP等具体型号加速器的sbdf号信息。

    1. 查看是否存在高性能RSA加速引擎HPRE。

        ```shell
        lspci | grep HPRE
        ```

        回显如下所示，说明HPRE存在。

        ```text
        79:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)
        b9:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)
        ```

    2. 查看是否存在安全加速引擎SEC。

        ```shell
        lspci | grep SEC
        ```

        回显如下信息，说明SEC存在。

        ```text
        76:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
        b6:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
        ```

    3. 查看是否存在压缩加速引擎ZIP。

        ```shell
        lspci | grep ZIP
        ```

        回显如下所示，说明ZIP存在。

        ```text
        75:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)
        b5:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)
        ```

    若执行以上命令后没有任何回显信息打印，说明操作系统中没有KAE加速器设备，请检查License是否安装成功。

### 安装OpenSSL/Tongsuo

KAE加解密模块是基于OpenSSL的，因此在安装和使用KAE加解密模块前请正确安装OpenSSL。OpenSSL版本要求为1.1.1x系列、3.0.x系列或Tongsuo 8.4.0。

>![](public_sys-resources/icon-notice.gif) **须知：** 
>若需使用非系统自带的OpenSSL/Tongsuo，请在OpenSSL/Tongsuo安装步骤中指定安装路径，并在后续源码安装的“[6](#方式一源码安装)”步骤传入该路径。

**前提条件<a name="zh-cn_topic_0200576865_section17733210143520"></a>**

- 已安装与系统版本对应的kernel-devel。

    查询当前内核版本号。

    ```shell
    uname -r
    ```

- 已安装perl、bzip2。

    查询perl、bzip2的版本号。

    ```shell
    perl --version
    bzip2 --version
    ```

- 已安装GCC、make工具，不同GCC版本下呈现出的性能数据存在差异，推荐使用7.4.1及以上版本，make推荐使用3.82及以上版本。

    查询GCC、make的版本号。

    ```shell
    gcc --version
    make --version
    ```

- 已安装automake、autoconf、libtool相关软件。

    查询automake、autoconf、libtool的版本号。

    ```shell
    automake --version
    autoconf --version
    libtool --version
    ```

尚未安装的软件请自行通过对应系统的命令行工具（例如CentOS、EulerOS和openEuler使用Yum工具，SUSE使用zypper工具）进行安装。

**安装步骤<a name="section1426493710530"></a>**

>![](public_sys-resources/icon-notice.gif) **须知：** 
>请先使用**openssl version**命令查询系统中的OpenSSL/Tongsuo版本，若OpenSSL版本为1.1.1x、3.0.x或Tongsuo版本为8.4.0，建议直接进行安装KAE操作，无需重新安装OpenSSL/Tongsuo。

1. 使用SSH远程登录工具，将OpenSSL/Tongsuo源码包拷贝到自定义路径下。

    OpenSSL源码包下载：[1.1.1x系列](https://openssl-library.org/source/old/1.1.1/index.html)、[3.0.x系列](https://openssl-library.org/source/old/3.0/index.html)、[Tongsuo 8.4.0](https://github.com/Tongsuo-Project/Tongsuo/tags)。

    >![](public_sys-resources/icon-note.gif) **说明：** 
    >Tongsuo通过**speed**命令调用自定义Engine时，在完成加解密任务后，无法释放相关资源，报段错误。该问题已在上游社区提issue跟进[issue](https://github.com/Tongsuo-Project/Tongsuo/issues/688)，使用时需先合入补丁再编译。

2. 在下载好的OpenSSL/Tongsuo源码目录下，编译安装OpenSSL/Tongsuo。

    若安装的OpenSSL/Tongsuo和OS默认的OpenSSL版本不一致，建议指定到其他目录，如“/usr/local/ssl3\_0\_14“，以防止使用过程出现版本冲突。

    - 默认路径安装配置，默认路径为“/usr/local“。

        ```shell
        ./config
        ```

    - 指定路径安装配置。
        - OpenSSL

            ```shell
            ./config --prefix=/usr/local/ssl1_1_1a
            ```

        - Tongsuo

            ```shell
            ./config --prefix=/opt/tongsuo
            ```

    >![](public_sys-resources/icon-note.gif) **说明：** 
    >该步骤会根据编译平台及环境自动生成Makefile文件，可以通过**./config --prefix**指定安装路径，**-Wl,-rpath**参数指定OpenSSL运行时依赖libcrypto、libssl库的路径。

    ```shell
    make
    make install
    ```

    OpenSSL/Tongsuo默认安装在“/usr/local“下，更加具体的安装指导请参考源码目录下的README文档。

**安装后检查<a name="section17265037195318"></a>**

- 设置PATH环境变量使**openssl**命令在全局范围使用。

    ```shell
    export PATH=/usr/local/bin:$PATH
    ```

- 查看OpenSSL版本信息。

    ```shell
    openssl version
    ```

    显示如下格式内容说明安装成功（以安装OpenSSL 1.1.1a为例）。

    ```text
    OpenSSL 1.1.1a 20 Nov 2018 
    ```

## 安装方式说明

KAE2.0支持源码安装和RPM包安装两种方式，安装前请根据实际使用操作系统选择合适的安装方式。

**表 1** KAE2.0支持的安装方式与操作系统说明<a id="KAE2.0支持的安装方式与操作系统说明"></a>

|安装方式|安装说明|当前支持系统|优缺点|
|--|--|--|--|
|源码安装|使用build.sh脚本进行安装。|openEuler 22.03 LTS-SP1/SP2/SP3/SP4EulerOS-V2.0 SP12TencentOS 5.4|优点：支持修改源码进行编译及安装。缺点：操作复杂，需要做一些额外的配置。|
|RPM安装|为了方便用户使用，华为提供了部分商用OS的RPM安装包。|openEuler 22.03 LTS-SP1/SP2/SP3/SP4EulerOS-V2.0 SP12|优点：安装后可以直接使用，不需要做编译及安装等操作。缺点：支持范围有限，仅适用于指定的操作系统。|

## 方式一：源码安装

KAE2.0源码包中包含KAEKernelDriver内核驱动、UADK框架、KAEOpensslEngine引擎和KAEZlib、KAEZstd、KAELz4模块，其中KAEKernelDriver内核驱动与UADK为必选项，其他模块按实际需求选择安装。若需要升级KAE版本，请先参见[卸载KAE](#卸载kae)章节卸载旧版本再进行新版本的安装。

**前提条件<a name="section14710172717351"></a>**

- 安装前系统环境已满足[环境要求](#环境要求)中的要求。
- 使用**openssl version**命令检查OpenSSL是否为1.1.1x或3.0.x系列或者Tongsuo版本是否为8.4.0，若不符合请参见[安装OpenSSL/Tongsuo](#安装openssltongsuo)安装OpenSSL/Tongsuo。
- 使用以下命令安装相关依赖。

    ```shell
    yum install -y make kernel-devel-`uname -r` libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath cmake libunwind-devel patch
    ```

- 设置OpenSSL环境变量“OPENSSL\_ENGINES“为KAE动态库所在目录，使OpenSSL能够识别到KAE引擎。
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

- 设置LD\_LIBRARY\_PATH环境变量，使KAE能够识别到UADK驱动动态库。

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

**安装步骤<a name="section1415911025615"></a>**

1. 使用远程登录工具，以root账号进入Linux操作系统命令行界面_。_
2. 请参见[软件包的获取](#环境部署)下载KAE2.0源码包，将KAE源码包拷贝到自定义路径下并解压。或通过以下命令下载。

    ```shell
    git clone https://gitcode.com/boostkit/KAE.git -b kae2
    ```

3. （可选）一键安装所有模块。

    当OpenSSL为1.1.1x系列，代码脚本提供一键式安装命令。进入KAE源码包目录，使用**sh build.sh all**命令安装以上所有组件内容。

    ```shell
    cd KAE
    sh build.sh all
    ```

4. 安装内核驱动。
    1. 进入KAE源码包目录中，执行安装脚本。

        ```shell
        cd KAE
        sh build.sh driver
        ```

        加速器驱动编译生成uacce.ko、hisi\_qm.ko、hisi\_sec2.ko、hisi\_hpre.ko、hisi\_zip.ko，安装路径为：“/lib/modules/\`uname -r\`/extra“。

    2. 查看驱动是否安装成功。

        - 查看“/sys/class/uacce“目录下是否存在加速引擎文件系统。

            ```shell
            ll /sys/class/uacce/
            ```

            回显信息如下所示，表示驱动安装成功。

            ```text
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec2-0
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec2-1
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-4 -> ../../devices/pci0000:74/0000:74:00.0/0000:75:00.0/uacce/hisi_zip-4
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-5 -> ../../devices/pci0000:b4/0000:b4:00.0/0000:b5:00.0/uacce/hisi_zip-5
            ```

        - 通过**lsmod**查看驱动安装情况来判断驱动是否安装成功。

            ```shell
            lsmod | grep hisi_qm
            ```

            回显信息如下所示，表示驱动安装成功。

            ```text
            hisi_qm               262144  3 hisi_sec2,hisi_zip,hisi_hpre
            uacce                 262144  1 hisi_qm
            ```

        >![](public_sys-resources/icon-note.gif) **说明：** 
        >- 若安装驱动或重启设备后查询不到设备文件，可能是操作系统自带加速驱动导致，可以卸载驱动后重新加载；或在启动脚本rc.local中加上重新加载驱动命令，以确保重启设备后能正常加载加速器驱动。
        >- 以下命令以hisi\_sec2为例重新加载：<br>
        rmmod hisi_sec2<br>
        modprobe hisi_sec2
        >- 鲲鹏920服务器上，如果执行**sh build.sh cleanup**后重新安装仍旧找不到设备文件，请确保License安装成功，若无License也会导致驱动安装失败，关于License请参见[获取License](#获取license)。
        >- KAE2.0版本安装驱动会默认将加解密及解压缩驱动一起安装，若不需要可手动卸载不需要的驱动文件。

5. 安装UADK框架。
    1. 执行安装UADK框架的脚本命令。

        ```shell
        sh build.sh uadk
        ```

        UADK框架中包含了用户态驱动，用户态驱动动态库文件为libwd.so、libwd\_crypto.so等。UADK默认安装路径为“/usr/include/uadk“，动态库文件在“/usr/local/lib“下。

        >![](public_sys-resources/icon-note.gif) **说明：** 
        >若执行安装UADK命令后失败，提示缺少头文件，则安装相关依赖包后重新执行安装命令即可。

    2. 查看UADK框架是否安装成功。

        ```shell
        ll /usr/local/lib/libwd*
        ```

        回显信息如下，表示安装成功。

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

6. 编译安装KAEOpensslEngine加速引擎。

    - OpenSSL 1.1.1x系列：
        - 使用默认路径下的OpenSSL。

            ```shell
            sh build.sh engine
            ```

        - 支持使用其他路径下的OpenSSL，如下所示。

            ```shell
            sh build.sh engine /usr/local/ssl1_1_1w
            ```

    - OpenSSL 3.0.x系列：
        - 使用默认路径下的OpenSSL。

            ```shell
            sh build.sh engine3
            ```

        - 支持使用其他路径下的OpenSSL，如下所示。

            ```shell
            sh build.sh engine3 /usr/local/ssl3_0_14
            ```

    - Tongsuo：
        - 使用默认路径下的Tongsuo。

            ```shell
            sh build.sh engine3_tongsuo
            ```

        - 支持使用其他路径下的Tongsuo，如下所示。

            ```shell
            sh build.sh engine3_tongsuo /opt/tongsuo
            ```

    KAE引擎动态库文件为libkae.so。动态库文件在“/usr/local/lib/engines-x.x“或“/usr/local/tongsuo/lib/engines-3.0“下。

7. 查看KAE引擎是否安装成功。

    - OpenSSL 1.1.1x系列：

        ```shell
        ll /usr/local/lib/engines-1.1
        ```

    - OpenSSL 3.0.x系列：

        ```shell
        ll /usr/local/lib/engines-3.0
        ```

    - Tongsuo 8.4.0：

        ```shell
        ll /usr/local/tongsuo/lib/engines-3.0
        ```

    回显信息如下，表示安装成功。

    ```text
    total 5644
    -rw-r--r--. 1 root root 3846524 Aug 22 17:28 kae.a
    -rwxr-xr-x. 1 root root     995 Aug 22 17:28 kae.la
    lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so -> kae.so.2.0.0
    lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so.2 -> kae.so.2.0.0
    -rwxr-xr-x. 1 root root 1967736 Aug 22 17:28 kae.so.2.0.0
    ```

8. 编译安装KAEZlib加速库。

    >![](public_sys-resources/icon-notice.gif) **须知：** 
    >在完成KAEZlib加速库的安装后，可以结合自身需求进行KAEGzip解压缩工具的编译安装，该解压缩工具集成了KAE硬加速接口，使用户能够更加便捷地使用鲲鹏硬加速模块进行文件的压缩和解压操作。

    1. 编译安装。

        ```shell
        sh build.sh zlib
        ```

        zlib加速库安装在“/usr/local/kaezip“。

    2. 查看zlib加速压缩库是否安装成功。

        ```shell
        ll /usr/local/kaezip/lib/
        ```

        回显信息如下所示，表示安装成功。

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

    3. <a name="li20414340916"></a>编译安装KAEGzip解压缩工具。

        ```shell
        sh build.sh gzip
        ```

        工具安装在“/usr/local/kaegzip“。

    4. <a name="li5793114715813"></a>查看KAEGzip解压缩工具是否安装成功。

        ```shell
        ldd /usr/local/kaegzip/gzip
        ```

        回显信息如下所示，表示安装成功。

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

9. 编译安装KAEZstd加速库。
    1. 编译安装。

        ```shell
        sh build.sh zstd
        ```

        KAEZstd加速库安装在“/usr/local/kaezstd“。

    2. 查看是否安装成功。

        ```shell
        ll /usr/local/kaezstd/lib/
        ```

        回显信息如下所示，表示安装成功。

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

10. 编译安装KAELz4加速库。
    1. 编译安装。

        ```shell
        sh build.sh lz4
        ```

        KAELz4加速库安装在“/usr/local/kaelz4“。

    2. 查看是否安装成功。

        ```shell
        ll /usr/local/kaelz4/lib/
        ```

        回显信息如下所示，表示安装成功。

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

11. 编译安装KAESnappy加速库。
    1. 编译安装。

        ```shell
        sh build.sh snappy
        ```

        KAESnappy加速库安装在“/usr/local/kaesnappy“。

    2. 查看是否安装成功。

        ```shell
        ll /usr/local/kaesnappy/lib/
        ```

        回显信息如下所示，表示安装成功。

        ```text
        -rwxr-xr-x 1 root root 142918 Oct 24 14:26 libkaessnappy.a
        lrwxrwxrwx 1 root root     46 Oct 24 14:26 libkaesnappy.so -> /usr/local/kaesnappy/lib/libkaesnappy.so.2.0.4
        lrwxrwxrwx 1 root root     46 Oct 24 14:26 libkaesnappy.so.0 -> /usr/local/kaesnappy/lib/libkaesnappy.so.2.0.4
        -rwxr-xr-x 1 root root  77472 Oct 24 14:26 libkaesnappy.so.2.0.4
        lrwxrwxrwx 1 root root     14 Oct 24 14:27 libsnappy.so -> libsnappy.so.1
        lrwxrwxrwx 1 root root     19 Oct 24 14:27 libsnappy.so.1 -> libsnappy.so.1.1.10
        -rwxr-xr-x 1 root root  78568 Oct 24 14:27 libsnappy.so.1.1.10
        ```

**安装后检查<a name="section196217415295"></a>**

1. 查看KAEOpensslEngine加速引擎是否生效。

    以验证RSA性能为例，验证步骤请参见[测试同步RSA性能](#安装后测试)，通过RSA性能命令可以看到指定KAE引擎之后，RSA的性能得到明显提升。

    除上述方法外，在执行RSA性能命令过程中，可以在新的终端上同时查看hisi\_hpre设备的硬件队列资源情况。同样，SM3/SM4算法可以查看hisi\_sec2的硬件队列消耗情况。

    ```shell
    cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    您也可以在执行RSA性能命令过程中通过以下命令每0.1秒刷新一次，实时查看hisi\_hpre的硬件队列消耗情况。

    ```shell
    watch -n 0.1 cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    显示结果从256变为255，说明RSA算法消耗了HPRE加速器一个硬件单元队列，说明KAEOpensslEngine加速引擎已生效。

2. 查看KAEZlib库加速引擎是否生效。通过**ldd**命令查看KAEZlib加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaezip/lib/libz.so.1.2.11
    ```

    如果有如下返回信息，说明KAEZlib加速库安装成功。同样的，用户的进程也可以通过**ldd**命令查看是否使用libwd库。

    ```text
     linux-vdso.so.1 (0x0000ffffa631d000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffa6110000)
     libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffffa60df000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffffa607e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffffa605d000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffffa62e0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffffa6038000)
    ```

3. 查看KAEZstd库加速引擎是否生效。通过**ldd**命令查看KAEZstd加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaezstd/lib/libkaezstd.so
    ```

    如果有如下返回信息，说明KAEZstd加速库安装成功。

    ```text
        linux-vdso.so.1 (0x0000ffff89774000)
        libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff896b5000)
        libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff89684000)
        libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff894d5000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffff89737000)
        libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff894b0000)
    ```

4. 查看KAELz4库加速引擎是否生效。通过**ldd**命令查看KAELz4加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaelz4/lib/libkaelz4.so
    ```

    如果有如下返回信息，说明KAELz4加速库安装成功。

    ```shell
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

5. 查看KAESnappy库加速引擎是否生效。通过**ldd**命令查看KAESnappy加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaesnappy/lib/libkaesnappy.so
    ```

    如果有如下返回信息，说明KAESnappy加速库安装成功。

    ```text
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

## 方式二：RPM包安装

KAE2.0的RPM软件包包括kae-driver、kae-openssl、kae-zip，使用加解密算法需要安装kae-driver和kae-openssl，使用KAEzip相关算法需要安装kae-driver和kae-zip。推荐使用源码的方式来安装KAE2.0，如需在openEuler以外的其他OS上通过RPM包方式安装KAE2.0，则需要通过源码制作RPM包再安装。若需要升级KAE版本，请先卸载旧版本再进行新版本的安装。

>![](public_sys-resources/icon-notice.gif) **须知：** 
>目前KAE2.0的RPM包是基于指定tag点、特定OS制作的，不具备KAE2.0的最新特性和OS的通用性。

**前提条件<a name="section9968616173616"></a>**

- RPM工具能正常使用。
- 使用**openssl version**命令检查OpenSSL是否为1.1.1x系列，若不符合请参见[安装OpenSSL/Tongsuo](#安装openssltongsuo)安装OpenSSL。
- 使用以下命令安装相关依赖。

    ```shell
    yum install -y make kernel-devel libtool numactl-devel openssl-devel chrpath  lz4-devel
    ```

- 设置OpenSSL环境变量“OPENSSL\_ENGINES“为KAE动态库所在目录，使OpenSSL能够识别到KAE引擎。

    ```shell
    export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
    ```

- 设置LD\_LIBRARY\_PATH环境变量，使KAE能够识别到UADK驱动动态库。

    ```shell
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    ```

**安装步骤<a name="section954494455617"></a>**

1. 使用SSH远程登录工具，以root账号进入Linux操作系统命令行界面。
2. 请参见[软件包的获取](#环境部署)将获取到的KAE2.0 RPM软件包拷贝到自定义路径下。

    若KAE代码仓没有相应OS的RPM，则需要通过以下步骤制作RPM包。

    1. 请从[Gitcode](https://gitcode.com/boostkit/KAE.git)获取KAE2.0源码包，或通过以下命令下载。

        ```shell
        git clone https://gitcode.com/boostkit/KAE.git -b kae2
        ```

    2. 在KAE源码目录制作RPM包。

        ```shell
        sh build.sh rpmpack
        ```

3. 安装加速驱动软件RPM包kae-driver。

    ```shell
    rpm -ivh kae-driver-2.0.1-1.aarch64.rpm
    ```

    回显结果如下即表明安装成功。

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

    >![](public_sys-resources/icon-note.gif) **说明：** 
    >若安装驱动或重启设备后查询不到设备文件，可能是操作系统自带加速驱动导致，可以卸载驱动后重新加载；或在启动脚本rc.local中加上重新加载驱动命令，以确保重启设备后能正常加载加速器驱动。以下命令以hisi\_sec2为例重新加载：
    >
    >```shell
    >rmmod hisi_sec2
    >modprobe hisi_sec2
    >```

4. 安装引擎库软件RPM包kae-openssl。

    ```shell
    rpm -ivh kae-openssl-2.0.1-1.aarch64.rpm
    ```

    回显结果如下即表明安装成功。

    ```text
    Verifying...                          ################################# [100%]
    Preparing...                          ################################# [100%]
    Updating / installing...
       1:kae-openssl-2.0.1-1              ################################# [100%]
    installing openssl engine...
    ```

5. 安装KAEZip软件RPM包kae-zip。

    ```shell
    rpm -ivh kae-zip-2.0.1-1.aarch64.rpm
    ```

    回显结果如下即表明安装成功。

    ```text
    Verifying...                          ################################# [100%]
    Preparing...                          ################################# [100%]
    installing pre zip...
    Updating / installing...
       1:kae-zip-2.0.1-1                  ################################# [100%]
    installing post zip...
    ```

6. 查看相关软件是否已正常安装到系统内。
    1. 查看驱动是否安装成功。
        - 查看“/sys/class/uacce“目录下是否存在加速引擎文件系统。

            ```shell
            ll /sys/class/uacce/
            ```

            回显信息如下所示，表示驱动安装成功。

            ```text
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec2-0
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec2-1
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-4 -> ../../devices/pci0000:74/0000:74:00.0/0000:75:00.0/uacce/hisi_zip-4
            lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-5 -> ../../devices/pci0000:b4/0000:b4:00.0/0000:b5:00.0/uacce/hisi_zip-5
            ```

        - 通过**lsmod**查看驱动安装情况来判断驱动是否安装成功。

            ```shell
            lsmod | grep uacce
            ```

            回显信息如下所示，表示驱动安装成功。

            ```text
            uacce                  32768  3 hisi_sec2,hisi_qm,hisi_zip
            ```

    2. 查看UADK框架是否安装成功。

        ```shell
        ll /usr/local/lib/libwd*
        ```

        回显信息如下，表示安装成功。

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

    3. 查看KAE引擎是否安装成功。

        ```shell
         ll /usr/local/lib/engines-1.1
        ```

        回显信息如下，表示安装成功。

        ```text
        total 5644
        -rw-r--r--. 1 root root 3846524 Aug 22 17:28 kae.a
        -rwxr-xr-x. 1 root root     995 Aug 22 17:28 kae.la
        lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so -> kae.so.2.0.0
        lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so.2 -> kae.so.2.0.0
        -rwxr-xr-x. 1 root root 1967736 Aug 22 17:28 kae.so.2.0.0
        ```

    4. 查看KAEZip解压缩模块是否安装成功。

        ```shell
        ll /usr/local/kaezip/lib
        ```

        回显信息如下，表示安装成功。

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

**安装后检查<a name="section13545944105612"></a>**

1. 查看KAE RPM软件包。

    ```shell
    rpm -qa kae-driver kae-openssl kae-zip
    ```

    显示以下格式内容说明安装成功。

    ```text
    kae-openssl-2.0.1-1.aarch64
    kae-driver-2.0.1-1.aarch64
    kae-zip-2.0.1-1.aarch64
    ```

2. 查看虚拟文件系统下对应的加速器设备。

    ```shell
    ls -al /sys/class/uacce/
    ```

    回显结果如下。

    ```text
    total 0
    lrwxrwxrwx. 1 root root 0 Nov 14 03:45 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
    lrwxrwxrwx. 1 root root 0 Nov 14 03:45 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
    lrwxrwxrwx. 1 root root 0 Nov 14 08:39 hisi_sec-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec-0
    lrwxrwxrwx. 1 root root 0 Nov 14 08:39 hisi_sec-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec-1
    lrwxrwxrwx.  1 root root 0 Dec  5 18:59 hisi_zip-4 -> ../../devices/pci0000:74/0000:74:00.0/0000:75:00.0/uacce/hisi_zip-4
    lrwxrwxrwx.  1 root root 0 Dec  5 18:59 hisi_zip-5 -> ../../devices/pci0000:b4/0000:b4:00.0/0000:b5:00.0/uacce/hisi_zip-5
    ```

3. 查看KAEOpensslEngine加速引擎是否生效。

    以验证RSA性能为例，验证步骤请参见[测试同步RSA性能](#安装后测试)，通过RSA性能命令可以看到指定KAE引擎之后，RSA的性能得到明显提升。

    除上述方法外，在执行RSA性能命令过程中，可以在新的终端上同时查看hisi\_hpre设备的硬件队列资源情况。同样，SM3/SM4算法可以查看hisi\_sec2的硬件队列消耗情况。

    ```shell
    cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    您也可以通过以下命令每0.1秒刷新一次，实时查看hisi\_hpre的硬件队列消耗情况。

    ```shell
    watch -n 0.1 cat /sys/class/uacce/hisi_hpre-*/available_instances
    ```

    显示结果从256变为255，说明RSA算法消耗了HPRE加速器一个硬件单元队列，说明KAEOpensslEngine加速引擎已生效。

4. 查看KAEZip库加速引擎是否生效。通过**ldd**命令查看KAEZip加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaezip/lib/libz.so.1.2.11
    ```

    如果有如下返回信息，说明KAEZlib加速库安装成功。同样的，用户的进程也可以通过**ldd**命令查看是否使用libwd库。

    ```shell
    linux-vdso.so.1 (0x0000ffffa631d000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffa6110000)
     libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffffa60df000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffffa607e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffffa605d000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffffa62e0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffffa6038000)
    ```

5. 查看KAEZstd库加速引擎是否生效。通过**ldd**命令查看KAEZstd加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaezstd/lib/libkaezstd.so
    ```

    如果有如下返回信息，说明KAEZstd加速库安装成功。

    ```text
            linux-vdso.so.1 (0x0000ffff89774000)
            libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff896b5000)
            libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff89684000)
            libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff894d5000)
            /lib/ld-linux-aarch64.so.1 (0x0000ffff89737000)
            libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff894b0000)
    ```

6. 查看KAELz4库加速引擎是否生效。通过**ldd**命令查看KAELz4加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaelz4/lib/libkaelz4.so
    ```

    如果有如下返回信息，说明KAELz4加速库安装成功。

    ```shell
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

7. 查看KAESnappy库加速引擎是否生效。通过**ldd**命令查看KAESnappy加速库是否链接到libwd库。

    ```shell
    ldd /usr/local/kaesnappy/lib/libkaesnappy.so
    ```

    如果有如下返回信息，说明KAESnappy加速库安装成功。

    ```text
     linux-vdso.so.1 (0x0000ffff84add000)
     libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff84a0e000)
     libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff849dd000)
     libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff8482e000)
     /lib/ld-linux-aarch64.so.1 (0x0000ffff84aa0000)
     libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff84809000)
    ```

## 安装后测试

### KAE加解密库测试

用户可以通过本节提供的命令测试RSA同步/异步模式、SM3模式、SM4 CBC模式和AES CBC异步模式下调用KAE加解密库前后的性能提升效果。

>![](public_sys-resources/icon-note.gif) **说明：** 
>若加解密库为Tongsuo，测试方法与OpenSSL一致。
>本测试数据源自鲲鹏920处理器及CentOS 7.6操作系统环境。

**检查OpenSSL<a name="section33586710151"></a>**

查看OpenSSL版本。

```shell
openssl version
```

如果不是安装KAE时的OpenSSL，可以设置如下环境变量来指定OpenSSL。以下命令中“/path/install“为OpenSSL的安装路径。

```shell
export PATH=/path/install/bin:$PATH
export LD_LIBRARY_PATH=/path/install/lib:$LD_LIBRARY_PATH
```

**测试同步RSA性能<a name="section54081455216"></a>**

- 使用OpenSSL的软件算法测试RSA性能。

    ```shell
    openssl speed -elapsed rsa2048
    ```

    显示结果如下。

    ```text
    ...
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.001384s 0.000035s   724.1  28365.8.
    ```

- 使用KAE加速引擎测试RSA性能。

    ```shell
    openssl speed -elapsed -engine kae rsa2048
    ```

    显示结果如下。

    ```text
    ....
                     sign    verify    sign/s verify/s
    rsa 2048 bits 0.000355s 0.000022s   2819.0  45478.4
    ```

>![](public_sys-resources/icon-note.gif) **说明：** 
>使用KAE加速引擎加速后签名性能从724.1 sign/s提升到2819 sign/s。

**测试异步RSA性能<a name="section115401118424"></a>**

- 使用OpenSSL的软件算法测试异步RSA性能。

    ```shell
    openssl speed -elapsed -async_jobs 36 rsa2048 
    ```

    显示结果如下。

    ```text
    ....
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.001318s 0.000032s    735.7  28555
    ```

- 使用KAE加速引擎测试异步RSA性能。

    ```shell
    openssl speed -engine kae -elapsed -async_jobs 36 rsa2048 
    ```

    显示结果如下。

    ```text
    .... 
                      sign    verify    sign/s verify/s
    rsa 2048 bits 0.000018s 0.000009s  54384.1 105317.0
    ```

>![](public_sys-resources/icon-note.gif) **说明：** 
>使用KAE加速引擎加速后异步RSA签名性能从735.7 sign/s提升到54384.1 sign/s。

**测试SM4 CBC模式性能<a name="section059717381527"></a>**

- 使用OpenSSL的软件算法测试SM4 CBC模式性能。

    ```shell
    openssl speed -elapsed -evp sm4-cbc
    ```

    显示结果如下。

    ```text
    You have chosen to measure elapsed time instead of user CPU time.
    ....
    Doing sm4-cbc for 3s on 10240 size blocks: 2196 sm4-cbc's in 3.00s  ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm4-cbc          82312.53k    85196.80k    85284.18k    85000.85k    85284.18k    85261.26k
    ```

- 使用KAE加速引擎测试SM4 CBC模式性能。

    ```shell
    openssl speed -elapsed -engine kae -evp sm4-cbc
    ```

    显示结果如下。

    ```text
    engine "kae" set. 
    You have chosen to measure elapsed time instead of user CPU time.
    ...
    Doing sm4-cbc for 3s on 1048576 size blocks: 11409 sm4-cbc's in 3.00s
    ...
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm4-cbc         383317.33k   389427.20k   395313.15k   392954.73k   394264.58k   394264.58k
    ```

>![](public_sys-resources/icon-note.gif) **说明：** 
>使用KAE加速后SM4 CBC模式在输入数据块大小为8MB时，性能从82312.53k/s提升到383317.33k/s。

**测试SM3模式性能<a name="section1220591319313"></a>**

- 使用OpenSSL的软件算法测试SM3模式性能。

    ```shell
    openssl speed -elapsed -evp sm3
    ```

    显示如下结果。

    ```text
    You have chosen to measure elapsed time instead of user CPU time.
    Doing sm3 for 3s on 102400 size blocks: 1536 sm3's in 3.00s
    ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm3              50568.53k    52428.80k    52428.80k    52428.80k    52428.80k    52428.80k
    ```

- 使用KAE加速引擎测试SM3模式性能。

    ```shell
    openssl speed -elapsed -engine kae -evp sm3
    ```

    显示如下结果。

    ```text
    engine "kae" set.
    You have chosen to measure elapsed time instead of user CPU time.
    Doing sm3 for 3s on 102400 size blocks: 19540 sm3's in 3.00s
    ....
    type            51200 bytes  102400 bytes  1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    sm3             648243.20k   666965.33k   677030.57k   678778.20k   676681.05k   668292.44k
    ```

>![](public_sys-resources/icon-note.gif) **说明：** 
>使用KAE加速后SM3算法在输入数据块大小为8MB时，性能从52428.80k/s提升到668292.44k/s。

**测试AES算法CBC模式异步性能<a name="section1018002911311"></a>**

- 使用OpenSSL软件算法测试AES算法CBC模式异步性能。

    ```shell
    openssl speed -elapsed -evp aes-128-cbc -async_jobs 4
    ```

    显示结果如下。

    ```text
    You have chosen to measure elapsed time instead of user CPU time.
    Doing aes-128-cbc for 3s on 51200 size blocks: 65773 aes-128-cbc's in 3.00s
    Doing aes-128-cbc for 3s on 102400 size blocks: 32910 aes-128-cbc's in 3.00s
    ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    aes-128-cbc    1122525.87k  1123328.00k  1120578.22k  1121277.27k  1119879.17k  1115684.86k
    ```

- 使用KAE加速引擎测试AES算法CBC模式异步性能。

    ```shell
    openssl speed -elapsed -evp aes-128-cbc -async_jobs 4 -engine kae
    ```

    结果显示如下。

    ```text
    engine "kae" set.
    You have chosen to measure elapsed time instead of user CPU time.
    Doing aes-128-cbc for 3s on 51200 size blocks: 219553 aes-128-cbc's in 3.00s
    Doing aes-128-cbc for 3s on 102400 size blocks: 117093 aes-128-cbc's in 3.00s
    ....
    type          51200 bytes 102400 bytes 1048576 bytes 2097152 bytes 4194304 bytes 8388608 bytes
    aes-128-cbc    3747037.87k  3996774.40k  1189085.18k  1196774.74k  1196979.11k  1199570.94k
    ```

>![](public_sys-resources/icon-note.gif) **说明：** 
>
>- OpenSSL的测试数据的长度定义在speed.c文件中（speed.c文件在openssl源代码包的app目录下，例如：openssl-1.1.1a/apps/speed.c）的lengths\_list数组中，测试者可以在此处修改该数据，然后请参见[安装OpenSSL/Tongsuo](#安装openssltongsuo)章节编译安装OpenSSL后进行测试。（本文中的51200bytes 102400bytes......等测试数据长度就是这样来的。）
>- AES仅支持数据长度为256KB及以下的异步操作。
>- 使用KAE加速后AES算法在输入数据块为100KB大小时，性能从1123328.00k/s提升到3996774.40k/s。

### KAEZlib压缩库测试

用户安装KAEZlib后，可以通过本节提供的操作步骤测试压缩库功能和性能。

>![](public_sys-resources/icon-notice.gif) **须知：** 
>测试步骤需要在源码目录下操作。若KAE是通过RPM包方式安装，则在执行测试之前需要下载并解压KAE源码。

1. 请参见[源码安装](#方式一源码安装)或[RPM包安装](#方式二rpm包安装)安装KAEZlib。
2. 进入测试目录。

    ```shell
    cd KAEZlib/test/gtest/
    ```

3. 测试KAEZlib加速库功能。

    ```shell
    sh build.sh
    ./kaezlibtest --gtest_filter=*Case*
    ```

    显示结果如下，SmallCase与LargeCase两个用例的执行结果均为**passed**，表明KAEZlib加速库功能正常。

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

4. 测试性能。
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

        - 使用zip测试压缩性能

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

        - 使用KAEzip测试压缩性能

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

        - 使用zip测试解压缩性能

            ```shell
            ./zip_perf -d -m 8 -f itemdata.zlib -n 1000
            ```

            显示结果如下。

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

        - 使用KAEzip测试解压缩性能

            ```shell
            ./kaezip_perf -d -m 8 -f itemdata.zlib -n 1000
            ```

            显示结果如下。

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

        可以看到解压缩速度从1.482GB/s提升到了9.422GB/s。

5. 若安装了KAEGzip解压缩工具，可通过下列步骤进行功能及性能验证。
    1. 获取帮助信息。

        ```shell
        /usr/local/kaegzip/gzip -h
        ```

    2. 功能测试。

        1. 使用KAEGzip压缩工具压缩itemdata文件，itemdata文件会被压缩为itemdata.gz文件，同时保留源文件itemdata。

            ```shell
            /usr/local/kaegzip/gzip -k itemdata
            ```

        2. 将源文件itemdata重命名为itemdata.orig。

            ```shell
            mv itemdata itemdata.orig
            ```

        3. 使用KAEGzip压缩工具解压缩itemdata.gz文件。

            ```shell
            /usr/local/kaegzip/gzip -d itemdata.gz 
            ```

        4. 比较使用KAEGzip压缩工具解压缩后的文件和源文件itemdata.orig。

            ```shell
            diff itemdata itemdata.orig 
            ```

        若没有任何回显信息返回，则表示KAEGzip工具能正确地完成文件的压缩解压。

    3. 测试压缩性能。

        - 使用Gzip工具

            ```shell
            time gzip itemdata
            ```

            回显示例如下。

            ```text
            real 0m0.348s
            user 0m0.343s
            sys 0m0.004s
            ```

        - 使用KAEGzip工具

            ```shell
            time /usr/local/kaegzip/gzip itemdata
            ```

            回显示例如下。

            ```text
            real 0m0.016s
            user 0m0.005s
            sys 0m0.010s
            ```

        可以看到相较于系统自带的Gzip工具，KAEGzip工具的压缩耗时均明显减少。

    4. 测试解压缩性能。

        - 使用Gzip工具

            ```shell
            time gzip -d itemdata.gz 
            ```

            回显示例如下。

            ```text
            real 0m0.038s
            user 0m0.031s
            sys 0m0.008s
            ```

        - 使用KAEGzip工具

            ```shell
            time /usr/local/kaegzip/gzip -d itemdata.gz 
            ```

        - 回显示例如下。

            ```text
            real 0m0.017s
            user 0m0.004s
            sys 0m0.012s
            ```

        可以看到相较于系统自带的Gzip工具，KAEGzip工具的解压耗时均明显减少。

6. 关于异步接口的使用及测试，参见KAEZlib目录的[README](../../KAEZlib/README.md)。

### KAEZstd压缩库测试

用户安装KAEZstd库后，可以通过本节提供的操作步骤测试KAEZstd压缩库功能和性能。

1. 请参见[源码安装](#方式一源码安装)或[RPM包安装](#方式二rpm包安装)安装KAEZstd。
2. 测试ZSTD压缩库功能。

    ```shell
    cd /KAE/KAEZstd/test/gtest
    mkdir build && cd build
    cmake ..
    make
    ./zstd_functest
    ```

3. 测试性能。
    - 使用系统自带ZSTD压缩库进行测试。

        ```shell
        zstd -b3 /home/KAE/scripts/compressTestDataset/itemdata
        ```

        显示结果如下。

        ```text
        3#itemdata   :  7316868   ->  1977124 (x3.701),  201.7 MB/s, 845.0 MB/s
        ```

    - 使用KAEZstd压缩库进行测试。

        ```shell
        /usr/local/kaezstd/bin/zstd -b3 /home/KAE/scripts/compressTestDataset/itemdata
        ```

        显示结果如下。

        ```text
        3#itemdata   :  7316868   ->  2158294 (x3.390), 438.5 MB/s, 1233.2 MB/s
        ```

        可以看到压缩速度从201.7MB/s提升到了438.5MB/s，压缩性能明显提升。

### KAELz4压缩库测试

用户安装KAELz4库后，可以通过本节提供的操作步骤测试KAELz4压缩库功能和性能。

**同步测试<a name="section371134572320"></a>**

用户安装KAELz4库后，基于“/KAE/KAELz4/open\_source/lz4-1.9.4/test“内开源压缩算法的测试脚本以及kunpeng-lzbench测试工具，测试KAELz4压缩库同步功能和性能。

1. 请参见[源码安装](#方式一源码安装)或[RPM包安装](#方式二rpm包安装)完成KAELz4的安装。
2. 从[Gitee](https://gitee.com/kunpeng_compute/lzbench)仓获取lzbench源码，并在源码路径下使用make命令编译生成二进制工具。
3. 测试LZ4压缩库功能。

    ```shell
    cd /KAE/KAELz4/open_source/lz4-1.9.4/tests
    make
    ./fullbench datagen
    ```

4. 测试性能。
    1. 进入lzbench源码路径，查看测试工具所使用的算法库。

        ```shell
        ldd lzbench
        ```

        回显如下内容，表示使用的是开源Lz4算法库。

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

    2. 调用开源Lz4算法库测试解压缩性能，测试文件位于“KAE/scripts/compressTestDataset“路径下。

        ```shell
        taskset -c 1 ./lzbench -relz4 -b8 -i1 -j -m1024 /pathtoKAE/scripts/compressTestDataset/
        ```

        显示结果如下。

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26722 MB/s 27211 MB/s   102760022    102760022 100.00 8 files
        lz4 1.9.4                 472 MB/s  2900 MB/s   102760022     61462487  59.81 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

    3. 设置环境变量LD\_LIBRARY\_PATH启用KAELz4加速库，查看测试工具所使用的算法库。

        ```shell
        export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:$LD_LIBRARY_PATH
        ldd lzbench
        ```

        回显如下内容，表示使用的是KAELz4算法库。

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

    4. 调用KAELz4库测试解压缩性能。

        ```shell
        taskset -c 1 ./lzbench -relz4 -b8 -i1 -j -m1024 ../../../../scripts/compressTestDataset/
        ```

        显示结果如下。

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26929 MB/s 26177 MB/s   102760022    102760022 100.00 8 files
        lz4 1.9.4                 840 MB/s  3030 MB/s   102760022     58783964  57.21 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

5. 测试压缩带宽。
    1. 设置环境变量LD\_LIBRARY\_PATH并启用LZ4加速库。

        ```shell
        export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:$LD_LIBRARY_PATH
        ```

    2. 在“/KAE/KAELz4/test/perftest“目录下编译带宽测试工具。

        ```shell
        cd KAE/KAELz4/test/perftest
        make
        ```

    3. 使用LZ4加速库测试压缩带宽。

        ```shell
        ./kaelz4_perf -m 80 -b 32 -l 640000
        ```

        显示结果如下。

        ```text
        kaelz4 perf parameter: multi process 64, stream length: 640000(KB), block size: 32(KB), compress level: 1, compress function: 0, loop times: 1, g_threadnum: 15, core sequence: 0 ~ 63
        kaelz4 compress perf result:
             time used: 82891615 us, speed = 7.069 GB/s
        ```

**异步测试<a name="section3413841245"></a>**

用户安装KAELz4库后，基于“/KAE/scripts/perftest/kzip“内的测试脚本，测试KAELz4压缩库异步功能和性能。

1. 请参见[源码安装](#方式一源码安装)或[RPM包安装](#方式二rpm包安装)安装KAELz4。
2. 测试KAELz4压缩库异步接口的功能。

    ```shell
    cd KAE/scripts/perftest/kzip
    sh scripts/runFunc.sh
    ```

3. 开启驱动fast模式，设置特定有效压缩窗长以达到最大性能。

    ```shell
    rmmod hisi_zip  
    modprobe hisi_zip perf_mode=1 uacce_mode=2 pf_q_num=256
    export KAE_LZ4_WINTYPE=8 
    export KAE_LZ4_COMP_TYPE=8
    ```

4. 测试KAELz4压缩库异步接口的性能。
    1. 8KB分片block异步接口性能。

        ```shell
        cd KAE/scripts/perftest/kzip
        sh runPerf.sh -A kaelz4async_block -m 1 -n 270000 -s 8
        ```

        显示结果如下：

        ```text
        kzip perf parameter: algorithm: kaelz4async_block, multi process 1, threadNum 1, stream length: 1024(KB), loop times: 270000, window_bits : 15, level : 6, chunk: 8
        compress filename : ../../../scripts/compressTestDataset/calgary
        kaelz4async_block compress perf result when loop 270000 times: file:../../../scripts/compressTestDataset/calgary. chunk 8 kb. time used: 58649811 us, speed = 13.941 GB/s iops = 1827.627k, compress latency avg = 0.547us, latency avg per io = 35.018us
        compress_size is 495878498755B = 472906.594MB, compress_rate is 1.770
        ```

    2. 8KB分片frame异步接口性能。

        ```shell
        cd KAE/scripts/perftest/kzip
        sh runPerf.sh -A kaelz4async_frame -m 1 -n 270000 -s 8
        ```

        显示结果如下：

        ```text
        kzip perf parameter: algorithm: kaelz4async_frame, multi process 1, threadNum 1, stream length: 1024(KB), loop times: 270000, window_bits : 15, level : 6, chunk: 8
        compress filename : ../../../scripts/compressTestDataset/calgary
        kaelz4async_frame compress perf result when loop 270000 times: file:../../../scripts/compressTestDataset/calgary. chunk 8 kb. time used: 58952173 us, speed = 13.869 GB/s iops = 1818.254k, compress latency avg = 0.550us, latency avg per io = 35.199us
        compress_size is 497489513676B = 474442.969MB, compress_rate is 1.765
        ```

### KAESnappy压缩库测试

用户安装KAESnappy库后，可以通过本节提供的操作步骤测试KAESnappy压缩库性能。

1. 请参见[源码安装](#方式一源码安装)或[RPM包安装](#方式二rpm包安装)完成KAESnappy的安装。
   
2. 从[Gitee](https://gitee.com/kunpeng_compute/lzbench)仓获取lzbench源码，并在源码路径下使用make命令编译生成二进制工具。

3. 测试性能。
    1. 进入lzbench源码路径，查看测试工具所使用的算法库。

        ```shell
        ldd lzbench
        ```

        回显如下内容，表示使用的是开源Snappy算法库。

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

    2. 调用开源Snappy算法库测试解压缩性能，测试文件位于“KAE/scripts/compressTestDataset“路径下。

        ```shell
        taskset -c 1 ./lzbench -resnappy -b8 -i1 -j -m1024 /pathtoKAE/scripts/compressTestDataset/
        ```

        显示结果如下。

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26722 MB/s 27211 MB/s   102760022    102760022 100.00 8 files
        snappy 2020-07-11         475 MB/s  1518 MB/s   102760022     61338103  59.69 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

    3. 设置环境变量LD\_LIBRARY\_PATH启用KAESnappy加速库，查看测试工具所使用的算法库。

        ```shell
        export LD_LIBRARY_PATH=/usr/local/kaesnappy/lib:$LD_LIBRARY_PATH
        ldd lzbench
        ```

        回显如下内容，表示使用的是KAESnappy算法库。

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

    4. 调用KAESnappy库测试解压缩性能。

        ```shell
        taskset -c 1 ./lzbench -resnappy -b8 -i1 -j -m1024 /pathtoKAE/scripts/compressTestDataset/
        ```

        显示结果如下。

        ```text
        lzbench 1.8 (64-bit Linux)  (null)
        Assembled by P.Skibinski
        
        Compressor name         Compress. Decompress.  Orig. size  Compr. size  Ratio Filename
        memcpy                  26929 MB/s 26177 MB/s   102760022    102760022 100.00 8 files
        snappy 2020-07-11         738 MB/s  1570 MB/s   102760022     57612940  56.07 8 files
        done... (cIters=1 dIters=1 cTime=1.0 dTime=2.0 chunkSize=8KB cSpeed=0MB)
        ```

## 卸载KAE

用户不再使用KAE，或需要进行新版本KAE的安装时，请参考本节内容卸载KAE。

**卸载源码安装的KAE2.0<a name="section126341424597"></a>**

1. 使用SSH远程登录工具，以root账号进入Linux操作系统命令行界面。
2. 源码方式安装的加速器驱动包及KAE加速引擎库包通过脚本命令进行卸载。

    - 卸载驱动。

        ```shell
        cd KAE
        sh build.sh driver clean
        ```

    - 卸载UADK。

        ```shell
        sh build.sh uadk clean
        ```

    - 卸载KAE加速引擎。
        - OpenSSL 1.1.1x：

            ```shell
            sh build.sh engine clean
            ```

        - OpenSSL 3.0.x：

            ```shell
            sh build.sh engine3 clean
            ```

        - Tongsuo 8.4.0：

            ```shell
            sh build.sh engine3_tongsuo clean
            ```

    - 卸载KAEZlib。

        ```shell
        sh build.sh zlib clean
        ```

        若安装了KAEGzip解压缩工具，可通过下列命令卸载。

        ```shell
        sh build.sh gzip clean
        ```

    - 卸载KAEZstd。

        ```shell
        sh build.sh zstd clean
        ```

    - 卸载KAELz4。

        ```shell
        sh build.sh lz4 clean
        ```

    - 卸载KAESnappy。

        ```shell
        sh build.sh snappy clean
        ```

    >![](public_sys-resources/icon-note.gif) **说明：** 
    >也可以通过**sh build.sh cleanup**命令一键式卸载默认安装路径的KAE组件。

**卸载RPM安装的KAE2.0<a name="section963562418918"></a>**

1. 使用SSH远程登录工具，以root账号进入Linux操作系统命令行界面。
2. 卸载KAE加速引擎相关软件包并检查卸载情况。
    1. 使用**rpm -e  _软件包名_**命令卸载kae-openssl、kae-driver和kae-zip。

        ```shell
        rpm -e kae-openssl
        rpm -e kae-driver
        rpm -e kae-zip
        ```

    2. 查询RPM包是否卸载成功。

        使用**rpm -qa | grep  _软件包名_**命令。

        ```shell
        rpm -qa | grep kae-openssl 
        rpm -qa | grep kae-driver
        rpm -qa | grep kae-zip
        ```

3. 查询KAE是否卸载成功。
    1. 查询KAE加速引擎软件库是否卸载，回显**No such file or directory**即卸载成功。

        ```shell
        ll /usr/local/lib/engines-1.1
        ```

    2. 查询KAEZip加速引擎软件库是否卸载，回显**No such file or directory**即卸载成功。

        ```shell
        ll /usr/local/kaezip/lib
        ```

    3. 查看KAE驱动是否已经卸载，没有回显内容即卸载成功。

        ```shell
        lsmod | grep uacce
        ```
