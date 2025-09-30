# 一、背景及规格

## 1.1、背景说明

鲲鹏加速引擎是基于鲲鹏处理器提供的硬件加速解决方案，包含了 KAE 加解密和 KAE 解压缩两个模块，分别用于加速 SSL/TLS 应用和数据压缩，可以显著降低处理器消耗，提高处理器效率。此外，加速引擎对应用层屏蔽了其内部实现细节，用户通过 OpenSSL、zlib标准接口即可以实现快速迁移现有业务。

本文介绍了 KAE 的安装流程。

## 1.2、版本说明

鲲鹏加速引擎（KAE）是一款基于鲲鹏 920 处理器研发的加速器。由于不同内核版本的差异，KAE 存在两套代码用于支持不同的内核代码，分别是 KAE1.0 和 KAE2.0 两套代码分支。其中，KAE1.0 适用于 4.19 内核；而 KAE2.0 适用于 5.X 内核（其中TOS适配了5.4内核版本）。

| 内核版本 | 设备形态 | KAE1.0        | KAE2.0        |
| ---------- | ---------- | --------------- | --------------- |
| 4.19     | 920      | **YES** | NA            |
| 5.4     | 920 / 920X     | NA            | **YES** |
| 5.10    | 920  / 920X    | NA            | **YES** |

> 由于不同版本内核接口可能存在差异，不同的操作系统使能KAE需要实际编译内核驱动验证是否匹配，若特定OS内核编译KAE驱动遇到接口报错，则说明驱动不兼容。

# 二、安装前准备

根据芯片款型及内核版本选择适合的KAE代码进行安装，安装前需要确定环境信息及安装license。

## 2.1 License安装

安装鲲鹏KAE加速引擎之前需要先安装相应的License，License安装成功之后，操作系统才能识别到加速器设备。

> TaiShan K系列服务器硬件KAE加速引擎已默认开启，无需申请License。
> 920新型号后续更新BIOS可以免license使用，具体BIOS版本待发布再更新

具体License申请使用操作可参考《[华为服务器iBMC许可证 使用指导](https://support.huawei.com/enterprise/zh/management-software/ibmc-pid-8060757?category=operation-maintenance "https://support.huawei.com/enterprise/zh/management-software/ibmc-pid-8060757?category=operation-maintenance")》。

通过**lspci**命令进行查看操作系统是否有加速器设备，如下所示。

```shell
lspci | grep HPRE
79:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)
b9:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)

lspci | grep ZIP
75:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)
b5:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)

lspci | grep SEC
76:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
b6:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
```

## 2.2 软件包获取

基于硬件cpu款型及内核OS情况，选择正确的KAE版本后，再获取软件包，用于后续安装。

### 2.2.2 KAE1.0软件包获取

KAE2.0 版本支持RPM包安装、源码安装两种种方式。

* **RPM包获取** KAE2.0 rpm包下载地址：尚未发布
* **源码包获取** KAE2.0 源码下载方式：git clone [https://gitee.com/kunpengcompute/KAE.git](https://gitee.com/kunpengcompute/KAE.git "https://gitee.com/kunpengcompute/KAE.git") -b kae1 或者访问Kunpeng/KAE代码仓下载源码包：[https://gitee.com/kunpengcompute/KAE](https://gitee.com/kunpengcompute/KAE "https://gitee.com/kunpengcompute/KAE")

## 2.4 KAE1.0安装

### 2.4.1 RPM包安装

RPM包在gitee社区[release界面](https://gitee.com/kunpengcompute/KAE/releases)，搜索1.X对应的rpm包

前提条件： 请保证rpm下载完成，并且license获取成功。 RPM或dpkg工具能正常使用。 OpenSSL 1.1.1a或以上版本已正确安装。

> hisi\_hpre，hisi\_sec2，hisi\_rde驱动软件包依赖于uacce软件包；libkae引擎软件包依赖于libwd软件包。 如果仅加速RSA/DH算法建议只需要安装uacce、hisi\_hpre、libwd、libkae软件包。 如果仅加速AES/MD5/SM3/SM4算法建议只需要安装uacce、hisi\_sec2、libwd、libkae软件

* 步骤1 使用SSH远程登录工具，以root帐号进入Linux操作系统命令行界面。
* 步骤2 将KAE加速引擎软件包拷贝到自定义路径下。
* 步骤3 安装加速驱动软件包。
  
  > * 可以通过**rpm -ivh \*.rpm**安装所有KAE加速引擎软件包。
  >   ```shell
  >   [root]rpm -ivh *.rpm
  >   Preparing...                          ################################# [100%]
  >   checking installed modules
  >   Updating / installing...
  >       1:uacce-1.0.1-1.centos7.6         ################################# [ 14%]
  >   modules installed
  >       2:libwd-1.0.1-1.centos7.6         ################################# [ 29%]
  >       3:libkae-1.0.1-1.centos7.6        ################################# [ 43%]
  >   checking installed modules
  >       4:hisi_hpre-1.0.1-1.centos7.6     ################################# [ 57%]
  >   modules installed
  >   checking installed modules
  >       5:hisi_rde-1.0.1-1.centos7.6      ################################# [ 71%]
  >   modules installed
  >   checking installed modules
  >       6:hisi_sec2-1.0.1-1.centos7.6     ################################# [ 86%]
  >   modules installed
  >   checking installed modules
  >       7:hisi_zip-1.0.1-1.centos7.6      ################################# [100%]
  >   checking installed modules
  >   ```
  > * 也可以按需依次安装rpm，以下以uacce-1.0.1为例
  >   ```shell
  >   [root]rpm -ivh uacce-1.0.1-1.centos7.6.aarch64.rpm
  >   Preparing...                          ################################# [100%]
  >   checking installed modules
  >   Updating / installing... 
  >   1:uacce-1.0.1-1.centos7.6             ################################# [100%]
  >   modules installed
  >   ```
  > * 安装libkae引擎软件包时还需要通过--prefix指定OpenSSL引擎的路径，命令与回显结果如下：
  >   ```shell
  >   [root]rpm -ivh libkae-1.0.1-1.centos7.6.aarch64.rpm      --prefix=/usr/local/lib/engines-1.1
  >   Preparing...                          ################################# [100%]
  >   Updating / installing...
  >       1:libkae-1.0.1-1.centos7.6        ################################# [100%]
  >   ```
* 步骤4 查看RPM软件是否已正常安装到系统内。
  
  > * 查看uacce是否已安装。
  >   
  >   ```shell
  >   rpm -ql uacce
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/hisi_qm.ko
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/uacce.ko
  >   ```
  > * 查看hisi\_sec2、hisi\_hpre、hisi\_rde是否已安装。
  >   
  >   ```shell
  >   rpm -ql hisi_sec2 hisi_hpre hisi_rde
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/hisi_sec2.ko
  >   /etc/modproe.d/hisi_sec2.conf
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/hisi_hpre.ko
  >   /etc/modproe.d/hisi_hpre.conf
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/hisi_rde.ko
  >   /etc/modproe.d/hisi_rde.conf
  >   ```
  >   
  >   查看hisi\_zip是否已安装。
  >   
  >   ```shell
  >   rpm -ql hisi_zip
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/hisi_zip.ko
  >   /etc/modproe.d/hisi_zip.conf
  >   ```
  > * 查看安装目录下是否生成对应模块。
  >   
  >   ```shell
  >   ls -al /lib/modules/`uname -r`/extra 
  >   -rw-r--r--. 1 root root 681104 Nov 12 17:32 hisi_hpre.ko
  >   -rw-r--r--. 1 root root 618888 Nov 12 17:32 hisi_qm.ko
  >   -rw-r--r--. 1 root root 844728 Nov 12 17:32 hisi_rde.ko
  >   -rw-r--r--. 1 root root 729304 Nov 12 17:32 hisi_sec2.ko
  >   -rw-r--r--. 1 root root 396784 Nov 12 17:32 hisi_zip.ko
  >   -rw-r--r--. 1 root root 467160 Nov 12 17:32 uacce.ko
  >   ```
  > * 在“/etc/modprobe.d/”目录下查看是否生成对应的配置文件。
  >   
  >   ```shell
  >   ls -al /etc/modprobe.d/
  >   -rw-r--r--.   1 root root  166 Oct 30  2018 firewalld-sysctls.conf
  >   -rw-r--r--.   1 root root   44 Nov 17 21:56 hisi_hpre.conf
  >   -rw-r--r--.   1 root root   43 Nov 17 21:56 hisi_rde.conf
  >   -rw-r--r--.   1 root root   61 Nov 17 21:56 hisi_sec2.conf
  >   -rw-r--r--.   1 root root  674 Jul  4  2018 tuned.conf
  >   -rw-r--r--.   1 root root   43 Nov 17 21:56 hisi_zip.conf
  >   ```
* 步骤5（可选）如果是SUSE操作系统，在加载外部驱动前需要先将配置文件“/etc/modprobe.d/10-unsupported-modules.conf”中的“allow\_unsupported\_modules”参数值设置为“1”。
* 步骤6 加载加速器驱动到内核。
  
  * 方式一：重启系统加载
  * 方式二：手动依次加载
  
  > 查询已载入内核的uacce驱动模块。
  > 
  > ```shell
  > lsmod | grep uacce
  > ```
  > 
  > 加载uacce驱动。 `modprobe uacce` 加载hisi\_sec2驱动，将根据“/etc/modprobe.d/hisi\_sec2.conf”下的配置文件加载到内核。 `modprobe hisi_sec2` 加载hisi\_hpre驱动，将根据“/etc/modprobe.d/hisi\_hpre.conf”下的配置文件加载到内核。 `modprobe hisi_hpre` 加载hisi\_rde驱动，将根据“/etc/modprobe.d/hisi\_rde.conf”下的配置文件加载到内核。 `modprobe hisi_rde` 加载hisi\_zip驱动，将根据/etc/modprobe.d/hisi\_zip.conf下的配置文件加载到内核。 `modprobe hisi_zip` 再次查询已载入内核的uacce驱动模块。有以下加载的模块显示则表示加载成功。
  > 
  > ```shell
  > lsmod | grep uacce
  > uacce                36864  3 hisi_sec2,hisi_qm,hisi_hpre,hisi_rde,hisi_zip
  > ```
* （可选）使用加解密功能时候，设置环境变量OPENSSL\_ENGINES 如果用户指定安装路径，则下面/usr/local/lib/engines-1.1应根据实际安装路径进行修改。
  
  ```shell
  export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
  ```
  
  > 说明：该环境变量默认为指定挂载到OpenSSL中的引擎路径，可以指定到客户自定义路径。

（dep包安装同rpm安装，rpm -ivh XXX.rpm 对应为 dpkg -i XXX.deb ）

### 2.4.2 源码安装

* 步骤1 下载代码
  
  ```shell
  git clone https://gitee.com/kunpengcompute/KAE.git -b kae1
  ```
* 步骤2 安装内核驱动
  
  ```shell
  cd kae_drvier
  make
  make install
  ```
  
  加速器驱动编译生成uacce.ko、hisi\_qm.ko、hisi\_sec2.ko、hisi\_hpre.ko、hisi\_zip.ko、hisi\_rde.ko，安装路径为：“lib/modules/`uname -r`/extra”。
  
  > 由于SUSE及CentOS内核目录为“/lib/modules/\`uname -r\`/”，驱动安装的目录为“/lib/modules/\`uname -r\`/extra”（\`uname -r\`命令获取当前运行内核信息）。如果其他操作系统不是该目录，需要修改Makefile文件中install指定的内核路径。 install: \$(shell mkdir -p /lib/modules/\`uname -r\`/extra)修改为\$(shell mkdir -p内核路径/extra)
* 步骤3 安装用户态驱动。
  
  ```shell
  cd warpdrive
  sh autogen.sh
  ./configure
  make
  make install
  ```
  
  其中，执行编译命令./configure时可以加--prefix选项用于指定加速器用户态驱动需要安装的位置，用户态驱动动态库文件为libwd.so。Warpdrive默认安装路径为“/usr/local”，动态库文件在“/usr/local/lib”下。
  
  > 说明：KAE引擎需要使用到OpenSSL的动态库与Warpdrive的动态库。Warpdrive源码安装路径选择需要与OpenSSL安装路径保持一致，使得KAE加速引擎可以通过LD\_LIBRARY\_PATH能够同时找到这两个动态库。
* 步骤4 （可选）如果是SUSE操作系统，在加载外部驱动前需要先将配置文件“/etc/modprobe.d/10-unsupported-modules.conf”中的“allow\_unsupported\_modules”参数值设置为“1”。
* 步骤5
* 方式一：重启系统加载
  
  * 方式二：手动依次加载
  
  > 查询已载入内核的uacce驱动模块。
  > 
  > ```shell
  > lsmod | grep uacce
  > ```
  > 
  > 加载uacce驱动。 `modprobe uacce` 加载hisi\_sec2驱动，将根据“/etc/modprobe.d/hisi\_sec2.conf”下的配置文件加载到内核。 `modprobe hisi_sec2` 加载hisi\_hpre驱动，将根据“/etc/modprobe.d/hisi\_hpre.conf”下的配置文件加载到内核。 `modprobe hisi_hpre` 加载hisi\_rde驱动，将根据“/etc/modprobe.d/hisi\_rde.conf”下的配置文件加载到内核。 `modprobe hisi_rde` 加载hisi\_zip驱动，将根据/etc/modprobe.d/hisi\_zip.conf下的配置文件加载到内核。 `modprobe hisi_zip` 再次查询已载入内核的uacce驱动模块。有以下加载的模块显示则表示加载成功。
  > 
  > ```shell
  > lsmod | grep uacce
  > uacce                36864  3 hisi_sec2,hisi_qm,hisi_hpre,hisi_rde,hisi_zip
  > ```
* （可选）设置环境变量OPENSSL\_ENGINES 如果用户指定安装路径，则下面/usr/local/lib/engines-1.1应根据实际安装路径进行修改。
  
  ```shell
  export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
  ```
  
  > 说明：该环境变量默认为指定挂载到OpenSSL中的引擎路径，可以指定到客户自定义路径。
* 步骤6 编译安装KAE加速引擎
  
  ```shell
  cd KAE
  chmod +x configure
  ./configure
  make clean & make
  make install
  ```
  
  其中，执行编译命令./configure时可以加--prefix选项用于指定KAE加速引擎的安装路径，KAE加速引擎动态库文件为libkae.so。 推荐通过默认方式安装KAE加速引擎。默认安装路径为“/usr/local”，动态库文件在“/usr/local/lib/engines-1.1”下。
* 步骤7 检查安装状态
  
  ```shell
  ls -al /usr/local/lib/ |grep libwd
  lrwxrwxrwx. 1 root root      14 Jun 25 11:16 libwd.so -> libwd.so.1.0.1
  lrwxrwxrwx. 1 root root      14 Jun 25 11:16 libwd.so.0 -> libwd.so.1.0.1
  -rwxr-xr-x. 1 root root  137280 Jun 24 11:37 libwd.so.1.0.1
  ```
  
  ```shell
  ls -al /usr/local/lib/engines-1.1/
  lrwxrwxrwx. 1 root root     48 Jun 25 11:21 kae.so -> /usr/local/openssl/lib/engines-1.1/kae.so.1.0.1
   lrwxrwxrwx. 1 root root     48 Jun 25 11:21 kae.so.0 -> /usr/local/openssl/lib/engines-1.1/kae.so.1.0.1
   -rwxr-xr-x. 1 root root 212192 Jun 24 11:37 kae.so.1.0.1
  ```
  
  查看虚拟文件系统下加速器设备
  
  ```shell
  ls -al /sys/class/uacce/
  total 0
   lrwxrwxrwx. 1 root root 0 Nov 14 03:45 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
   lrwxrwxrwx. 1 root root 0 Nov 14 03:45 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
   lrwxrwxrwx. 1 root root 0 Nov 17 22:09 hisi_rde-4 -> ../../devices/pci0000:78/0000:78:01.0/uacce/hisi_rde-4
   lrwxrwxrwx. 1 root root 0 Nov 17 22:09 hisi_rde-5 -> ../../devices/pci0000:b8/0000:b8:01.0/uacce/hisi_rde-5
   lrwxrwxrwx. 1 root root 0 Nov 14 08:39 hisi_sec-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec-0
   lrwxrwxrwx. 1 root root 0 Nov 14 08:39 hisi_sec-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec-1
  ```
* 步骤8 通过openssl命令验证加速器是否生效。
  
  ```shell
  [root]openssl speed rsa2048
                                       sign    verify    sign/s verify/s
   rsa 2048 bits 0.001381s 0.000035s    724.1  28601.0
  
  [root]openssl speed -engine kae rsa2048
  engine "kae" set.
                                        sign    verify    sign/s verify/s
   rsa 2048 bits 0.000175s 0.000021s   5730.1  46591.8
  ```
* 步骤9 KAEZip 安装：编译安装 zlib 库 a. 从zlib官网下载[zlib-1.2.11.tar.gz](https://www.zlib.net/fossils/zlib-1.2.11.tar.gz "https://www.zlib.net/fossils/zlib-1.2.11.tar.gz")，拷贝到“kae\_zip\_engine/open\_source”路径下。 b. 编译安装zlib库。
  
  ```shell
  cd kae_zip_engine
  sh setup.sh install
  ```
  
  c.更多详细说明详见[KAEZip源码安装官网文档](https://www.hikunpeng.com/document/detail/zh/kunpengaccel/compress/devg-kaezip/kunpengaccel_kaezip_0028.html "https://www.hikunpeng.com/document/detail/zh/kunpengaccel/compress/devg-kaezip/kunpengaccel_kaezip_0028.html")。
* 步骤10 通过**ldd**命令查看zlib加速库是否链接到libwd和libkaezip。
  
  ```shell
  ldd /usr/local/kaezip/lib/libz.so.1.2.11
    linux-vdso.so.1 =>  (0x0000ffff80280000)
    libc.so.6 => /lib64/libc.so.6 (0x0000ffff80080000)
    libwd.so.1 => /lib64/libwd.so.1 (0x0000ffff80040000)
    /lib/ld-linux-aarch64.so.1 (0x0000ffff80290000)
    libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffff80830000)
  ```

# 三、常见问题

## 3.1 安装问题

### 驱动安装问题

* 内核版本和内核开发包版本不一致导致内核安装失败。（包括小版本号）
  
  > uname -r 查看内核版本
  > rpm -qa | grep kernel-devel 查看内核开发包版本
  
  解决办法：安装和内核版本一致的开发包
* 缺少license导致加载失败
  
  > lspci | grep HPRE
  > lspci | grep SEC
  > lspci | grep ZIP
  
  解决办法：920申请license安装；920新型号更新免license版本BIOS
