
在历史的代码仓中，我们有以下几个部分的代码：

[KAEdriver](https://gitee.com/kunpengcompute/KAEdriver)  驱动层代码

[KAE](https://gitee.com/kunpengcompute/KAE/tree/v1.3.11/) kae_engine层代码

[KAEzip](https://gitee.com/kunpengcompute/KAEzip) kae_zip层代码


这些代码仓适合查看1.3.11版本及其之前的tag。

后来基于1.3.11版本的tag信息，我们将KAEdriver、KAE和KAEzip三个仓的代码合并到了[KAE](https://gitee.com/kunpengcompute/KAE)仓中。针对不同的内核版本，我们将代码分为了kae1分支（4.49内核）和kae2分支（5.10内核）。

因此，如果您需要使用最新的代码，只需参考KAE代码仓中的readme。如果您需要下载历史代码，则需要到历史仓的对应tag点下载代码。

---

# 一、背景及规格

## 1.1、背景说明

鲲鹏加速引擎是基于鲲鹏处理器提供的硬件加速解决方案，包含了 KAE 加解密和 KAE 解压缩两个模块，分别用于加速 SSL/TLS 应用和数据压缩，可以显著降低处理器消耗，提高处理器效率。此外，加速引擎对应用层屏蔽了其内部实现细节，用户通过 OpenSSL、zlib标准接口即可以实现快速迁移现有业务。

本文介绍了 KAE 的安装流程。

## 1.2、版本说明

鲲鹏加速引擎（KAE）是一款基于鲲鹏 920 处理器研发的加速器。由于不同内核版本的差异，KAE 存在两套代码用于支持不同的内核代码，分别是 KAE1.0 和 KAE2.0 两套代码分支。其中，KAE1.0 适用于 4.19 内核；而 KAE2.0 适用于 5.1x 内核。

| 内核版本 | 设备形态 | KAE1.0        | KAE2.0    |
| ---------- | ---------- | --------------- | --------------- |
| 4.19     | 920      | **YES**       | NA      |
| 5.1x     | 920      | NA            | **YES** |

## 1.3、KAE算法规格说明

由于硬件差异，KAE不同版本加速引擎能够支持的加密算法存在不同，支持情况详见以下表格：

|                     |  鲲鹏 920  |
| --------------------| ---------  | 
| 摘要算法 SM3         | YES       | 
| 摘要算法 DM5         | YES       | 
| 对称加密算法 SM4-CTR | YES       | 
| 对称加密算法 SM4-XTS | YES       |
| 对称加密算法 SM4-CBC | YES       | 
| 对称加密算法 SM4-ECB | YES       | 
| 对称加密算法 SM4-OFB | YES       | 
| 对称加密算法 SM4-CFB | **NA**    |
| 对称加密算法 AES-ECB | YES       | 
| 对称加密算法 AES-CTR | YES       | 
| 对称加密算法 AES-XTS | YES       | 
| 对称加密算法 AES-CBC | YES       | 
| 对称加密算法 AES-OFB | **NA**    | 
| 对称加密算法 AES-CFB | **NA**    | 
| 对称加密算法 AES-GCM | **NA**    | 
| 对称加密算法 AES-CCM | **NA**    | 
| 非对称算法 RSA       | YES       | 
| 非对称算法 SM2       | **NA**    | 
| 密钥协商算法 DH      | YES        |

> 注意：
> 1、对称加密算法 SM4-XTS 不支持 openSSL，只支持内核态使用。

KAE-zlib 解压缩功能支持情况见下表：

|           | 支持 zlib/Gzip 数据格式 | 支持 deflate 算法 | 可配置压缩等级 |
| ----------- | ------------------------- | ------------------- | ---------------- |
| 鲲鹏920   | YES                     | **NA**                | **NA**            |

# 二、安装前准备

根据芯片款型及内核版本选择适合的KAE代码进行安装，安装前需要确定环境信息及安装license。

## 2.1 环境信息确认

* 以 TaiShan 200 服务器为例，开启 KAE 加速引擎功能
* CPU：鲲鹏 920 处理器
* iBMC 版本：V365 及以上
* BIOS 版本：V105 及以上
* KAE1.0 支持操作系统：
  * CentOS 7.6 4.14.0-115.el7a.0.1.aarch64 version
  * SUSE 15.1 4.12.14-195-default.aarch64 version
  * EulerOS 2.8 4.19.36-vhulk1907.1.0.h410.eulerosv2r8.aarch64 version
  * NeoKylin 7.6 4.14.0-115.5.1.el7a.06.aarch64 version
  * BCLinux-R7-U6-Server-aarch64 version
  * Kylin 4.0.2 (juniper) 4.15.0-70-generic version
  * Kylin release 4.0.2 (SP2) 4.19.36-vhulk1907.1.0.h403.ky4.aarch64 version
  * UniKylin Linux release 3(Core) 4.18.0-80.ky3.kb21.hw.aarch64 version
  * Ubuntu 18.04.1 LTS 4.15.0-29-generic version
  * openEuler 20.03 LTS 4.19.90-2003.4.0.0036.oe1.aarch64 version
  * openEuler 20.03 LTS-SP1 4.19.90-2012.4.0.0053.oe1.aarch64 version
* KAE2.0支持操作系统：
  * openEuler 22.03 LTS-SP1
  * openEuler 22.03 LTS-SP2

## 2.2 软件包获取

基于硬件cpu款型及内核OS情况，选择正确的KAE版本后，再获取软件包，用于后续安装。

### 2.2.1 KAE1.0软件包获取

KAE1.0 版本支持RPM、DEB包安装、源码安装三种方式。

* **RPM及DEB获取**
  KAE1.0 rpm 包下载地址：[https://gitee.com/kunpengcompute/KAE/releases/tag/v1.2.10](https://gitee.com/kunpengcompute/KAE/releases/tag/v1.2.10)
  > 说明：rpm 包的获取需要进入下载地址选取指定操作系统的 rpm 包

KAE1.0 RPM包说明如下表所示：

| 软件包名称 | 软件包说明| 
| --- | --- |
|  uacce-版本号-1.OS类型.aarch64.rpm<br>uacce-版本号-1.OS类型.aarch64.deb| 统一加速器框架，包含内容：uacce.ko、hisi_qm.ko内核模块 |
|  hisi_hpre-版本号-1.OS类型.aarch64.rpm<br>hisi_hpre-版本号-1.OS类型.aarch64.deb | 依赖：uacce RPM包 <br> 包含内容：hisi_hpre.ko内核模块<br> 支持：RSA/DH算法 |
| hisi_sec2-版本号-1.OS类型.aarch64.rpm <br>hisi_sec2-版本号-1.OS类型.aarch64.deb|  依赖：uacce RPM包<br>包含内容：hisi_sec2.ko内核模块 <支持：AES/MD5/SM3/SM4算法>  |
| hisi_rde-版本号-1.OS类型.aarch64.rpm <br>hisi_rde-版本号-1.OS类型.aarch64.deb |  依赖：uacce RPM包<br> 包含内容：hisi_rde.ko内核模块 <br> 支持：FlexEC算法 |
| hisi_zip-版本号-1.OS类型.aarch64.rpm<br>hisi_zip-版本号-1.OS类型.aarch64.deb | 依赖：uacce RPM包<br>包含内容：hisi_zip.ko内核模块<br>支持：zlib/gzip |
| libwd-版本号-1.OS类型.aarch64.rpm<br>libwd-版本号-1.OS类型.aarch64.deb  | 包含内容：libwd.so动态链接库 <br> 提供接口给KAE加速引擎 |
| libkae-版本号-1.OS类型.aarch64.rpm <br> libkae-版本号-1.OS类型.aarch64.deb | 依赖：libwd RPM包 <br>包含内容：libkae.so动态库<br>支持：SM3/SM4/RSA/AES/MD5/DH等算法|
| libkaezip-版本号-1.OS类型.aarch64.rpm<br>libkaezip-版本号-1.OS类型.aarch64.deb | 依赖：libwd RPM/DEB包<br>包含内容：libkaezip.so动态库<br>支持：压缩解压算法 |

* **源码包获取**

KAE1.0 源码下载方式：git clone [https://gitee.com/kunpengcompute/KAE.git](https://gitee.com/kunpengcompute/KAE.git) -b kae1
或者访问Kunpeng/KAE代码仓下载源码包：https://gitee.com/kunpengcompute/KAE

### 2.2.2 KAE2.0软件包获取

KAE2.0 版本支持RPM包安装、源码安装两种种方式。

* **RPM包获取**
  KAE2.0 rpm包下载地址：尚未发布
* **源码包获取**
  KAE2.0 源码下载方式：git clone https://gitee.com/kunpengcompute/KAE.git -b kae2
  或者访问Kunpeng/KAE代码仓下载源码包：https://gitee.com/kunpengcompute/KAE

## 2.3 License安装

安装鲲鹏KAE加速引擎之前需要先安装相应的License，License安装成功之后，操作系统才能识别到加速器设备。

> TaiShan K系列服务器硬件KAE加速引擎已默认开启，无需申请License。

具体License申请使用操作可参考《[华为服务器iBMC许可证 使用指导](https://support.huawei.com/enterprise/zh/management-software/ibmc-pid-8060757?category=operation-maintenance)》。

通过**lspci**命令进行查看操作系统是否有加速器设备，如下所示。

```shell
lspci | grep HPRE
79:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)
b9:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)

lspci | grep RDE
78:01.0 RAID bus controller: Huawei Technologies Co., Ltd. HiSilicon RDE Engine (rev 21)
b8:01.0 RAID bus controller: Huawei Technologies Co., Ltd. HiSilicon RDE Engine (rev 21)

lspci | grep ZIP
75:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)
b5:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)

lspci | grep SEC
76:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
b6:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
```

## 2.4 KAE安装

### 2.4.1 KAE1.0版本

#### 二进制包安装

前提条件：
请保证rpm下载完成，并且license获取成功。
RPM或dpkg工具能正常使用。
OpenSSL 1.1.1a或以上版本已正确安装。

> hisi\_hpre，hisi\_sec2，hisi\_rde驱动软件包依赖于uacce软件包；libkae引擎软件包依赖于libwd软件包。
> 如果仅加速RSA/DH算法建议只需要安装uacce、hisi\_hpre、libwd、libkae软件包。
> 如果仅加速AES/MD5/SM3/SM4算法建议只需要安装uacce、hisi\_sec2、libwd、libkae软件

* 步骤1
  使用SSH远程登录工具，以root帐号进入Linux操作系统命令行界面。
* 步骤2
  将KAE加速引擎软件包拷贝到自定义路径下。
* 步骤3
  安装加速驱动软件包。
  
  > * 可以通过**rpm -ivh \*.rpm**安装所有KAE加速引擎软件包。
  >   
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
  >   
  >   ```shell
  >   [root]rpm -ivh uacce-1.0.1-1.centos7.6.aarch64.rpm
  >   Preparing...                          ################################# [100%]
  >   checking installed modules
  >   Updating / installing... 
  >   1:uacce-1.0.1-1.centos7.6             ################################# [100%]
  >   modules installed
  >   ```
  > * 安装libkae引擎软件包时还需要通过--prefix指定OpenSSL引擎的路径，命令与回显结果如下：
  >   
  >   ```shell
  >   [root]rpm -ivh libkae-1.0.1-1.centos7.6.aarch64.rpm      --prefix=/usr/local/lib/engines-1.1
  >   Preparing...                          ################################# [100%]
  >   Updating / installing...
  >       1:libkae-1.0.1-1.centos7.6        ################################# [100%]
  >   ```
* 步骤4
  查看RPM软件是否已正常安装到系统内。
  
  > * 查看uacce是否已安装。
  >   
  >   ```shell
  >   rpm -ql uacce
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/hisi_qm.ko
  >   /lib/modules/4.14.0-115.el7a.0.1.aarch64/extra/uacce.ko
  >   ```
  > * 查看hisi_sec2、hisi_hpre、hisi_rde是否已安装。
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
  >   查看hisi_zip是否已安装。
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
* 步骤5（可选）如果是SUSE操作系统，在加载外部驱动前需要先将配置文件“/etc/modprobe.d/10-unsupported-modules.conf”中的“allow_unsupported_modules”参数值设置为“1”。
* 步骤6
  加载加速器驱动到内核。
  
  * 方式一：重启系统加载
  * 方式二：手动依次加载
  
  > 查询已载入内核的uacce驱动模块。
  > 
  > ```shell
  > lsmod | grep uacce
  > ```
  > 
  > 加载uacce驱动。
  > `modprobe uacce`
  > 加载hisi_sec2驱动，将根据“/etc/modprobe.d/hisi_sec2.conf”下的配置文件加载到内核。
  > `modprobe hisi_sec2`
  > 加载hisi_hpre驱动，将根据“/etc/modprobe.d/hisi_hpre.conf”下的配置文件加载到内核。
  > `modprobe hisi_hpre`
  > 加载hisi_rde驱动，将根据“/etc/modprobe.d/hisi_rde.conf”下的配置文件加载到内核。
  > `modprobe hisi_rde`
  > 加载hisi_zip驱动，将根据/etc/modprobe.d/hisi_zip.conf下的配置文件加载到内核。
  > `modprobe hisi_zip`
  > 再次查询已载入内核的uacce驱动模块。有以下加载的模块显示则表示加载成功。
  > 
  > ```shell
  > lsmod | grep uacce
  > uacce                36864  3 hisi_sec2,hisi_qm,hisi_hpre,hisi_rde,hisi_zip
  > ```
* （可选）使用加解密功能时候，设置环境变量OPENSSL_ENGINES
  如果用户指定安装路径，则下面/usr/local/lib/engines-1.1应根据实际安装路径进行修改。
  
  ```shell
  export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
  ```
  
  > 说明：该环境变量默认为指定挂载到OpenSSL中的引擎路径，可以指定到客户自定义路径。

（dep包安装同rpm安装，rpm -ivh XXX.rpm 对应为 dpkg -i XXX.deb ）

#### 源码安装

* 步骤1
  下载代码
  
  ```shell
  git clone https://gitee.com/kunpengcompute/KAE.git -b kae1
  ```
* 步骤2
  安装内核驱动
  
  ```shell
  cd kae_drvier
  make
  make install
  ```
  
  加速器驱动编译生成uacce.ko、hisi_qm.ko、hisi_sec2.ko、hisi_hpre.ko、hisi_zip.ko、hisi_rde.ko，安装路径为：“lib/modules/`uname -r`/extra”。
  
  > 由于SUSE及CentOS内核目录为“/lib/modules/\`uname -r\`/”，驱动安装的目录为“/lib/modules/\`uname -r\`/extra”（\`uname -r\`命令获取当前运行内核信息）。如果其他操作系统不是该目录，需要修改Makefile文件中install指定的内核路径。 install: \$(shell mkdir -p /lib/modules/\`uname -r\`/extra)修改为$(shell mkdir -p内核路径/extra)
* 步骤3
  安装用户态驱动。
  
  ```shell
  cd warpdrive
  sh autogen.sh
  ./configure
  make
  make install
  ```
  
  其中，执行编译命令./configure时可以加--prefix选项用于指定加速器用户态驱动需要安装的位置，用户态驱动动态库文件为libwd.so。Warpdrive默认安装路径为“/usr/local”，动态库文件在“/usr/local/lib”下。
  
  > 说明：KAE引擎需要使用到OpenSSL的动态库与Warpdrive的动态库。Warpdrive源码安装路径选择需要与OpenSSL安装路径保持一致，使得KAE加速引擎可以通过LD_LIBRARY_PATH能够同时找到这两个动态库。
* 步骤4
  （可选）如果是SUSE操作系统，在加载外部驱动前需要先将配置文件“/etc/modprobe.d/10-unsupported-modules.conf”中的“allow_unsupported_modules”参数值设置为“1”。
* 步骤5
* 方式一：重启系统加载
  
  * 方式二：手动依次加载
  
  > 查询已载入内核的uacce驱动模块。
  > 
  > ```shell
  > lsmod | grep uacce
  > ```
  > 
  > 加载uacce驱动。
  > `modprobe uacce`
  > 加载hisi_sec2驱动，将根据“/etc/modprobe.d/hisi_sec2.conf”下的配置文件加载到内核。
  > `modprobe hisi_sec2`
  > 加载hisi_hpre驱动，将根据“/etc/modprobe.d/hisi_hpre.conf”下的配置文件加载到内核。
  > `modprobe hisi_hpre`
  > 加载hisi_rde驱动，将根据“/etc/modprobe.d/hisi_rde.conf”下的配置文件加载到内核。
  > `modprobe hisi_rde`
  > 加载hisi_zip驱动，将根据/etc/modprobe.d/hisi_zip.conf下的配置文件加载到内核。
  > `modprobe hisi_zip`
  > 再次查询已载入内核的uacce驱动模块。有以下加载的模块显示则表示加载成功。
  > 
  > ```shell
  > lsmod | grep uacce
  > uacce                36864  3 hisi_sec2,hisi_qm,hisi_hpre,hisi_rde,hisi_zip
  > ```
* （可选）设置环境变量OPENSSL_ENGINES
  如果用户指定安装路径，则下面/usr/local/lib/engines-1.1应根据实际安装路径进行修改。
  
  ```shell
  export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
  ```
  
  > 说明：该环境变量默认为指定挂载到OpenSSL中的引擎路径，可以指定到客户自定义路径。
* 步骤6
  编译安装KAE加速引擎
  
  ```shell
  cd KAE
  chmod +x config
  ./configure
  make clean & make
  make install
  ```
  
  其中，执行编译命令./configure时可以加--prefix选项用于指定KAE加速引擎的安装路径，KAE加速引擎动态库文件为libkae.so。
  推荐通过默认方式安装KAE加速引擎。默认安装路径为“/usr/local”，动态库文件在“/usr/local/lib/engines-1.1”下。
* 步骤7
  检查安装状态
  
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
* 步骤8
  通过openssl命令验证加速器是否生效。
  
  ```shell
  [root]openssl speed rsa2048
                                       sign    verify    sign/s verify/s
   rsa 2048 bits 0.001381s 0.000035s    724.1  28601.0
  
  [root]openssl speed -engine kae rsa2048
  engine "kae" set.
                                        sign    verify    sign/s verify/s
   rsa 2048 bits 0.000175s 0.000021s   5730.1  46591.8
  ```

通过**ldd**命令查看zlib加速库是否链接到libwd和libkaezip。

```shell
ldd /usr/local/kaezip/lib/libz.so.1.2.11
  linux-vdso.so.1 =>  (0x0000ffff80280000)
  libc.so.6 => /lib64/libc.so.6 (0x0000ffff80080000)
  libwd.so.1 => /lib64/libwd.so.1 (0x0000ffff80040000)
  /lib/ld-linux-aarch64.so.1 (0x0000ffff80290000)
  libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffff80830000)
```

### 2.4.2 KAE2.0版本

#### 二进制包安装

RPM包尚未发布。

#### 源码安装

通过2.2节获取到源码后，进入KAE文件夹，目录结构如下所示：

```shell
-rw-r--r--.  1 root root 6921 Aug  4 16:37 build.sh
drwxr-xr-x.  7 root root 4096 Aug 15 17:13 KAEKernelDriver
drwxr-xr-x.  7 root root 4096 Aug 15 17:13 KAEOpensslEngine
drwxr-xr-x.  9 root root 4096 Aug 15 17:19 KAEZlib
drwxr-xr-x.  8 root root 4096 Aug  8 10:45 KAEZstd
-rw-r--r--.  1 root root    5 Jul 27 17:25 README.md
drwxr-xr-x.  3 root root 4096 Jul 27 17:25 scripts
drwxr-xr-x. 14 root root 4096 Aug 15 17:13 uadk
```

需要依次安装驱动、安装UADK、安装OpensslEngine(按需)、安装Zlib(按需)。

* **安装驱动**

```shell
[root@localhost KAE]# sh build.sh driver
build driver
make -C /lib/modules/`rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel | head -n 1`/build M=/home/USER/KAE/KAEKernelDriver modules \
        CONFIG_CC_STACKPROTECTOR_STRONG=y \
        CONFIG_UACCE=m \
        CONFIG_CRYPTO_QM_UACCE=m \
        CONFIG_CRYPTO_DEV_HISI_SGL=m \
        CONFIG_CRYPTO_DEV_HISI_QM=m \
        CONFIG_CRYPTO_DEV_HISI_ZIP=m \
        CONFIG_CRYPTO_DEV_HISI_HPRE=m \
        CONFIG_CRYPTO_DEV_HISI_SEC2=m \
        CONFIG_CRYPTO_DEV_HISI_TRNG=m
make[1]: Entering directory '/usr/src/kernels/5.10.0-146.0.0.75.oe2203sp2.aarch64'
  CC [M]  /home/USER/KAE/KAEKernelDriver/uacce/uacce.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/qm.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/sgl.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/debugfs.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/sec2/sec_main.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hpre/hpre_main.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/zip/zip_main.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hpre/hpre_crypto.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/sec2/sec_crypto.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/zip/zip_crypto.o
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/zip/hisi_zip.o
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hpre/hisi_hpre.o
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/sec2/hisi_sec2.o
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hisi_qm.o
  MODPOST /home/USER/KAE/KAEKernelDriver/Module.symvers
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hisi_qm.mod.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hpre/hisi_hpre.mod.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/sec2/hisi_sec2.mod.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/zip/hisi_zip.mod.o
  CC [M]  /home/USER/KAE/KAEKernelDriver/uacce/uacce.mod.o
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hpre/hisi_hpre.ko
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/hisi_qm.ko
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/zip/hisi_zip.ko
  LD [M]  /home/USER/KAE/KAEKernelDriver/hisilicon/sec2/hisi_sec2.ko
  LD [M]  /home/USER/KAE/KAEKernelDriver/uacce/uacce.ko
make[1]: Leaving directory '/usr/src/kernels/5.10.0-146.0.0.75.oe2203sp2.aarch64'
depmod -a
modprobe uacce
modprobe hisi_qm
modprobe hisi_sec2 uacce_mode=2 pf_q_num=256
modprobe hisi_hpre uacce_mode=2 pf_q_num=256
modprobe hisi_zip  uacce_mode=2 pf_q_num=256
echo "options hisi_sec2 uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_sec2.conf
echo "options hisi_hpre uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_hpre.conf
echo "options hisi_zip  uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_zip.conf
```

可以通过查看目录/sys/class/uacce是否存在加速引擎文件系统判断驱动是否安装成功。

```shell
[root@localhost KAE]# ll /sys/class/uacce/
total 0
lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-2 -> ../../devices/pci0000:78/0000:78:00.0/0000:79:00.0/uacce/hisi_hpre-2
lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_hpre-3 -> ../../devices/pci0000:b8/0000:b8:00.0/0000:b9:00.0/uacce/hisi_hpre-3
lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-0 -> ../../devices/pci0000:74/0000:74:01.0/0000:76:00.0/uacce/hisi_sec2-0
lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_sec2-1 -> ../../devices/pci0000:b4/0000:b4:01.0/0000:b6:00.0/uacce/hisi_sec2-1
lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-4 -> ../../devices/pci0000:74/0000:74:00.0/0000:75:00.0/uacce/hisi_zip-4
lrwxrwxrwx. 1 root root 0 Aug 22 17:14 hisi_zip-5 -> ../../devices/pci0000:b4/0000:b4:00.0/0000:b5:00.0/uacce/hisi_zip-5
```

> 说明： 若无内容显示，可能是因为uacce默认安装了内核版本，可以先卸载后重新安装。
> sh build cleanup

* 安装UADK

```shell
sh build.sh uadk
...
```

可以通过查找libwd*.so来确定是否安装成功

```shell
[root@localhost KAE]# ll /usr/local/lib/libwd*
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

* **安装OpenSSLEngine（按需）**

```shell
sh build.sh engine
...
```

可以通过查看kae.so判断是否安装成功

```shell
[root@localhost KAE]# ll /usr/local/lib/engines-1.1
total 5644
-rw-r--r--. 1 root root 3846524 Aug 22 17:28 kae.a
-rwxr-xr-x. 1 root root     995 Aug 22 17:28 kae.la
lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so -> kae.so.2.0.0
lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so.2 -> kae.so.2.0.0
-rwxr-xr-x. 1 root root 1967736 Aug 22 17:28 kae.so.2.0.0
```

也可以通过openssl speed命令查看加速引擎是否生效：

```shell
[root@localhost KAE]# openssl speed rsa2048
Doing 2048 bits private rsa's for 10s: 7779 2048 bits private RSA's in 9.99s
Doing 2048 bits public rsa's for 10s: 321542 2048 bits public RSA's in 9.99s
OpenSSL 1.1.1m  14 Dec 2021
built on: Thu Apr 13 09:58:22 2023 UTC
options:bn(64,64) md2(char) rc4(char) des(int) aes(partial) idea(int) blowfish(ptr)
compiler: gcc -fPIC -pthread -Wa,--noexecstack -Wall -O3 -O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/generic-hardened-cc1 -fasynchronous-unwind-tables -fstack-clash-protection -Wa,--noexecstack -specs=/usr/lib/rpm/generic-hardened-ld -DOPENSSL_USE_NODELETE -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_BN_ASM_MONT -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DVPAES_ASM -DECP_NISTZ256_ASM -DPOLY1305_ASM -DSM4_ASM -DVPSM4_EX_ASM -DSM3_ASM -DZLIB -DNDEBUG -DPURIFY -DDEVRANDOM="\"/dev/urandom\""
                  sign    verify    sign/s verify/s
rsa 2048 bits 0.001284s 0.000031s    778.7  32186.4
[root@localhost KAE]# export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
[root@localhost KAE]# openssl speed -engine kae rsa2048
engine "kae" set.
Doing 2048 bits private rsa's for 10s: 32132 2048 bits private RSA's in 4.95s
Doing 2048 bits public rsa's for 10s: 517087 2048 bits public RSA's in 9.95s
OpenSSL 1.1.1m  14 Dec 2021
built on: Thu Apr 13 09:58:22 2023 UTC
options:bn(64,64) md2(char) rc4(char) des(int) aes(partial) idea(int) blowfish(ptr)
compiler: gcc -fPIC -pthread -Wa,--noexecstack -Wall -O3 -O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/generic-hardened-cc1 -fasynchronous-unwind-tables -fstack-clash-protection -Wa,--noexecstack -specs=/usr/lib/rpm/generic-hardened-ld -DOPENSSL_USE_NODELETE -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_BN_ASM_MONT -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DVPAES_ASM -DECP_NISTZ256_ASM -DPOLY1305_ASM -DSM4_ASM -DVPSM4_EX_ASM -DSM3_ASM -DZLIB -DNDEBUG -DPURIFY -DDEVRANDOM="\"/dev/urandom\""
                  sign    verify    sign/s verify/s
rsa 2048 bits 0.000154s 0.000019s   6491.3  51968.5
```

* **安装KAEZlib（按需）**

```shell
sh build.sh zlib
```

通过**ldd**命令查看zlib加速库是否链接到libwd和libkaezip。

```shell[root@localhost
linux-vdso.so.1 (0x0000ffffb0282000)
        libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffffb0075000)
        libkaezip.so.2.0.0 => /usr/local/kaezip/lib/libkaezip.so.2.0.0 (0x0000ffffb0044000)
        libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffffaffe3000)
        libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffffaffb2000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffffb0245000)
        libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffffaff8d000)
```

> 说明：脚本提供一键式安装命令：sh build.sh all, 初次使用前建议先 sh build.sh cleanup
