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

# 二、安装说明

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

### 2.2.1 KAE2.0软件包获取

KAE2.0 版本支持RPM包安装、源码安装两种种方式。

* **RPM包获取** KAE2.0 rpm包下载地址：尚未发布
* **源码包获取** KAE2.0 源码下载方式：git clone [https://gitee.com/kunpengcompute/KAE.git](https://gitee.com/kunpengcompute/KAE.git "https://gitee.com/kunpengcompute/KAE.git") -b kae2 , 或访问Kunpeng/KAE代码仓下载源码包：[https://gitee.com/kunpengcompute/KAE](https://gitee.com/kunpengcompute/KAE "https://gitee.com/kunpengcompute/KAE")

## 2.3 KAE2.0安装

### 2.3.1 RPM包安装

RPM包在gitee社区[release界面](https://gitee.com/kunpengcompute/KAE/releases)

> 内核RPM包的安装会依赖OS的内核版本号，gitee社区提供的RPM都是在特性OS版本编译，安装需要依赖对应版本，若OS版本不匹配，可以通过源码按照方式使用，或者通过源码sh build.sh rpmpack命令生成特点版本的RPM使用。

### 2.3.2 源码安装

通过2.2节获取到源码后，进入KAE文件夹，目录结构如下所示：

```shell-rw-r--r--.
-rw-r--r--.  1 root root 13609 Feb 12 10:48 env-check.sh
drwxr-xr-x.  4 root root    54 May  7 20:05 KAEGzip
drwxr-xr-x.  5 root root   125 May  7 20:05 KAEKernelDriver
drwxr-xr-x.  6 root root   163 May  7 20:20 KAELz4
drwxr-xr-x.  6 root root   233 May  7 20:05 KAEOpensslEngine
drwxr-xr-x.  7 root root   132 May  7 20:05 KAEZlib
drwxr-xr-x.  6 root root   166 May  7 20:22 KAEZstd
-rw-r--r--.  1 root root 29683 Feb 12 10:48 README.md
drwxr-xr-x.  5 root root    83 May  7 20:05 scripts
drwxr-xr-x. 10 root root  4096 May  7 20:05 uadk
```

需要依次安装驱动、安装UADK、安装应用层软件（KAEOpensslEngine、KAEZlib、KAEZstd、KAELz4、KAEGzip）。

关键编译命令：
`sh build.sh -h`  查看帮助信息
`sh build.sh all` 一键简易安装

#### 2.3.2.1 安装内核驱动

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

> 说明： 若无内容显示，可能是因为uacce默认安装了内核版本，可以先卸载后重新安装。 sh build cleanup

#### 2.3.2.2 安装用户态驱动

```shell
sh build.sh uadk
...
```

可以通过查找libwd\*.so来确定是否安装成功

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

#### 2.3.2.3 安装OpenSSLEngine（按需）

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
lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so -> kae.so.2.0.4
lrwxrwxrwx. 1 root root      12 Aug 22 17:28 kae.so.2 -> kae.so.2.0.4
-rwxr-xr-x. 1 root root 1967736 Aug 22 17:28 kae.so.2.0.4
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

#### 2.3.2.4 安装KAEZlib（按需）

```shell
sh build.sh zlib
```

查看kaezip软件库是否生成

```shell
[root@localhost KAE]# ll /usr/local/kaezip/lib/
total 428
lrwxrwxrwx. 1 root root     40 May 10 09:29 libkaezip.so -> /usr/local/kaezip/lib/libkaezip.so.2.0.4
lrwxrwxrwx. 1 root root     40 May 10 09:29 libkaezip.so.0 -> /usr/local/kaezip/lib/libkaezip.so.2.0.4
-rwxr-xr-x. 1 root root 215480 May 10 09:29 libkaezip.so.2.0.4
-rw-r--r--. 1 root root 150106 May 10 09:29 libz.a
lrwxrwxrwx. 1 root root     14 May 10 09:29 libz.so -> libz.so.1.2.11
lrwxrwxrwx. 1 root root     14 May 10 09:29 libz.so.1 -> libz.so.1.2.11
-rwxr-xr-x. 1 root root 144208 May 10 09:29 libz.so.1.2.11
drwxr-xr-x. 2 root root   4096 May 10 09:29 pkgconfig
```

若通过**ldd**命令查看zlib加速库没链接到libwd和libkaezip，可以通过LD_LIBRARY_PATH指定依赖库地址。

#### 2.3.2.5 安装KAEGzip（按需）

```shell
sh build.sh gzip
```

查看kaegzip二进制工具是否生成

```shell
[root@localhost KAE]# ll /usr/local/kaegzip/
total 116
-rwxr-xr-x. 1 root root 154712 May 10 09:29 gzip
```

若通过**ldd**命令查看zlib加速库没链接到libwd和libkaezip，可以通过LD_LIBRARY_PATH指定依赖库地址。

#### 2.3.2.6 安装KAEZztd（按需）

此特性仅在920新型号处理器有效

```shell
sh build.sh zstd
```

查看kaezstd软件库是否生成

```shell
[root@localhost KAE]# ll /usr/local/kaezstd/lib/
total 2224
-rwxr-xr-x. 1 root root 291642 May 10 09:29 libkaezstd.a
lrwxrwxrwx. 1 root root     42 May 10 09:29 libkaezstd.so -> /usr/local/kaezstd/lib/libkaezstd.so.2.0.4
lrwxrwxrwx. 1 root root     42 May 10 09:29 libkaezstd.so.0 -> /usr/local/kaezstd/lib/libkaezstd.so.2.0.4
-rwxr-xr-x. 1 root root 153088 May 10 09:29 libkaezstd.so.2.0.4
-rw-r--r--. 1 root root 986046 May 10 09:29 libzstd.a
lrwxrwxrwx. 1 root root     16 May 10 09:29 libzstd.so -> libzstd.so.1.5.2
lrwxrwxrwx. 1 root root     16 May 10 09:29 libzstd.so.1 -> libzstd.so.1.5.2
-rwxr-xr-x. 1 root root 843000 May 10 09:29 libzstd.so.1.5.2
drwxr-xr-x. 2 root root   4096 May 10 09:29 pkgconfig
```

若通过**ldd**命令查看zstd加速库没链接到libwd和libkaezstd，可以通过LD_LIBRARY_PATH指定依赖库地址。

#### 2.3.2.7 安装KAELz4（按需）

此特性仅在920新型号处理器有效

```shell
sh build.sh lz4
```

查看kaelz4软件库是否生成

```shell
[root@localhost KAE]# ll /usr/local/kaelz4/lib/
total 884
-rwxr-xr-x. 1 root root 208476 May 10 09:29 libkaelz4.a
lrwxrwxrwx. 1 root root     40 May 10 09:29 libkaelz4.so -> /usr/local/kaelz4/lib/libkaelz4.so.2.0.4
lrwxrwxrwx. 1 root root     40 May 10 09:29 libkaelz4.so.0 -> /usr/local/kaelz4/lib/libkaelz4.so.2.0.4
-rwxr-xr-x. 1 root root 145328 May 10 09:29 libkaelz4.so.2.0.4
-rw-r--r--. 1 root root 339872 May 10 09:30 liblz4.a
lrwxrwxrwx. 1 root root     15 May 10 09:30 liblz4.so -> liblz4.so.1.9.4
lrwxrwxrwx. 1 root root     15 May 10 09:30 liblz4.so.1 -> liblz4.so.1.9.4
-rwxr-xr-x. 1 root root 276336 May 10 09:30 liblz4.so.1.9.4
drwxr-xr-x. 2 root root   4096 May 10 09:30 pkgconfig
```

若通过**ldd**命令查看zstd加速库没链接到libwd和libkaelz4，可以通过LD_LIBRARY_PATH指定依赖库地址。

#### 2.3.2.8 源码方式卸载

```shell
sh build.sh driver clean  内核驱动卸载
sh build.sh uadk clean    用户态驱动卸载
sh build.sh engine clean  加解密引擎卸载
sh build.sh zlib clean    压缩库zlib卸载
sh build.sh gzip clean    压缩库gzip卸载
sh build.sh zstd clean    压缩库zstd卸载
sh build.sh lz4 clean     压缩库lz4卸载
sh build.sh cleanup       一键式卸载
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

## 声明
- 此代码仓计划参与OpenSSL/Tongsuo/BoringSSL/Lz4/Zlib/Gzip/Zstd软件开源，仅作OpenSSL/Tongsuo/BoringSSL/Lz4/Zlib/Gzip/Zstd功能扩展或性能提升，编码风格遵照原生开源软件，继承原生开源软件安全设计，不破坏原生开源软件设计及编码风格和方式，软件的任何漏洞与安全问题，均由相应的上游社区根据其漏洞和安全响应机制解决。请密切关注上游社区发布的通知和版本更新。鲲鹏计算社区对软件的漏洞及安全问题不承担任何责任。

## 参与贡献
```
如果您想为本仓库贡献代码，请向本仓库任意maintainer发送邮件
如果您找到产品中的任何Bug，欢迎您提出ISSUE
```