# 版本说明书

## 版本配套说明

### 产品版本信息

<a name="table62675726"></a>
<table><tbody><tr id="row41561572"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.1.1"><p id="p11044137"><a name="p11044137"></a><a name="p11044137"></a>产品名称</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.1.1 "><p id="p48427257"><a name="p48427257"></a><a name="p48427257"></a>Kunpeng BoostKit</p>
</td>
</tr>
<tr id="row24726251"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.2.1"><p id="p56669300"><a name="p56669300"></a><a name="p56669300"></a>产品版本</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.2.1 "><p id="p16166112734513"><a name="p16166112734513"></a><a name="p16166112734513"></a><span id="text1726192733514"><a name="text1726192733514"></a><a name="text1726192733514"></a>26.1.RC1</span></p>
</td>
</tr>
<tr id="row5497143514612"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.3.1"><p id="p162251517551"><a name="p162251517551"></a><a name="p162251517551"></a>软件名称</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.3.1 "><p id="p51757141375"><a name="p51757141375"></a><a name="p51757141375"></a>KAE（Kunpeng Accelerator Engine，鲲鹏加速引擎）</p>
</td>
</tr>
<tr id="row615762416269"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.4.1"><p id="p12158152417260"><a name="p12158152417260"></a><a name="p12158152417260"></a>软件版本</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.4.1 "><p id="p51757141375"><a name="p51757141375"></a><a name="p51757141375"></a>2.1.0</p>
</td>
</tr>
</tbody>
</table>

### 硬件版本配套说明

|项目|说明|
|--|--|
|服务器|鲲鹏服务器（开启KAE功能）|
|处理器|鲲鹏920处理器、鲲鹏920新型号处理器、鲲鹏950处理器|
|iBMC|V365及以上版本|
|BIOS|V105及以上版本|

>![](public_sys-resources/icon-note.gif) **说明：**
>
>- 非虚拟化场景使用加速器建议关闭SMMU，开启SMMU会影响加速器性能，具体操作请参见《[BIOS 参数参考（鲲鹏920处理器）](https://support.huawei.com/enterprise/zh/doc/EDOC1100088653/ca8d53c6)》。
>- KAEZstd、KAELz4和KAESnappy目前仅支持在鲲鹏920新型号处理器以及鲲鹏950处理器上使用。不同处理器型号支持的加密/压缩算法存在不同，详情请参见《README》中的“[算法支持与规格](../../README.md#算法支持与规格)”内容。
>- 鲲鹏950处理器仅支持使用KAE2.0。

### 与操作系统配套说明

|KAE版本|操作系统|OpenSSL版本|
|--|--|--|
|KAE2.0（当前维护版本）|openEuler 22.03 LTS SP1/SP2/SP3/SP4<br>openEuler 24.03 LTS SP1/SP2/SP3<br>EulerOS-V2.0 SP12<br>TencentOS 5.4<br>4.19内核（仅支持用户态使用）|OpenSSL 1.1.1x系列<br>OpenSSL 3.0.x系列<br>Tongsuo 8.4.0<br>BoringSSL|
|KAE1.0（历史版本，不再维护更新）|CentOS 7.6 4.14.0-115.el7a.0.1.aarch64<br>SUSE 15.1 4.12.14-195-default.aarch64<br>EulerOS 2.8 4.19.36-vhulk1907.1.0.h410.eulerosv2r8.aarch64<br>NeoKylin 7.6 4.14.0-115.5.1.el7a.06.aarch64<br>BCLinux-R7-U6-Server-aarch64<br>Kylin 4.0.2 (juniper) 4.15.0-70-generic<br>Kylin release 4.0.2 (SP2) 4.19.36-vhulk1907.1.0.h403.ky4.aarch64<br>UniKylin Linux release 3(Core)  4.18.0-80.ky3.kb21.hw.aarch64<br>Ubuntu 18.04.1 LTS 4.15.0-29-generic<br>openEuler 20.03 LTS 4.19.90-2003.4.0.0036.oe1.aarch64<br>openEuler 20.03 LTS SP1 4.19.90-2012.4.0.0053.oe1.aarch64|OpenSSL 1.1.1x系列|

>![](public_sys-resources/icon-note.gif) **说明：** 
>- openEuler 22.03 LTS SP1仅支持KAE v2.0.3及以前版本。
>- KAE2.0在4.19内核下仅支持通过UADK、OpenSSL/Tongsuo/BoringSSL、Zlib、ZSTD、LZ4、Snappy、Gzip等用户态接口使用，不支持Linux内核crypto API中的加解密及压缩/解压缩接口、dm-crypt、SM4-XTS等内核态接口。

## 版本使用注意事项

请参见《README》中的“[算法支持与规格](../../README.md#算法支持与规格)”内容。

## V26.1.RC1

### 更新说明

**新增特性**

|KAE版本|更新说明|
|--|--|
|KAE2.0|新增支持在KVM虚拟机场景下通过VF查询HostOS上PF设备的硬件故障隔离状态和隔离阈值;<br>新增支持4.19内核用户态使用，不支持内核态加解密及压缩/解压缩接口。|

**修改特性**

无

**删除特性**

无

### 已解决的问题

无

### 遗留问题

无

## V26.0.RC1

### 更新说明

**新增特性**

|KAE版本|更新说明|
|--|--|
|KAE2.0|KAEZlib加速压缩库新增支持异步模式；新增适配Snappy压缩库硬加速|

**修改特性**

无

**删除特性**

无

### 已解决的问题

无

### 遗留问题

无

## V25.3.0

### 更新说明

**新增特性<a name="section10245714145913"></a>**

|KAE版本|更新说明|
|--|--|
|KAE2.0|新增支持鲲鹏950处理器。KAELz4加速压缩库异步接口新增支持polling模式。|

**修改特性<a name="section18746155435910"></a>**

无

**删除特性<a name="section143731931903"></a>**

无

### 已解决的问题

无

### 遗留问题

无

## V25.2.RC1

### 更新说明

**新增特性<a name="section10245714145913"></a>**

|KAE版本|更新说明|
|--|--|
|KAE2.0|优化KAELz4库解压性能。优化KAEZstd库解压性能。|

**修改特性<a name="section18746155435910"></a>**

无

**删除特性<a name="section143731931903"></a>**

无

### 已解决的问题

无

### 遗留问题

无

## V25.1.RC1

### 更新说明

**新增特性<a name="section11862975"></a>**

|KAE版本|更新说明|
|--|--|
|KAE2.0|新增适配TencentOS 5.4操作系统。加解密库新增适配BoringSSL RSA硬加速。KAELz4加速压缩库新增支持异步模式。|

**修改特性<a name="section16450949161512"></a>**

无

**删除特性<a name="section9218125814159"></a>**

无

### 已解决的问题

无

### 遗留问题

无

## V25.0.RC1

### 更新说明

**新增特性<a name="section11862975"></a>**

|KAE版本|更新说明|
|--|--|
|KAE1.0|新增支持鲲鹏920新型号处理器。|
|KAE2.0|加解密库基于鲲鹏920系列处理器新增对Tongsuo 8.4.0的适配，通过KAE加速引擎显著提升Web场景下HTTPS安全连接的性能。KAEZlib基于鲲鹏920系列处理器适配开源Gzip压缩算法，用于日志数据压缩存储、软件版本压缩打包等场景下使用KAE提升压缩和解压缩性能。|

**修改特性<a name="section16450949161512"></a>**

无

**删除特性<a name="section9218125814159"></a>**

无

### 已解决的问题

无

### 遗留问题

无

## V24.0.0

### 更新说明

**新增特性<a name="section961991011171"></a>**

|KAE版本|更新说明|
|--|--|
|KAE2.0|新增适配openEuler 22.03 LTS SP3/SP4操作系统。加解密库新增适配OpenSSL 3.0.x系列版本。解压缩库基于鲲鹏920新型号处理器新增KAEZstd、KAELz4加速库。|

**修改特性<a name="section16450949161512"></a>**

无

**删除特性<a name="section9218125814159"></a>**

无

### 已解决的问题

无

### 遗留问题

无

## 版本配套文档

### V26.1.RC1版本配套文档

| 文档名称 | 内容简介 | 交付形式 |
| --- | --- | --- |
| 《版本说明书》 | 提供KAE每个发布版本的基础信息和特性更新信息。 | 开源仓 |
| 《用户指南》 | 提供接口说明、接口调用示例、日志查询方法等。 | 开源仓 |
| 《最佳实践》 | 提供KAE在Web、分布式存储、数据库、虚拟化场景下使用的实践案例。 | 开源仓 |
| 《快速入门》 | 提供KAE加解密和压缩库快速使能并验证加速能力的快速入门指导。 | 开源仓 |
| 《安装指南》 | 提供KAE源码编译安装和RPM包安装方式的详细指导。 | 开源仓 |
| 《常见问题》 | 本文档提供提供KAE安装、使用过程的常见问题和解决方法。 | 开源仓 |

### 获取文档的方法

您可以通过[开源仓](https://gitcode.com/boostkit/KAE)浏览和获取相关文档。
