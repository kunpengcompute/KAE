# Release Notes

## Version Mapping

### Product Version Information

<a name="table62675726"></a>
<table><tbody><tr id="row41561572"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.1.1"><p id="p11044137"><a name="p11044137"></a><a name="p11044137"></a>Product Name</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.1.1 "><p id="p48427257"><a name="p48427257"></a><a name="p48427257"></a>Kunpeng BoostKit</p>
</td>
</tr>
<tr id="row24726251"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.2.1"><p id="p56669300"><a name="p56669300"></a><a name="p56669300"></a>Product Version</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.2.1 "><p id="p16166112734513"><a name="p16166112734513"></a><a name="p16166112734513"></a><span id="text1726192733514"><a name="text1726192733514"></a><a name="text1726192733514"></a>26.1.RC1</span></p>
</td>
</tr>
<tr id="row5497143514612"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.3.1"><p id="p162251517551"><a name="p162251517551"></a><a name="p162251517551"></a>Software Name</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.3.1 "><p id="p51757141375"><a name="p51757141375"></a><a name="p51757141375"></a>Kunpeng Accelerator Engine (KAE)</p>
</td>
</tr>
<tr id="row615762416269"><th class="firstcol" valign="top" width="42.17%" id="mcps1.1.3.4.1"><p id="p12158152417260"><a name="p12158152417260"></a><a name="p12158152417260"></a>Software Version</p>
</th>
<td class="cellrowborder" valign="top" width="57.830000000000005%" headers="mcps1.1.3.4.1 "><p id="p51757141375"><a name="p51757141375"></a><a name="p51757141375"></a>2.1.0</p>
</td>
</tr>
</tbody>
</table>

### Hardware Version Mapping

|Item|Description|
|--|--|
|Server|Kunpeng server (with KAE enabled)|
|Processor|Kunpeng 920 processor, new Kunpeng 920 processor model, or Kunpeng 950 processor|
|iBMC|V365 or later|
|BIOS|V105 or later|

>![](public_sys-resources/icon-note.gif) **NOTE**
>
>- To use the accelerator in the non-virtualization scenario, you need to disable SMMU. Enabling the SMMU will affect the accelerator performance. For details, see [BIOS Parameter Reference (Kunpeng 920 Processor)](https://support.huawei.com/enterprise/en/doc/EDOC1100088647/426cffd9/about-this-document).
>- KAEZstd, KAELz4, and KAESnappy can only be used on the new Kunpeng 920 processor model and Kunpeng 950 processor. Encryption and compression algorithms vary with processor models. For details, see "Supported Algorithms and Specifications" in [README_EN](../../README_EN.md#supported-algorithms-and-specifications).
>- Kunpeng 950 processors support only KAE 2.0.

### OS Version Mapping

|KAE Version|OS|OpenSSL Version|
|--|--|--|
|KAE 2.0 (active maintenance version)|<ul><li>openEuler 22.03 LTS SP1/SP2/SP3/SP4</li><li>openEuler 24.03 LTS SP1/SP2/SP3</li><li>EulerOS V2.0 SP12</li><li>TencentOS 5.4</li><li>Kernel 4.19 (user mode only)</li></ul>|<ul><li>OpenSSL 1.1.1x</li><li>OpenSSL 3.0.x</li><li>Tongsuo 8.4.0</li><li>BoringSSL</li></ul>|
|KAE 1.0 (legacy version, not maintained)|<ul><li>CentOS 7.6 4.14.0-115.el7a.0.1.aarch64</li><li>SUSE 15.1 4.12.14-195-default.aarch64</li><li>EulerOS 2.8 4.19.36-vhulk1907.1.0.h410.eulerosv2r8.aarch64</li><li>NeoKylin 7.6 4.14.0-115.5.1.el7a.06.aarch64</li><li>BCLinux-R7-U6-Server-aarch64</li><li>Kylin 4.0.2 (juniper) 4.15.0-70-generic</li><li>Kylin release 4.0.2 (SP2) 4.19.36-vhulk1907.1.0.h403.ky4.aarch64</li><li>UniKylin Linux release 3(Core) 4.18.0-80.ky3.kb21.hw.aarch64</li><li>Ubuntu 18.04.1 LTS 4.15.0-29-generic</li><li>openEuler 20.03 LTS 4.19.90-2003.4.0.0036.oe1.aarch64</li><li>openEuler 20.03 LTS SP1 4.19.90-2012.4.0.0053.oe1.aarch64</li></ul>|OpenSSL 1.1.1x|

>![](public_sys-resources/icon-note.gif) **NOTE**
>
>- openEuler 22.03 LTS SP1 supports only KAE v2.0.3 and earlier versions.
>- Under kernel 4.19, KAE 2.0 supports usage only through user-mode interfaces such as UADK, OpenSSL/Tongsuo/BoringSSL, zlib, zstd, LZ4, Snappy, and gzip. It does not support kernel-mode interfaces such as encryption/decryption and compression/decompression interfaces in the Linux kernel crypto API, dm-crypt, and SM4-XTS.

## Usage Precautions

For details, see [Supported Algorithms and Specifications](../../README_EN.md#supported-algorithms-and-specifications).

## V26.1.RC1

### Change Description

**New Features**

|KAE Version|Description|
|--|--|
|KAE 2.0|<ul><li>Added support for querying the hardware fault isolation status and isolation threshold of PF devices on the host OS via VFs in KVM scenarios.</li><li>Added support for user-mode usage under kernel 4.19, while kernel-mode encryption/decryption and compression/decompression interfaces are not supported.</li></ul>|

**Modified Features**

None

**Deleted Features**

None

### Resolved Issues

None

### Known Issues

None

## V26.0.RC1

### Change Description

**New Features**

|KAE Version|Change Description|
|--|--|
|KAE 2.0|Added asynchronous support to the KAEZlib compression library and adapted to hardware acceleration of the Snappy library.|

**Modified Features**

None

**Deleted Features**

None

### Resolved Issues

None

### Known Issues

None

## V25.3.0

### Change Description

**New Features<a name="section10245714145913"></a>**

|KAE Version|Change Description|
|--|--|
|KAE 2.0|Supported Kunpeng 950 processors. Added polling support for asynchronous APIs of the KAELz4 compression library.|

**Modified Features<a name="section18746155435910"></a>**

None

**Deleted Features<a name="section143731931903"></a>**

None

### Resolved Issues

None

### Known Issues

None

## V25.2.RC1

### Change Description

**New Features<a name="section10245714145913"></a>**

|KAE Version|Change Description|
|--|--|
|KAE 2.0|Optimized the decompression performance of the KAELz4 library. Optimized the decompression performance of the KAEZstd library.|

**Modified Features<a name="section18746155435910"></a>**

None

**Deleted Features<a name="section143731931903"></a>**

None

### Resolved Issues

None

### Known Issues

None

## V25.1.RC1

### Change Description

**New Features<a name="section11862975"></a>**

|KAE Version|Change Description|
|--|--|
|KAE 2.0|Adapted to TencentOS 5.4. Added support for BoringSSL RSA hardware-based acceleration to the encryption and decryption library. Added asynchronous support to the KAELz4 compression library.|

**Modified Features<a name="section16450949161512"></a>**

None

**Deleted Features<a name="section9218125814159"></a>**

None

### Resolved Issues

None

### Known Issues

None

## V25.0.RC1

### Change Description

**New Features<a name="section11862975"></a>**

|KAE Version|Change Description|
|--|--|
|KAE 1.0|Supported the new Kunpeng 920 processor model.|
|KAE 2.0|Added support for Tongsuo 8.4.0 to the encryption and decryption library based on Kunpeng 920 series processors so that KAE can be used to significantly improve the performance of HTTPS connections in web scenarios. Added support for the open source Gzip compression algorithm to KAEZlib based on Kunpeng 920 series processors so that KAE can be used to improve performance in scenarios such as log compression and storage, software compression and packaging, and other.|

**Modified Features<a name="section16450949161512"></a>**

None

**Deleted Features<a name="section9218125814159"></a>**

None

### Resolved Issues

None

### Known Issues

None

## V24.0.0

### Change Description

**New Features<a name="section961991011171"></a>**

|KAE Version|Change Description|
|--|--|
|KAE 2.0|Added support for openEuler 22.03 LTS SP3/SP4. Added support for OpenSSL 3.0.x to the encryption and decryption library. Added KAEZstd and KAELz4 to the decompression library based on the new Kunpeng 920 processor model.|

**Modified Features<a name="section16450949161512"></a>**

None

**Deleted Features<a name="section9218125814159"></a>**

None

### Resolved Issues

None

### Known Issues

None

## Documentation

### V26.1.RC1 Documentation

|Document|Description|Delivery Method|
|--|--|--|
|*Release Notes*|Provides basic information and feature updates of each KAE version.|Open-source repository|
|*User Guide*|Provides API descriptions, API calling examples, log query methods, and more.|Open-source repository|
|*Best Practices*|Provides the practices of using the KAE in web, distributed storage, database, and virtualization scenarios.|Open-source repository|
|*Quick Start*|Provides guidance on how to quickly enable KAE encryption, decryption, and compression libraries and verify the acceleration capabilities.|Open-source repository|
|*Installation Guide*|Provides detailed instructions for installing KAE by compiling the source code and installing the RPM package.|Open-source repository|
|*FAQs*|Provides answers to frequently asked questions (FAQs) about installing and using KAE.|Open-source repository|

### Obtaining Documentation

Visit the [open-source repository](https://gitcode.com/boostkit/KAE) to view or download required documents.
