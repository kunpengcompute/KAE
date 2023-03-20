# Kunpeng Acceleration Engine Driver

- [Introduction](#introduction)
- [License](#license)
- [Requirements](#requirements)
- [Installation Instructions](#installation-instructions)
- [Contribution Guidelines](#contribution-Guidelines)
- [Vulnerability Management](#Vulnerability-Management)
- [Quality Requirements](#Quality-Requirements)
- [Secure Design](#Secure-Design)
- [More Information](#more-information)
- [Copyright](#copyright)

## Introduction

Kunpeng Acceleration Engine (KAE) driver is used to build performance competitiveness of common software libraries on the Kunpeng platform.

KAE driver is a new technology within Hisilicon Kunpeng 920 processors. It provides a hardware-enabled foundation for security, authentication, and compression. It significantly increases the performance across cloud, networking, big data, and storage applications and  platforms.  For more information,  visit:

<https://github.com/kunpengcompute/KAE>

## License
The Licensing of the files within this project is split as follows:

The kernel-space KAE driver is under the [SPDX-GPL-2.0](https://opensource.org/licenses/GPL-2.0 ). Please see the LICENSE file in the top level of `kae_driver`.

The user-space KAE driver is under the [APACHE LICENSE, VERSION 2.0](https://www.apache.org/licenses/LICENSE-2.0 ). Please see the LICENSE file in the top level of `warpdrive`.

## Requirements

- CPU: Kunpeng 920 
- Operating System: 
  * CentOS 7.6  4.14.0-115.el7a.0.1.aarch64 version
  * SuSE 15.1 4.12.14-195-default arch64 version
  * NeoKylin 7.6 4.14.0-115.5.1.el7a.06.aarch64 version
  * EulerOS 2.8 4.19.36-vhulk1907.1.0.h410.eulerosv2r8.aarch64 version
  * BCLinux-R7-U6-Server-aarch64 version
  * Kylin 4.0.2 (juniper) 4.15.0-70-generic version
  * Kylin release 4.0.2 (SP2) 4.19.36-vhulk1907.1.0.h403.ky4.aarch64 version
  * UniKylin Linux release 3(Core)  4.18.0-80.ky3.kb21.hw.aarch64 version
  * Ubuntu 18.04.1 LTS 4.15.0-29-generic version

## Installation Instructions

Download the release version of Kunpeng Accelerator Engine Driver from:

<https://github.com/kunpengcompute/KAEdriver>


Note: To build the Kunpeng Accelerator Engine Driver, install the `kernel-devel` package first.

Firstly, install the accelerator driver:

```
cd kae_driver
make
make install
modprobe uacce
modprobe hisi_qm
modprobe hisi_sec2
modprobe hisi_hpre
modprobe hisi_zip
modprobe hisi_rde
```

Check whether the accelerator driver has been loaded successfully by running the `lsmod` command. 

`uacce.ko, hisi_qm.ko, sgl.ko, hisi_sec2.ko, hisi_hpre.ko, hisi_zip.ko` should be in the list. 

Secondly, install the warpdrive:

```
cd warpdrive
sh autogen.sh 
./configure 
make 
make install
```
Check whether the accelerator driver has been loaded successfully by running the `ls -al /usr/local/lib` command. `libwd.so` should be in the list. 

For more information about the installation guide and the user guide, visit:
<https://www.hikunpeng.com/developer/boostkit/library/encryption-decryption>

## Contribution Guidelines

If you want to contribute to KAE driver, please use GitHub [issues](https://github.com/kunpengcompute/KAEdriver/issues/new) for tracking requests and bugs.

## Vulnerability Management
Please refer to https://github.com/kunpengcompute/Kunpeng#security

## Quality Requirements
Please refer to [Secure Coding Specifications](https://github.com/kunpengcompute/Kunpeng/blob/master/security/SecureCoding.md).

## Secure Design
Please refer to [Secure Design](https://github.com/kunpengcompute/Kunpeng/blob/master/security/SecureDesign.md).

## More Information

For further assistance, contact Huawei Support at:

<https://support.huawei.com>

<https://www.hikunpeng.com/developer/boostkit/library/encryption-decryption>

## Copyright

Copyright © 2018 Huawei Corporation. All rights reserved.
