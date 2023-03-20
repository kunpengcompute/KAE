# Kunpeng Acceleration Engine Driver

- [Introduction](#introduction)
- [License](#license)
- [Requirements](#requirements)
- [Installation Instructions](#installation-instructions)
- [More Information](#more information)
- [Copyright](#Copyright)

## Introduction

It is the kernel-space driver for the Kunpeng Acceleration Engine，which is a new technology within Hisilicon Kunpeng 920 processors，provides a hardware-enabled foundation for security, authentication, and compression. It significantly increases the performance across cloud, networking, big data, and storage applications and  platforms.  For more information,  please see the following location at:

<https://github.com/kunpengcompute/kunpeng_kae>

## License

It is licensed under the [SPDX-GPL-2.0](https://opensource.org/licenses/GPL-2.0 ). For more information, see the LICENSE file. 

## Requirements

- CPU: Kunpeng 920 
- Operating System: 
  - CentOS 7.6  4.14.0-115.el7a.0.1.aarch64 version
  - SuSE 15.1 4.12.14-195-default arch64 version
  - NeoKylin 7.6 4.14.0-115.5.1.el7a.06.aarch64 version
  - EulerOS 2.8 4.19.36-vhulk1907.1.0.h410.eulerosv2r8.aarch64 version
  - BCLinux-R7-U6-Server-aarch64 version
  - Kylin 4.0.2 (juniper) 4.15.0-70-generic version
  - Kylin release 4.0.2 (SP2) 4.19.36-vhulk1907.1.0.h403.ky4.aarch64 version
  - UniKylin Linux release 3(Core)  4.18.0-80.ky3.kb21.hw.aarch64 version
  - Ubuntu 18.04.1 LTS 4.15.0-29-generic version

## Installation Instructions

Download the Kunpeng Accelerator Engine Driver from:

```
https://www.huaweicloud.com/kunpeng/software/accelerator.html
```

Note: To build the Kunpeng Accelerator Engine Driver, install the `kernel-devel` package first.

install the accelerator driver:

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

Check the accelerator driver has been loaded successfully by running the `lsmod` command. 

`uacce.ko, hisi_qm.ko, sgl.ko, hisi_sec2.ko, hisi_hpre.ko, hisi_zip.ko` should be in the list. 

## More Information

For further assistance, contact Huawei Support at:

<https://support.huawei.com>

## Copyright

Copyright © 2018 Huawei Corporation. All rights reserved.