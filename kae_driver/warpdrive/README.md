# Warpdrive

- [Introduction](#introduction)
- [License](#license)
- [Requirements](#requirements)
- [Installation Instructions](#installation-instructions)
- [More Information](#more information)
- [Copyright](#Copyright)

## Introduction

It is the user-space driver for the Kunpeng Acceleration Engine，which is a new technology within Hisilicon Kunpeng 920 processors，provides a hardware-enabled foundation for security, authentication, and compression. It significantly increases the performance across cloud, networking, big data, and storage applications and  platforms.  For more information,  please see the following location at:

<https://github.com/kunpengcompute/kunpeng_kae>

## License

It is licensed under the [APACHE LICENSE, VERSION 2.0](https://www.apache.org/licenses/LICENSE-2.0 ). For more information, see the LICENSE file. 

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

Download the Kunpeng Accelerator Engine Warpdrive from:

```
https://www.huaweicloud.com/kunpeng/software/accelerator.html
```

Note: To build the Kunpeng Accelerator Engine Warpdrive, install the `automake` package first.

install the warpdrive:

```
cd warpdrive
sh autogen.sh 
./configure 
make 
make install
```

Check the accelerator driver has been loaded successfully by running the `ls -al /usr/local/lib` command. `libwd.so` should be in the list. 

## More Information

For further assistance, contact Huawei Support at:

<https://support.huawei.com>

## Copyright

Copyright © 2018 Huawei Corporation. All rights reserved.