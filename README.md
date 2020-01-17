# Kunpeng Acceleration Engine

- [Introduction](#introduction)
- [License](#license)
- [Requirements](#requirements)
- [Installation Instructions](#installation-instructions)
    - [Building OpenSSL](#building-openssl)
    - [Cloning and Building Kunpeng Acceleration Engine](#cloning-and-building-kunpeng-acceleration-engine)
    - [Testing Kunpeng Accelerator Engine](#testing-kunpeng-accelerator-engine)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Loading Engines by Setting the OpenSSL Configuration File](#loading-engines-by-setting-the-openssl-configuration-file)
- [More Information](#more-information)
- [Copyright](#copyright)

## Introduction

Kunpeng Acceleration Engine is a new technology within Hisilicon Kunpeng 920 processors which 

provides a hardware-enabled foundation for security, authentication, and compression. It significantly increases the performance across cloud, networking, big data, and storage applications and  platforms.

Kunpeng Acceleration Engine includes symmetric encryption, asymmetric encryption, digital signatures, and RSA for accelerating SSL/TLS application, which makes processors more efficient and reduces hardware costs. By accelerating SSL/TLS with Kunpeng Acceleration Engine, you can:

- Support higher-performance secured tunnels and a greater number of authenticated clients
- Have higher-performance encrypted traffic throughout a secured network
- Accelerate compute-intense symmetric and asymmetric cryptography
- Have greater platform application efficiency
- Have higher-performance compression and decompression
- Maximize CPU utilization

So far, the algorithms supported by Kunpeng Acceleration Engine are:

- Asymmetric encryption algorithm:  RSA Support Key Sizes 1024/2048/3072/4096
- Digest algorithm: SM3
- Block cipher algorithm: SM4 Support CTR/XTS/CBC
- Block cipher algorithm: AES Support CTR/XTS/CBC/ECB
- Key exchange algorithm: DH Support 768bit/1024bit/1536bit/2048bit/3072bit/4096bit

## License

It is licensed under the [APACHE LICENSE, VERSION 2.0](https://www.apache.org/licenses/LICENSE-2.0 ). For more information, see the LICENSE file. 

## Requirements

* CPU: Kunpeng 920 
* Operating System: 
  * CentOS 7.6  4.14.0-115.el7a.0.1.aarch64 version
  * SuSE 15.1 4.12.14-195-default arch64 version
  * NeoKylin 7.6 4.14.0-115.5.1.el7a.06.aarch64 version
  * EulerOS 2.8 4.19.36-vhulk1907.1.0.h410.eulerosv2r8.aarch64 version
* OpenSSL 1.1.1a  or later OpenSSL

## Installation Instructions

### Building OpenSSL

Clone OpenSSL from Github at the following location:

    git clone https://github.com/openssl/openssl.git

You are advised to check out and build the OpenSSL 1.1.1a git tag specified in the release notes.
Versions of OpenSSL before OpenSSL 1.1.0 are not supported.

Note: You are not advised to install the accelerated version of OpenSSL as your default system library. Otherwise, acceleration may be used unexpectedly by other applications on the system, resulting in undesired/unsupported behavior. The `--prefix` can be used with the `./config` command to specify the location that `make install` will copy files to. Please see the OpenSSL INSTALL file for full details on usage of the `--prefix` option.

By default, we usually install OpenSSL as follows:

    ./config -Wl,-rpath=/usr/local/lib
    make
    make install
The `-Wl,-rpath` optioncan specify the openssl shared libraries where the binaries will link to.

### Cloning and Building Kunpeng Acceleration Engine

Clone the Github repository containing the Kunpeng Accelerator Engine:

    git clone https://github.com/kunpengcompute/KAE

Download the release version of Kunpeng Accelerator Engine Driver from:

<https://github.com/kunpengcompute/KAEdriver>

Firstly, build and install the accelerator driver:
Note: To build the Kunpeng Accelerator Engine Driver, install the `kernel-devel` package first.

```
tar -zxf Kunpeng_KAE_driver.tar.gz
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
Secondly, install the accelerator library:

```
cd warpdrive
sh autogen.sh 
./configure 
make 
make install
```

Then, install the  Kunpeng Accelerator Engine:

```
cd KAE 
chmod +x configure 
./configure 
make  
make install

```

Note: The `--openssl_path` can be used with the `./configure` command to specify the location that  `make install` will copy files to. The default installation path for the accelerator engine is `/usr/local/lib/openssl-1.1`. You are advised to install the Kunpeng Accelerator Engine by default as the OpenSSL; 
Export the environment variableas `OPENSSL_ENGINES` as follows :

```
export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
```

### Testing Kunpeng Accelerator Engine

Run the following command to check when the Kunpeng Accelerator Engine is loaded correctly:

```
cd /usr/local/bin/
./openssl  genrsa -out test.key -engine kae 2048 
./openssl  rsa -in test.key -pubout -out test_pub.key -engine kae 
./openssl  rsautl -encrypt -in rsa_test -inkey test_pub.key -pubin -out rsa_test.en -engine kae 
./openssl  rsautl -decrypt -in rsa_test.en -inkey test.key -out rsa_test.de -engine kae
```

```
./openssl enc -sm4-cbc -a -in sm4_test -out sm4_test.en -pass pass:123456 -engine kae 
./openssl enc -sm4-cbc -a -in sm4_test -out sm4_test.en -pass pass:123456 -p -engine kae 
./openssl enc -sm4-cbc -d -a -in sm4_test.en -out sm4_test.de -pass pass:123456 -engine kae 
./openssl sm3 -out sm3_out -engine kae sm3_test
```

## Examples

Here is an example to show you how to use the Kunpeng Accelerator Engine. 

```
#include <stdio.h> 
#include <stdlib.h> 
 
/* OpenSSL headers */ 
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 
#include <openssl/engine.h> 
  
int main(int argc, char **argv) 
{ 
    /* Initializing OpenSSL */ 
    SSL_load_error_strings(); 
    ERR_load_BIO_strings(); 
    OpenSSL_add_all_algorithms(); 
     
    /*You can use ENGINE_by_id Function to get the handle of the Kunpeng Accelerator Engine*/ 
    ENGINE *e = ENGINE_by_id("kae");
    ENGINE_init(e); 
     
    /*The user code To Do */ 
    ...

    ENGINE_free(e); 
}

```

## Troubleshooting

The most likely failure point is that the Kunpeng Accelerator Engine is not loaded successfully. If this occurs:

   1. Check that the accelerator driver has been loaded successfully by running the `lsmod` command. 

      `uacce.ko, hisi_qm.ko, sgl.ko, hisi_sec2.ko, hisi_hpre.ko, hisi_zip.ko` should be in the list. 

   2. Check that the paths have been set correctly so that the `libkae.so` engine file can be copied to the correct location.

   3. Check that the installation path has been correctly added to the environment variable `OPENSSL_ENGINES` and exported to the shell by running the `export` command.

## Loading Engines by Setting the OpenSSL Configuration File 

By setting up the OpenSSL configuration file, you can also initialize the Kunpeng Accelerator Engine for your OpenSSL application. For further details on using the `openssl.cnf` file, see the OpenSSL online documentation at:

<https://www.openssl.org/docs/man1.1.0/apps/config.html>

Here is an example to show you how to set up the  `openssl.cnf`  file to load engines. Add the following statements to the global section (assuming that the path is the one that KAE installed):

    openssl_conf = openssl_engine_init
    
    [ openssl_engine_init ]
    engines = engine_section
    
    [ engine_section ]
    kae = kae_section
    
    [ kae_section ]
    engine_id = kae
    dynamic_path = /usr/local/lib/engines-1.1/kae.so


## More Information

For further assistance, contact Huawei Support at:

<https://support.huawei.com>

<https://www.huaweicloud.com/kunpeng/software/accelerator.html>

## Copyright

Copyright © 2018 Huawei Corporation. All rights reserved.
