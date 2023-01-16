OpenSSL engine for uadk
=================

- [Prerequisites](#prerequisites)
- [Installation Instruction](#installation-instruction)
	- [Build and install OpenSSL](#build-and-install-openssl)
	- [Build and install UADK](#build-and-install-uadk)
	- [Build and install UADK engine](#build-and-install-uadk-engine)
	- [Testing](#testing)
- [Install libraries to the temp folder](#Install-libraries-to-the-temp-folder)
- [Environment variable of uadk engin](#Environment-variable-of-uadk-engine)

Prerequisites
=============
* CPU: aarch64
* OpenSSL: 1.1.1f
* libnuma
* zlib

Installation Instruction
========================

Build and install OpenSSL
-----------------------

```
    git clone https://github.com/openssl/openssl.git
    cd openssl
    git checkout -b OpenSSL_1_1_1f OpenSSL_1_1_1f
    ./config -Wl,-rpath=/usr/local/lib
    make
    make test
    sudo make install
    openssl version
```

Build and install UADK
--------------------

```
    git clone https://github.com/Linaro/uadk.git
    cd uadk
    ./cleanup.sh
    ./autogen.sh
    ./configure
    make
    sudo make install
```
* If get error:"cannot find -lnuma", please install the libnuma-dev
* If get error:"fatal error: zlib.h: No such file or directory", please install zlib.

Build and install UADK Engine
-----------------------------------
```
    git clone https://github.com/Linaro/uadk_engine.git
    cd uadk_engine
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae
    make
    sudo make install

    Option --enable-kae can be chosen to enable KAE for non-sva version
```

Testing
-------
```
    ./test/sanity_test.sh
```

Install libraries to the temp folder
====================================

   Install all libraries to a temp folder like /tmp/build for debugging purposes.\
   If so, PKG_CONFIG_PATH has to be exported to ensure the env is set up correctly.\
   The pkg-config can be used for double-checking env.

```
    $ cd openssl
    $ ./config --prefix=/tmp/build
    $ make; make install

    $ export PKG_CONFIG_PATH=/tmp/build/lib/pkgconfig/
    $ pkg-config libcrypto --libs
    -L/tmp/build/lib -lcrypto

    $ cd uadk
    $ ./autogen.sh
    $ ./configure --prefix=/tmp/build
    $ make; make install

    $ pkg-config libwd --libs
    -L/tmp/build/lib -lwd

    $ cd uadk_engine
    $ autoreconf
    $ ./configure --prefix=/tmp/build
    $ make; make install

    $ openssl engine -c /tmp/build/lib/uadk_engine.so
    $ ./test/sanity_test.sh /tmp/build/lib/uadk_engine.so

```

Environment variable of uadk engine
===================================
Introduction
------------
Through the environment variable function, users can configure the number of\
queue resources that can be applied by different algorithms by setting the\
algorithm switch in the openssl.cnf file.

Usage
-----
#. Firstly, modify the openssl.cnf file, add the following settings at the beginning of this file:

```
openssl_cnf = openssl_def
[openssl_def]
engines = engine_section
[engine_section]
uadk_engine = uadk_section
[uadk_section]
UADK_CMD_ENABLE_RSA_ENV = 1
UADK_CMD_ENABLE_DH_ENV = 1
UADK_CMD_ENABLE_CIPHER_ENV = 1
UADK_CMD_ENABLE_DIGEST_ENV = 1
UADK_CMD_ENABLE_ECC_ENV = 1
```
Note:
* The number 1 for enable environment variable, and 0 for disable environment variable.
* By default, you can find openssl.cnf file under /usr/local/ssl/ path.

#. Secondly, use "export" command to set queue number.
For example,
```
export WD_RSA_CTX_NUM="sync:2@0,async:4@0"
export WD_DH_CTX_NUM="sync:2@0,async:4@0"
export WD_CIPHER_CTX_NUM="sync:2@2,async:4@2"
export WD_DIGEST_CTX_NUM="sync:2@2,async:4@2"
export WD_ECC_CTX_NUM="sync:2@0,async:4@0"
```
Note:
* You can write these commands into ~/.bashrc file and source it, or just input temporarily.
* "sync" indicates synchronous mode, "async" indicates asynchronous mode.
* "sync:2@0" means request 2 queues on numa-0 node, under synchronous mode.
* "async:2@0" means request 2 queues on numa-0 node, under asynchronous mode.
* If you do not perform the second step, the engine will use the default\
  setting:"sync:2@0, async:2@0" to request queues from hardware.
