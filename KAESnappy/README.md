
# KAESnappy 用户使用指南
## 一、概述

KAESnappy算法劫持开源snappy中的snappy_compress接口，通过硬算卸载原压缩流程中的LZ77算法部分，进行性能优化。压缩接口对压缩数据大小无限制，使用方式与开源算法保持一致。

### 特点：

* ​**硬件加速支持**​：通过硬件加速器对压缩过程加速，该接口能够显著提升压缩任务的执行效率，同时降低CPU负载。
* ​**兼容社区SNAPPY格式**​：该接口生成的压缩数据格式与社区Snappy格式兼容。
* ​**轻松集成**​：不修改snappy开源接口，可以轻松集成到现有的应用程序中，用户只需通过动态链接KAESnappy的动态库，就能轻松实现高性能数据压缩。

## 二、背景依赖和安装编译说明

该算法是KAE2.0的一部分，硬件环境和操作系统限制见KAE安装前准备章节。

使用该接口需要正确安装KAE2.0，推荐使用源码安装方式安装最新版本KAE，过程详见：[https://www.hikunpeng.com/document/detail/zh/kunpengaccel/compress/devg-kaezip/kunpengaccel\_kaezip\_0029.html](https://www.hikunpeng.com/document/detail/zh/kunpengaccel/compress/devg-kaezip/kunpengaccel_kaezip_0029.html)

* 硬件限制：
  CPU：限制为 Kunpeng 920 7280Z
* 注意事项：
  KAE依赖相关开发套件的安装。安装命令如下：

```
yum install -y make kernel-devel libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath
```

#### 前置环境设置

- 开启驱动fast模式
  
  ~~~
  rmmod hisi_zip # 删除驱动，这一步执行后，watch命令就看不到那一组256了
  
  #注意是uacc_mode=2,因为是nosva模式；这一步执行后，watch会看到4个256，表示使能正确
  modprobe hisi_zip perf_mode=1 uacce_mode=2 pf_q_num=256
  ~~~
- 设置fast模式下特定有效压缩窗长

    ```
    export KAE_SNAPPY_WINTYPE=8
    export KAE_SNAPPY_COMP_TYPE=8
    ```

### 编译使用步骤
在正确安装KAE2.0之后，在KAE2.0目录下安装KAESNAPPY
  ~~~
  sh build.sh snappy
  ~~~

随后可通过LD_LIBRARY_PATH指定依赖库地址，让应用程序链接至KAESNAPPY的动态库，并通过ldd命令查看是否链接成功
