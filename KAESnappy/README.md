
# KAESnappy 用户使用指南
## 概述

KAESnappy算法集成开源Snappy中的Snappy压缩接口（snappy_compress），通过硬算卸载原压缩流程中的Lz77算法部分进行性能优化。压缩接口对压缩数据大小无限制，使用方式与开源Snappy压缩算法保持一致。

### 特点：

* ​**支持硬件加速**​：通过硬件加速器对压缩过程加速，该接口能够显著提升压缩任务的执行效率，同时降低CPU负载。
* ​**兼容性**​：该接口生成的压缩数据格式与社区Snappy格式兼容。
* ​**易集成**​：用户只需通过动态链接KAESnappy的动态库，就能轻松实现高性能数据压缩。不涉及开源Snappy接口的修改，即可集成到现有的应用程序中。

## 背景依赖和安装编译说明

该算法是KAE2.0的一部分，硬件环境和操作系统限制见KAE安装前准备章节。

使用该接口需要正确安装KAE2.0，推荐使用源码安装方式安装最新版本KAE。

* 注意事项：
  KAE依赖相关开发套件的安装。安装命令如下：

```
yum install -y make kernel-devel libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath
```

### 编译与使用
安装KAE2.0之后，在KAE2.0目录下安装KAESnappy：
  ~~~
  sh build.sh snappy
  ~~~

随后可通过LD_LIBRARY_PATH指定依赖库地址，让应用程序链接至KAESnappy的动态库，并通过ldd命令查看是否链接成功。具体步骤可参见[安装指南](../docs/zh/installation_guide.md)。

## 声明
- 此代码仓计划参与Snappy软件开源，仅作Snappy性能提升，编码风格遵照原生开源软件，继承原生开源软件安全设计，不破坏原生开源软件设计及编码风格和方式，软件的任何漏洞与安全问题，均由相应的上游社区根据其漏洞和安全响应机制解决。请密切关注上游社区发布的通知和版本更新。鲲鹏计算社区对软件的漏洞及安全问题不承担任何责任。