# KAEGzip
- KAEGzip属于鲲鹏加速引擎的解压缩模块，使用鲲鹏硬加速模块实现deflate算法，结合无损用户态驱动框架，提供高性能Gzip格式压缩接口，使用户能够更加便捷地进行文件的压缩和解压操作，而不必通过API方式进行调用。

# 开源许可证

本目录按代码来源分别适用以下许可证：

* 自研构建脚本 `build.sh` 采用 Apache License 2.0，完整条款见 [LICENSE](LICENSE)。该许可不覆盖 GNU gzip 源码、适配补丁或修改后的 gzip 程序。
* `open_source/gzip-1.13.tar.gz` 保留原始上游源码包。GNU gzip 及其修改版本采用 GPL-3.0-or-later，完整 GPLv3 条款见 [COPYING](COPYING)；源码包中各文件原有的版权声明和许可例外继续有效。
* `patch/kaegzip_for_gzip-1.13.patch` 修改上游的 `deflate.c`、`gzip.c`、`gzip.h`、`inflate.c`、`unzip.c`、`util.c` 和 `zip.c`。KAE 适配修改采用 GPL-3.0-or-later，并保留上游版权声明。这些上游来源代码不重新许可为 Apache-2.0。
* 链接的 KAEZlib、zlib、UADK 等依赖继续适用各自的许可证；应保留它们的版权和许可声明。最终组合的 gzip 程序按 GPLv3 的要求发行。

`build.sh install` 将编译生成的 `gzip` 可执行文件安装到 `/usr/local/kaegzip`。

## 对应源码与发行

源码可从 [KAE 源码仓库](https://gitcode.com/boostkit/KAE) 获取。应选择与所发布二进制一致的发布标签或提交，并保留发行者的全部额外修改。

分发二进制时，应按 [COPYING](COPYING) 提供对应的完整源码或符合 GPLv3 的源码提供方式。对应源码应包含所使用的 gzip 源码包、KAE 适配补丁、构建和安装脚本、配置及所需依赖的相应源码（法律允许排除的系统库等除外）。发行说明应标明准确的版本或提交及源码获取地址；仅提供可能持续变化的仓库首页链接不能替代对应源码的提供。

# 声明
- 此代码仓计划参与Gzip软件开源，仅作Gzip性能提升，编码风格遵照原生开源软件，继承原生开源软件安全设计，不破坏原生开源软件设计及编码风格和方式，软件的任何漏洞与安全问题，均由相应的上游社区根据其漏洞和安全响应机制解决。请密切关注上游社区发布的通知和版本更新。鲲鹏计算社区对软件的漏洞及安全问题不承担任何责任。