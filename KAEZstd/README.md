# KAEZstd
- KAEZstd属于鲲鹏加速引擎的解压缩模块，使用鲲鹏硬加速模块实现lz77_zstd算法，提供ZSTD库标准接口。通过加速引擎可以实现不同场景下应用性能的提升，压缩效率有显著提升。
- 更多信息请参见：https://www.hikunpeng.com/document/detail/zh/kunpengaccel/kae/usermanual/kunpengaccel_16_0002.html。

# 开源许可证

KAEZstd 自研源文件、头文件、构建脚本和测试代码采用 Apache License 2.0，完整条款见 [LICENSE](LICENSE)。该许可仅适用于自研内容，不替换上游代码的版权和许可声明。

上游 Zstandard 提供 BSD-3-Clause 和 GPLv2 双许可选项。本模块与 Apache-2.0 自研代码组合时，对上游部分选择 BSD-3-Clause，并保留其版权和许可声明。具体范围如下：

* `open_source/zstd-1.5.4.tar.gz`：保留原始上游源码包及其中各文件的许可声明和例外。
* `test/gtest/common.h` 和 `test/perftest/common.h`：裁剪自上游 `examples/common.h`，采用上游 BSD-3-Clause 许可，保留 Meta 的版权声明。
* `test/gtest/func_common.cpp`、`test/gtest/func_common.h` 和 `test/perftest/kaezstd_perf.c`：包含上游流式压缩、解压示例的代码。上游部分适用 BSD-3-Clause，Apache-2.0 仅适用于 KAEZstd 的自研修改。
* `open_source/zstd_decompress.patch` 中新增的 `lib/decompress/zstd_decompress_block_aarch64.S`：由 Zstd 解压源码生成的汇编，保留上游版权和双许可声明，不作为纯自研 Apache-2.0 文件处理。两个补丁中的上游代码均继续保留原有许可。
* 下载或链接的其他第三方依赖（例如 GoogleTest）继续适用各自的许可证。

[LICENSE.zstd](LICENSE.zstd) 完整保留所附 Zstandard 1.5.4 的 `LICENSE`、`COPYING`、相关上游文件的版权许可声明，以及本目录此前使用的 Facebook BSD 许可文本，并列明上述代码来源。发行时应一并提供适用的许可证和版权声明。

# 声明
- 此代码仓计划参与Zstd软件开源，仅作Zstd性能提升，编码风格遵照原生开源软件，继承原生开源软件安全设计，不破坏原生开源软件设计及编码风格和方式，软件的任何漏洞与安全问题，均由相应的上游社区根据其漏洞和安全响应机制解决。请密切关注上游社区发布的通知和版本更新。鲲鹏计算社区对软件的漏洞及安全问题不承担任何责任。
