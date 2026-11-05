# KAEOpensslEngine
- KAE加解密是鲲鹏加速引擎的加解密模块，使用鲲鹏硬加速引擎实现RSA/SM2/SM3/SM4/DH/MD5/AES算法，结合无损用户态驱动框架，提供高性能对称加解密、非对称加解密算法能力，兼容OpenSSL 1.1.1x、OpenSSL 3.0.x系列版本、Tongsuo 8.4.0、BoringSSL，支持同步&异步机制。
- 更多信息请参考：https://www.hikunpeng.com/document/detail/zh/kunpengaccel/kae/usermanual/kunpengaccel_16_0002.html。

# 许可证与版权

KAEOpensslEngine 的许可证适用范围按代码来源区分。自研代码采用 Apache-2.0；包含上游代码的文件保留其原有许可证、版权和归属声明。以下路径均相对于本目录。

| 许可证文件 | 许可证 | 适用范围 |
| --- | --- | --- |
| [LICENSE](LICENSE) | Apache License 2.0 | KAEOpensslEngine 自研代码、华为与 Linaro 联合署名的 Apache-2.0 文件，以及明确采用 Apache-2.0 的上游代码。 |
| [LICENSE.openssl](LICENSE.openssl) | 旧版 OpenSSL License 和 Original SSLeay License | 下方列出的旧版 OpenSSL 来源代码；两套许可条件须同时满足，不能任选其一。 |
| [LICENSE.gmssl](LICENSE.gmssl) | GmSSL 2014–2017 原始六条款许可 | `src/v1/alg/ciphers/sw/e_sms4_gcm.c` 中的 GmSSL 来源代码。 |

Apache-2.0 代码中的上游归属声明仍须保留，包括华为与 Linaro 联合署名文件中的 Linaro 声明，以及下列文件中的 OpenSSL 声明：

- `src/v1/alg/ciphers/asm/sm4-armv8.S`
- `src/v1/alg/ciphers/asm/sm4-armv8.h`
- `test/bssl_test/src/rsa/rsa_demo.h`

[src/bssl/alg/bssl_rsa.c](src/bssl/alg/bssl_rsa.c) 包含适配的 BoringSSL/OpenSSL 代码，文件头保留了上游版权、来源文件和 Apache-2.0 参考版本。列出的版本用于源码比对，原始导入版本尚未确认；华为版权声明仅覆盖华为自身的贡献。

以下文件也包含 KAE 适配，文件头分别保留华为与上游声明。华为 Apache-2.0 声明仅适用于华为自身的原创修改；复制或移植的上游代码继续遵守其原有许可：

- `src/v1/alg/ciphers/asm/ce_sm4.c`
- `src/v1/alg/ciphers/asm/ce_sm4.h`
- `src/v1/alg/ciphers/asm/sm4-armv8.h`
- `src/v1/alg/ciphers/sw/e_sms4_gcm.c`

两个 `arm_arch.h` 保留旧版 OpenSSL 来源部分的声明，同时分别为 `src/v1/alg/ciphers/asm/arm_arch.h` 中的 SM3/SM4 能力宏和 `src/v1/alg/ciphers/sw/arm_arch.h` 中的 PAC/BTI 宏块补充上游来源说明。这些新增宏对应的 OpenSSL Apache-2.0 声明仅覆盖相应部分，并不表示这些宏是华为原创。参考版本和补充声明见文件头及 `LICENSE.openssl` 第 3 节。

`LICENSE.openssl` 对应以下文件中的旧版 OpenSSL 来源代码，并收录相关的 OpenSSL、Ribose 版权及归属声明：

- `src/v1/alg/ciphers/asm/arm_arch.h`
- `src/v1/alg/ciphers/asm/ce_sm4.c`
- `src/v1/alg/ciphers/asm/ce_sm4.h`
- `src/v1/alg/ciphers/sw/arm_arch.h`
- `src/v1/alg/ciphers/sw/evp_locl.h`
- `src/v1/alg/ciphers/sw/internal/evp_int.h`
- `src/v1/alg/ciphers/sw/modes_lcl.h`
- `src/v1/alg/ciphers/sw/e_sms4_gcm.c`

`LICENSE.openssl` 完整收录的许可文本取自 OpenSSL_1_1_1w；该版本仅作为许可文本来源，不表示上述文件均从该版本导入。原有文件头中指向上游 `LICENSE` 的旧版 OpenSSL 条款，在本目录由 `LICENSE.openssl` 提供。

`e_sms4_gcm.c` 同时保留 GmSSL 和 OpenSSL 声明，相关代码须遵守两者适用的条款。`LICENSE.gmssl` 完整保留该文件中的原始 GmSSL 许可，不使用其他 GmSSL 版本的许可证替代。

分发包含这些代码的源码或二进制时，应随附适用的许可证，保留相关版权、归属及致谢声明，并遵守修改标识、广告宣传和名称使用等适用条款。相关致谢已收录在 `LICENSE.openssl` 和 `LICENSE.gmssl` 中。外部依赖的 OpenSSL、GmSSL、Tongsuo 和 BoringSSL 按实际使用版本的许可证处理；本模块的 Apache-2.0 许可不替代这些依赖的许可。

# 声明
- 此代码仓计划参与OpenSSL/Tongsuo/BoringSSL软件开源，仅作OpenSSL/Tongsuo/BoringSSL功能扩展或性能提升，编码风格遵照原生开源软件，继承原生开源软件安全设计，不破坏原生开源软件设计及编码风格和方式，软件的任何漏洞与安全问题，均由相应的上游社区根据其漏洞和安全响应机制解决。请密切关注上游社区发布的通知和版本更新。鲲鹏计算社区对软件的漏洞及安全问题不承担任何责任。
