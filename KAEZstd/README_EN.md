# KAEZstd

- KAEZstd is a KAE decompression module. It uses Kunpeng hardware-based acceleration to implement the lz77_zstd algorithm and provides standard zstd library APIs. KAE can improve application performance in different scenarios and significantly enhance compression efficiency.
- For more information, see https://www.hikunpeng.com/document/detail/en/kunpengaccel/kae/usermanual/kunpengaccel_16_0002.html.

# Open Source Licenses

Original KAEZstd source files, headers, build scripts and test code are licensed under the Apache License 2.0; see [LICENSE](LICENSE) for the full terms. This license applies only to original contributions and does not replace upstream copyright or license notices.

Upstream Zstandard offers a choice of BSD-3-Clause or GPLv2. This module selects BSD-3-Clause for upstream code combined with its Apache-2.0 contributions and retains the upstream copyright and license notices. The scope is as follows:

* `open_source/zstd-1.5.4.tar.gz`: the original upstream source archive, including individual file license notices and exceptions, is preserved.
* `test/gtest/common.h` and `test/perftest/common.h`: these are reduced copies of upstream `examples/common.h`. They use the upstream BSD-3-Clause license and retain Meta's copyright notice.
* `test/gtest/func_common.cpp`, `test/gtest/func_common.h` and `test/perftest/kaezstd_perf.c`: these contain code from upstream streaming compression and decompression examples. The upstream portions use BSD-3-Clause; Apache-2.0 applies only to original KAEZstd modifications.
* `lib/decompress/zstd_decompress_block_aarch64.S`, added by `open_source/zstd_decompress.patch`: this assembly is generated from Zstd decompression source. It retains the upstream copyright and dual-license notice and is not treated as an original Apache-2.0 file. Upstream code in both patches retains its existing licenses.
* Other third-party dependencies that are downloaded or linked, such as GoogleTest, retain their respective licenses.

[LICENSE.zstd](LICENSE.zstd) preserves the complete `LICENSE` and `COPYING` from the bundled Zstandard 1.5.4, the relevant upstream copyright and license notice, and the Facebook BSD license text previously used in this directory. It also records the source of the code identified above. Distributions must include the applicable license texts and copyright notices.

# Statements

- This code repository contributes to the Zstd open-source project solely for performance optimization. It strictly adheres to the coding style and methods, as well as security design of the native open-source software. Any vulnerability and security issues of the software shall be resolved by the corresponding upstream communities according to their response mechanisms. Please pay attention to the notifications and version updates released by the upstream communities. The Kunpeng computing community does not assume any responsibility for software vulnerabilities and security issues.
