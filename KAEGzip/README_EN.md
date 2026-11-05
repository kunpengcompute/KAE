# KAEGzip

- KAEGzip is a KAE decompression module. It uses Kunpeng hardware-based acceleration to implement the Deflate algorithm, and works with the lossless user-space driver framework to provide APIs for high-performance compression in Gzip format. It enables you to compress and decompress files more conveniently without calling APIs.

# Open Source Licenses

The licenses in this directory apply according to the origin of the code:

* The original build script `build.sh` is licensed under the Apache License 2.0; see [LICENSE](LICENSE). This license does not cover the GNU gzip source, the adaptation patch or the modified gzip program.
* `open_source/gzip-1.13.tar.gz` preserves the original upstream source archive. GNU gzip and its modified versions use GPL-3.0-or-later; see [COPYING](COPYING) for the full GPLv3 terms. Individual copyright notices and license exceptions in the archive remain in force.
* `patch/kaegzip_for_gzip-1.13.patch` modifies upstream `deflate.c`, `gzip.c`, `gzip.h`, `inflate.c`, `unzip.c`, `util.c` and `zip.c`. The KAE adaptations use GPL-3.0-or-later and retain upstream copyright notices. These upstream-derived files are not relicensed under Apache-2.0.
* Linked dependencies such as KAEZlib, zlib and UADK retain their respective licenses and copyright notices. The resulting combined gzip program is distributed under the requirements of GPLv3.

`build.sh install` installs the compiled `gzip` executable in `/usr/local/kaegzip`.

## Corresponding Source and Distribution

Source is available from the [KAE source repository](https://gitcode.com/boostkit/KAE). Select the release tag or commit matching the distributed binary and retain all additional changes made by the distributor.

When distributing binaries, provide the complete corresponding source or a source provision method permitted by GPLv3 as described in [COPYING](COPYING). Corresponding source must include the gzip source archive, KAE adaptation patch, build and installation scripts, configuration, and the relevant source for required dependencies, except for System Libraries and other exclusions permitted by the license. Release documentation must identify the exact version or commit and the source download location; a link to a changing repository home page alone does not replace provision of corresponding source.

# Statements

- This code repository contributes to the Gzip open-source project solely for performance optimization. It strictly adheres to the coding style and methods, as well as security design of the native open-source software. Any vulnerability and security issues of the software shall be resolved by the corresponding upstream communities according to their response mechanisms. Please pay attention to the notifications and version updates released by the upstream communities. The Kunpeng computing community does not assume any responsibility for software vulnerabilities and security issues.
