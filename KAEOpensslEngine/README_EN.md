# KAEOpensslEngine

- The KAE encryption and decryption module implements the RSA, SM2, SM3, SM4, DH, MD5, and AES algorithms. It provides high-performance symmetric and asymmetric encryption and decryption based on the lossless user-mode driver framework. It is compatible with OpenSSL 1.1.1x, OpenSSL 3.0.x, Tongsuo 8.4.0, and BoringSSL, and supports synchronous and asynchronous mechanisms.
- For more information, see https://www.hikunpeng.com/document/detail/en/kunpengaccel/kae/usermanual/kunpengaccel_16_0002.html.

# Licenses and copyright

The applicable licenses in KAEOpensslEngine depend on the origin of the code. Original KAEOpensslEngine code is licensed under Apache-2.0. Files containing upstream code retain their original licenses, copyright notices, and attribution notices. All paths below are relative to this directory.

| License file | License | Scope |
| --- | --- | --- |
| [LICENSE](LICENSE) | Apache License 2.0 | Original KAEOpensslEngine code, Apache-2.0 files carrying both Huawei and Linaro copyright notices, and upstream code explicitly licensed under Apache-2.0. |
| [LICENSE.openssl](LICENSE.openssl) | Legacy OpenSSL License and Original SSLeay License | The legacy OpenSSL-derived code in the files listed below. Both sets of conditions apply; they are not alternative licenses. |
| [LICENSE.gmssl](LICENSE.gmssl) | Original GmSSL 2014–2017 six-clause license | The GmSSL-derived portions of `src/v1/alg/ciphers/sw/e_sms4_gcm.c`. |

Upstream attribution notices must also be retained in Apache-2.0 code. These include the Linaro notices in files carrying both Huawei and Linaro notices, and the OpenSSL notices in:

- `src/v1/alg/ciphers/asm/sm4-armv8.S`
- `src/v1/alg/ciphers/asm/sm4-armv8.h`
- `test/bssl_test/src/rsa/rsa_demo.h`

[src/bssl/alg/bssl_rsa.c](src/bssl/alg/bssl_rsa.c) contains adapted BoringSSL/OpenSSL code. Its header preserves the upstream copyright notices, source paths, and Apache-2.0 reference versions. Those versions identify implementations used for source comparison; the original import versions have not been confirmed. The Huawei copyright notice applies only to Huawei's contributions.

The following files also contain KAE adaptations and retain separate Huawei and upstream notices. The Huawei Apache-2.0 notice applies only to Huawei's original modifications; copied or ported upstream code retains its original license terms:

- `src/v1/alg/ciphers/asm/ce_sm4.c`
- `src/v1/alg/ciphers/asm/ce_sm4.h`
- `src/v1/alg/ciphers/asm/sm4-armv8.h`
- `src/v1/alg/ciphers/sw/e_sms4_gcm.c`

Both `arm_arch.h` files retain the notices for their legacy OpenSSL-derived portions. Additional upstream attribution covers the SM3/SM4 capability macros in `src/v1/alg/ciphers/asm/arm_arch.h` and the PAC/BTI macro blocks in `src/v1/alg/ciphers/sw/arm_arch.h`. The corresponding OpenSSL Apache-2.0 notices apply only to those additions and do not identify them as Huawei-original code. See the file headers and section 3 of `LICENSE.openssl` for the reference version and additional notice.

`LICENSE.openssl` applies to the legacy OpenSSL-derived code in the following files and includes the relevant OpenSSL and Ribose copyright and attribution notices:

- `src/v1/alg/ciphers/asm/arm_arch.h`
- `src/v1/alg/ciphers/asm/ce_sm4.c`
- `src/v1/alg/ciphers/asm/ce_sm4.h`
- `src/v1/alg/ciphers/sw/arm_arch.h`
- `src/v1/alg/ciphers/sw/evp_locl.h`
- `src/v1/alg/ciphers/sw/internal/evp_int.h`
- `src/v1/alg/ciphers/sw/modes_lcl.h`
- `src/v1/alg/ciphers/sw/e_sms4_gcm.c`

The complete license text in `LICENSE.openssl` comes from OpenSSL_1_1_1w. This is a license-text reference, not a claim that all listed files were imported from that release. References to the upstream `LICENSE` in the original legacy OpenSSL headers are covered by `LICENSE.openssl` in this directory.

`e_sms4_gcm.c` retains both GmSSL and OpenSSL notices, and the relevant code remains subject to the applicable terms of both. `LICENSE.gmssl` reproduces the file's complete original GmSSL notice without substituting a license from a different GmSSL release.

When distributing source or binaries containing this code, include the applicable license texts, retain the relevant copyright, attribution, and acknowledgement notices, and comply with applicable requirements for modification notices, advertising, and use of names. The relevant acknowledgements are included in `LICENSE.openssl` and `LICENSE.gmssl`. External OpenSSL, GmSSL, Tongsuo, and BoringSSL dependencies remain subject to the licenses of the versions actually used; this module's Apache-2.0 license does not replace those licenses.

# Statements

- This code repository contributes to the OpenSSL, Tongsuo, and BoringSSL open-source project solely for performance optimization. It strictly adheres to the coding style and methods, as well as security design of the native open-source software. Any vulnerability and security issues of the software shall be resolved by the corresponding upstream communities according to their response mechanisms. Please pay attention to the notifications and version updates released by the upstream communities. The Kunpeng computing community does not assume any responsibility for software vulnerabilities and security issues.
