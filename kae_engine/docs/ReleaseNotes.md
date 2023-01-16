
# UADK engine Release v1.1 December 2022

## New Features

- UADK engine consists of five sub-modules: RSA, DH, ECC, Cipher, and Digest.\
  After hardware accelerators from different vendors are registered to UADK general framework,\
  users can use the OpenSSL command line tools or OpenSSL standard interfaces through UADK engine,\
  and finish the computing task with the hardware accelerators.\
  The engine ID is 'uadk_engine'.

- The main features of UADK engine are as follows:
- RSA sub-module.\
  Supports RSA algorithm of 1024/2048/3072/4096-bits key size with standard mode and CRT mode.\
  Provides key generation, asymmetric encryption and decryption, and digital signature functions.
- DH sub-module.\
  Supports DH algorithms of 768/1024/1536/2048/3072/4096-bits key size.\
  Provides key exchange functions.
- ECC sub-module.\
  Supports elliptic-curve cryptography.\
  Provide ECDH/X25519/X448 key exchange, ECDSA elliptic curve digital signature,\
  SM2 digital signature and SM2 asymmetric encryption and decryption functions.
- Cipher sub-module.\
  Supports block cipher algorithms, including AES algorithm with CBC/ECB/CTR/XTS mode,\
  SM4 algorithm with CTR/CBC/ECB/OFB/CFB mode, and 3DES algorithm.\
  Provides symmetric encryption and decryption functions.
- Digest sub-module.\
  Supports MD5/SM3/SHA1/SHA224/SHA256/SHA384/SHA512 algorithms.\
  Provides generating message digest functions and supports digest multiple updates.\
- Supports switching to OpenSSL software method in abnormal cases.
- Supports configuring the engine with an environment variable.

## Fixes

- Fixed uadk engine compatibility problem when using a different mode of UADK.
- Fixed the init status of SM2 and decryption check.
- Fixed the init operation sequence of ECC-related algorithms.
- Improved the digest performance by about 5%.
- Added timeout protection mechanism when doing an asynchronous job.
- Fixed the repeatedly initializing problem, initializing resources only once.

## Working combination

- UADK v2.4
- OpenSSL 1.1.1f
