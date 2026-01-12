Introduction
-------------------------

lzbench is an in-memory benchmark of open-source LZ77/LZSS/LZMA compressors. It joins all compressors into a single exe. 
At the beginning an input file is read to memory. 
Then all compressors are used to compress and decompress the file and decompressed file is verified. 
This approach has a big advantage of using the same compiler with the same optimizations for all compressors. 
The disadvantage is that it requires source code of each compressor (therefore Slug or lzturbo are not included).
kzbench is a modified version based on lzbench. It only trims the compression algorithms related to KAE and is modified to be called by relying on dynamic libraries.

|Status   |
|---------|
| [![Build Status][travisMasterBadge]][travisLink] [![Build status][AppveyorMasterBadge]][AppveyorLink]  |

[travisMasterBadge]: https://travis-ci.org/inikep/lzbench.svg?branch=master "Continuous Integration test suite"
[travisLink]: https://travis-ci.org/inikep/lzbench
[AppveyorMasterBadge]: https://ci.appveyor.com/api/projects/status/u7kjj8ino4gww40v/branch/master?svg=true "Visual test suite"
[AppveyorLink]: https://ci.appveyor.com/project/inikep/lzbench


Usage
-------------------------

```
usage: lzbench [options] input [input2] [input3]

where [input] is a file or a directory and [options] are:
 -b#   set block/chunk size to # KB (default = MIN(filesize,1747626 KB))
 -c#   sort results by column # (1=algname, 2=ctime, 3=dtime, 4=comprsize)
 -e#   #=compressors separated by '/' with parameters specified after ',' (deflt=fast)
 -iX,Y set min. number of compression and decompression iterations (default = 1, 1)
 -j    join files in memory but compress them independently (for many small files)
 -l    list of available compressors and aliases
 -m#   set memory limit to # MB (default = no limit)
 -o#   output text format 1=Markdown, 2=text, 3=text+origSize, 4=CSV (default = 2)
 -p#   print time for all iterations: 1=fastest 2=average 3=median (default = 1)
 -r    operate recursively on directories
 -s#   use only compressors with compression speed over # MB (default = 0 MB)
 -tX,Y set min. time in seconds for compression and decompression (default = 1, 2)
 -v    disable progress information
 -x    disable real-time process priority
 -z    show (de)compression times instead of speed

Example usage:
  lzbench -ezstd filename = selects all levels of zstd
  lzbench -ebrotli,2,5/zstd filename = selects levels 2 & 5 of brotli and zstd
  lzbench -t3 -u5 fname = 3 sec compression and 5 sec decompression loops
  lzbench -t0 -u0 -i3 -j5 -ezstd fname = 3 compression and 5 decompression iter.
  lzbench -t0u0i3j5 -ezstd fname = the same as above with aggregated parameters
```

lzbench was tested with:
- Ubuntu: gcc 4.8 (both 32-bit and 64-bit), 4.9, 5 (32-bit and 64-bit), 6 (32-bit and 64-bit), 7, 8, 9 and clang 3.5, 3.6, 3.8, 3.9, 4.0, 5.0, 6.0, 7, 8, 9
- MacOS: Apple LLVM version 9.1.0
- MinGW (Windows): gcc 5.3 (32-bit), gcc 6.2 (both 32-bit and 64-bit), gcc 9.1



Supported compressors
-------------------------
**Warning**: some of the compressors listed here have security issues and/or are 
no longer maintained.  For information about the security of the various compressors, 
see the [CompFuzz Results](https://github.com/nemequ/compfuzz/wiki/Results) page.

 - [lz4/lz4hc v1.9.3](https://github.com/lz4/lz4)
 - [lzlib 1.12-rc2](http://www.nongnu.org/lzip)
 - [snappy 2020-07-11 (4dd277f)](https://github.com/google/snappy)
 - [zlib 1.2.11](http://zlib.net)
 - [zstd 1.5.5](https://github.com/facebook/zstd)

QAT support
-------------------------

If QAT is available, lzbench supports additional compressors:
  - [qatzip](https://github.com/intel/QATzip) - QAT default compressor, using defalte algorithm
  - [qatlz4](https://github.com/intel/QATzip) - QAT compressor, using lz4 algorithm
  - [qatgzip](https://github.com/intel/QATzip) - similar to the reference `qatzip` benchmark, using GPU memory
  - [qatzstd](https://github.com/intel/QAT-ZSTD-Plugin) ZSTD compressor, using QAT hardware

The QAT compiler is available which can be passed to `make` via the `ENABLE_QAT` variable, *e.g.*:
```
make ENABLE_QAT=1
```

Benchmarks
-------------------------

The following results are obtained with `lzbench 1.8` with the `-t16,16 -eall` options using 1 core of Intel Core i7-8700K, Ubuntu 18.04.3 64-bit, and clang 9.0.1
with "silesia.tar" which contains tarred files from [Silesia compression corpus](http://sun.aei.polsl.pl/~sdeor/index.php?page=silesia).
The results sorted by ratio are available [here](lzbench18_sorted.md).

| Compressor name         | Compress.  |Decompress. | Compr. size | Ratio |
| ---------------         | -----------| -----------| ----------- | ----- |
| memcpy                  | 10362 MB/s | 10790 MB/s |   211947520 |100.00 |
| lz4 1.9.2               |   737 MB/s |  4448 MB/s |   100880800 | 47.60 |
| lz4fast 1.9.2 -3        |   838 MB/s |  4423 MB/s |   107066190 | 50.52 |
| lz4fast 1.9.2 -17       |  1201 MB/s |  4632 MB/s |   131732802 | 62.15 |
| lz4hc 1.9.2 -1          |   131 MB/s |  4071 MB/s |    83803769 | 39.54 |
| lz4hc 1.9.2 -4          |    81 MB/s |  4210 MB/s |    79807909 | 37.65 |
| lz4hc 1.9.2 -9          |    33 MB/s |  4378 MB/s |    77884448 | 36.75 |
| lz4hc 1.9.2 -12         |    11 MB/s |  4427 MB/s |    77262620 | 36.45 |
| lzlib 1.11 -0           |    36 MB/s |    61 MB/s |    63847386 | 30.12 |
| lzlib 1.11 -3           |  6.81 MB/s |    69 MB/s |    56320674 | 26.57 |
| lzlib 1.11 -6           |  2.82 MB/s |    74 MB/s |    49777495 | 23.49 |
| lzlib 1.11 -9           |  1.82 MB/s |    76 MB/s |    48296889 | 22.79 |
| zlib 1.2.11 -1          |   119 MB/s |   383 MB/s |    77259029 | 36.45 |
| zlib 1.2.11 -6          |    35 MB/s |   407 MB/s |    68228431 | 32.19 |
| zlib 1.2.11 -9          |    14 MB/s |   404 MB/s |    67644548 | 31.92 |
| zstd 1.4.3 -1           |   480 MB/s |  1203 MB/s |    73508823 | 34.68 |
| zstd 1.4.3 -2           |   356 MB/s |  1067 MB/s |    69594511 | 32.84 |
| zstd 1.4.3 -5           |   104 MB/s |   932 MB/s |    63993747 | 30.19 |
| zstd 1.4.3 -8           |    46 MB/s |  1055 MB/s |    60757793 | 28.67 |
| zstd 1.4.3 -11          |    20 MB/s |  1001 MB/s |    59239357 | 27.95 |
| zstd 1.4.3 -15          |  7.12 MB/s |  1024 MB/s |    57167422 | 26.97 |
| zstd 1.4.3 -18          |  3.58 MB/s |   912 MB/s |    53690572 | 25.33 |
| zstd 1.4.3 -22          |  2.28 MB/s |   865 MB/s |    52738312 | 24.88 |

