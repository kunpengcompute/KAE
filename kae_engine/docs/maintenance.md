
# Contributor's Guide

## Getting Started

Clone UADK from [Github](https://github.com/Linaro/uadk).

Clone uadk_engine from [Github](https://github.com/Linaro/uadk_engine).

## License

Adopt Apache License 2.0.

## Coding Style

Adopt linux kernel coding style, so check with linux/scripts/checkpatch.pl

## Making Changes

```
Make patches
linux/scripts/checkpatch.pl *.patch
sudo test/sanity_test.sh
```

## Release
Likely two releases each year in May and November.\
Tag {x}.{y} is for release, while .{z} is for the major bug fixes.\
In the meantime, ReleaseNotes is required to describe release contents.\
ReleasesNotes:\
Features:\
Fixes:

## Main maintainers

```
Zhangfei Gao <zhangfei.gao@linaro.org>
Zhou Wang <wangzhou1@hisilicon.com>
Zhiqi Song <songzhiqi1@huawei.com>
```
