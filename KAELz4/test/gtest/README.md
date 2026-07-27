# KAELz4 GTest说明

## 开源LZ4功能测试

KAELz4功能测试复用开源LZ4测试功能实现。

具体方式：先完成KAELz4安装，然后进入`KAELz4/open_source/lz4-1.9.4/tests`目录执行`make`。

1. block模式功能测试：通过生成的`fuzzer`，以及脚本`test_custom_blocksizes.sh`验证。
2. frame模式功能测试：通过生成的`frametest`，以及脚本`test-lz4-list.py`验证。

执行上述功能测试前，请确保KAELz4已安装完成。

## GTest单元测试

普通构建和运行：

```sh
sh run.sh
```

也可以手动构建：

```sh
sh build.sh
./kaelz4test
```

首次构建会自动下载并编译GoogleTest 1.11.0。脚本优先使用GoogleTest官方
GitHub release，官方地址不可达时会切换到Gitee镜像。也可以通过
`GTEST_DOWNLOAD_URL`指定其他可信下载地址。

## Polling异步零拷贝与非零拷贝测试

`src/async_polling_case.cpp`覆盖KAELz4 polling异步压缩接口，包括零拷贝和非零拷贝两条路径。零拷贝用例使用hugetlb大页内存，并通过`/proc/self/pagemap`把虚拟地址转换为物理地址。

在需要强制验证零拷贝的环境中，建议设置`KAELZ4_REQUIRE_HUGEPAGE=1`。设置后，如果大页申请或PFN读取不可用，零拷贝用例会直接失败；不设置时，零拷贝环境不可用会跳过相关用例。

申请1GB大页：

```sh
echo 10 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
```

如果平台只支持512MB大页，可改用：

```sh
echo 10 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-524288kB/nr_hugepages
```

运行polling异步完整GTest：

```sh
sudo env LD_LIBRARY_PATH=/usr/local/kaelz4/lib:/usr/local/lib \
  KAE_LZ4_WINTYPE=8 \
  KAE_LZ4_COMP_TYPE=8 \
  KAELZ4_REQUIRE_HUGEPAGE=1 \
  ./kaelz4test
```

只运行polling异步用例：

```sh
sudo env LD_LIBRARY_PATH=/usr/local/kaelz4/lib:/usr/local/lib \
  KAE_LZ4_WINTYPE=8 \
  KAE_LZ4_COMP_TYPE=8 \
  KAELZ4_REQUIRE_HUGEPAGE=1 \
  ./kaelz4test --gtest_filter=KAELz4AsyncPolling.*
```
