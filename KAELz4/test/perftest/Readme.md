## 本目录用于KAELz4单P带宽能力测试和基于lzbench工具的性能测试

### 1. 单p带宽测试
step1: 执行下列命令
```
export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib/:$LD_LIBRARY_PATH
```

step2: 在本目录执行make，即可得到kaelz4_perf可执行文件，根据提示输入参数可测试单P下KAELz4带宽上限

### 2. lzbench工具性能测试

step1: 从[Gitee仓](https://gitee.com/kunpeng_compute/lzbench)获取Kunpeng-lzbench测试工具源码，进入源码路径执行`make`，编译得到二进制工具，根据指定测试命令即可测试KAELz4性能

step2: 测试block模式性能
```
numactl -C 1 ./lzbench -relz4 -b128 -i1 -j -m1024 /数据集目录
```

step3: 测试frame模式性能
```
numactl -C 1 ./lzbench -relz4frame -b128 -i1 -j -m1024 /数据集目录
```

注：执行上述性能测试前，请确保kaelz4已安装完成