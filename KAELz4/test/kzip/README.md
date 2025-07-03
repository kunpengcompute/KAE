
# 压缩性能测试小工具 kzip

## 安装
1、安装依赖
```
cd KAE
# 安装 frame 相关头文件
yum install lz4-devel
# 覆盖安装本次新增异步接口相关头文件
sh build.sh uadk
sh build.sh lz4
```
2、打包 kzip
```
# 在测试目录中
sh build.sh
```

## 参数说明
所有参数均可选

- -A 算法类型
```
kaelz4: 同步lz4 block格式压缩
kaelz4_frame: 同步lz4 frame格式压缩
kaelz4async_block: 异步lz4 block格式压缩
kaelz4async_frame: 异步lz4 frame格式压缩
```
- -d 处理压缩任务或解压任务
default:null 默认压缩任务。

- -m 并发进程数量
使用fork()复制进程进行测试，默认2，一共创建2个进程。异步测试时推荐并发1。

- -t 并发线程数量
默认1，不使用pthread_create()创建更多子线程。大于1时-m参数失效。

- -i 客户端流量控制，inflight num。
异步压缩时，同一时间依次下发压缩任务的数量。默认256，最大1024。

- -g 是否展示时延数据
默认1展示。

- -f 待处理的文件路径
需要是存在的文件，将读取文件的内容进行压缩

- -o 处理的结果
如果存在，则将压缩或解压的结果保存到该路径

- -s 输入分片大小
对输入数据的分片处理。单位KB。默认0不分片。解压时无效

- -n 测试循环次数
默认1000

- -P 大页配置
是否使用大页存储待压缩数据。默认0不使用

- -p poll模式配置
是否开启poll模式进行压缩。默认0不开启。

- -r crc32校验处理
是否携带crc32校验值。默认0 不携带。


## 使用限制
1、异步接口硬件环境限制：kunpeng 920 7280z
2、最大性能测试时需要开启fast，详见《KAELz4 异步压缩接口用户使用指南》
3、KAE 加速器与 NUMA 节点存在绑定关系。将进程绑定至特定 NUMA 节点后，该进程即可使用该节点对应的 KAE 硬件加速器。
4、SGL模式下不支持切软算。
5、kzip工具通过使用大页内存获取真实的物理地址，测试SGL模式的时候，要先申请大页内存。可参考如下命令：
```
sysctl vm.nr_hugepages=10000
```

## 测试命令

```shell
# 不同数据集下接口功能测试
sh runFunc.sh
```

polling模式接口测试：
```shell
# 1、单IO时延数据：等价串行流程，结果表示单个IO的压缩时延。
sh runPerf.sh -A kaelz4async_frame -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 1 -p 1 -f [path to calgary.tar] 
# 2、单核压缩能力：单线程加压，结果表示单线程能提供的压缩带宽与时延。
sh runPerf.sh -A kaelz4async_frame -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 4 -p 1 -f [path to calgary.tar]
```

通用线程池模式接口测试：
```shell
# 1、单IO时延测试：等价串行流程，结果表示单个IO的压缩时延。
export KAE_LZ4_ASYNC_THREAD_NUM=1
sh runPerf.sh -A kaelz4async_frame -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 1 -p 0 -f [path to calgary.tar] 

# 2、单核压缩能力测试：单线程加压，结果表示单线程能够提供的压缩带宽与时延。
export KAE_LZ4_ASYNC_THREAD_NUM=1
sh runPerf.sh -A kaelz4async_frame -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 4 -p 0 -f [path to calgary.tar]

# 3、单KAE能力：多线程加压，结果表示满足5G@4K的压缩带宽前提的时延。
export KAE_LZ4_ASYNC_THREAD_NUM=5 # 可选5或6
sh runPerf.sh -A kaelz4async_frame -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 16 -p 0 -f [path to calgary.tar]

#4、单KAE最大能力：多线程满压，结果表示单KAE能够提供的最大压缩带宽。
export KAE_LZ4_ASYNC_THREAD_NUM=8
sh runPerf.sh -A kaelz4async_frame -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 64 -p 0 -f [path to calgary.tar]
```

```
# 单一场景接口组合使用demo测试
export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:$LD_LIBRARY_PATH
./kzip -T 1
```