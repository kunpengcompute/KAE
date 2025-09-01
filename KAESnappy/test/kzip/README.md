
# 压缩性能测试小工具 kzip

## 构建
1、安装依赖
~~~
cd KAE
# 安装 frame 相关头文件
yum install lz4-devel
# 覆盖安装本次新增异步接口相关头文件
sh build.sh lz4
~~~
2、打包 kzip
~~~
# 在测试目录中
sh build.sh
~~~

## 测试

~~~
# 测试 alg/KAELz4/lz4.c
sh runPerf.sh -A kaelz4 -m 4

# 测试 alg/KAELz4/lz4Frame.c
sh runPerf.sh -A kaelz4_frame -m 12
~~~