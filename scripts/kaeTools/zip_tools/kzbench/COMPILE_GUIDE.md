# KAE压缩算法性能测试工具 (kzbench适配版)

## 简介

这是对lzbench的适配版本，专门用于测试KAE项目中的核心压缩算法性能。该工具仅保留了最常用的4种压缩算法，并通过动态库方式进行链接。

## 支持的压缩算法

- **zlib**: 经典的DEFLATE压缩算法
- **zstd**: Facebook开发的高性能压缩算法  
- **lz4**: 极快的压缩算法，注重速度
- **snappy**: Google开发的快速压缩算法
- **memcpy**: 基准测试用的内存拷贝

## 编译环境要求

### Linux系统依赖
```bash
# CentOS/RHEL/OpenEuler
sudo yum install gcc gcc-c++ zlib-devel zstd-devel lz4-devel snappy-devel




## 编译步骤

### 1. 检查依赖
```bash
# 检查编译器
gcc --version
g++ --version

# 检查库文件
pkg-config --exists zlib && echo "zlib: OK" || echo "zlib: MISSING"
pkg-config --exists libzstd && echo "zstd: OK" || echo "zstd: MISSING"
pkg-config --exists liblz4 && echo "lz4: OK" || echo "lz4: MISSING"
pkg-config --exists snappy && echo "snappy: OK" || echo "snappy: MISSING"
```

### 2. 编译
```bash
make clean
make
```

### 3. 验证
```bash
# 检查可执行文件
./lzbench -l
./lzbench --help
```

## 常见编译问题及解决方案

### 问题1: 找不到动态库
**错误信息**: `cannot find -lz` 或类似
**解决方案**:
```bash
# 查找库文件
find /usr -name "libz.so*" 2>/dev/null
find /usr -name "libzstd.so*" 2>/dev/null
find /usr -name "liblz4.so*" 2>/dev/null
find /usr -name "libsnappy.so*" 2>/dev/null

# 设置库路径
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

### 问题2: 头文件找不到
**错误信息**: `zlib.h: No such file or directory`
**解决方案**:
```bash
# 查找头文件
find /usr -name "zlib.h" 2>/dev/null
find /usr -name "zstd.h" 2>/dev/null
find /usr -name "lz4.h" 2>/dev/null
find /usr -name "snappy.h" 2>/dev/null

# 在Makefile中添加路径（如果需要）
make CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib"
```

### 问题4: C++标准问题
**错误信息**: `error: 'ZSTD_createCCtx' was not declared in this scope`
**解决方案**:
```bash
# 检查zstd版本
pkg-config --modversion libzstd

# 更新到较新版本
sudo apt-get install libzstd-dev
```

### 问题5: 权限问题
**错误信息**: `Permission denied`
**解决方案**:
```bash
chmod +x lzbench
sudo chown $USER:$USER lzbench
```

## 高级编译选项

### 调试版本
```bash
make BUILD_TYPE=debug
```

### 指定库路径
```bash
make LDFLAGS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib"
```


## 使用方法

### 基本用法
```bash
# 测试所有支持的算法
./lzbench testfile.txt

# 只测试zlib算法
./lzbench -ezlib testfile.txt

# 测试zstd的不同压缩级别
./lzbench -ezstd testfile.txt

# 比较lz4和snappy的性能
./lzbench -elz4/snappy testfile.txt

# 设置更长的测试时间
./lzbench -t5,10 -i3 testfile.txt
```

### 性能测试示例
```bash
# 创建测试文件
dd if=/dev/urandom of=test.dat bs=1M count=10

# 运行完整测试
./lzbench -t10,20 -i5 test.dat

# 输出CSV格式结果
./lzbench -o4 test.dat > results.csv
```

## 故障排除

### 运行时错误
1. **库找不到**: 设置`LD_LIBRARY_PATH`环境变量
2. **权限错误**: 检查文件权限和执行权限
3. **内存错误**: 减小测试文件大小或块大小

### 性能问题
1. **CPU频率**: 确保CPU处于高性能模式
2. **内存带宽**: 使用本地内存而非NUMA远程内存
3. **系统负载**: 在空闲系统上运行测试

## 集成到KAE项目

### 作为子模块使用
```bash
# 在KAE项目中添加
mkdir -p tools/performance
cp -r kzbench tools/performance/
cd tools/performance/kzbench
make
```

### 自动化测试脚本
```bash
#!/bin/bash
# kae_test.sh
for algo in zlib zstd lz4 snappy; do
    echo "Testing $algo..."
    ./lzbench -e$algo -t5,10 test_data.bin
done
```

## 注意事项

1. **系统兼容性**: 确保目标系统有相应的动态库
2. **版本一致性**: 不同版本的库可能有API差异
3. **性能基准**: 在相同硬件和系统配置下进行比较
4. **测试数据**: 使用代表性的测试数据

## 获取帮助

如果编译过程中遇到问题：
1. 检查系统日志：`dmesg | tail`
2. 查看编译输出详细信息：`make VERBOSE=1`
3. 确认库文件完整性：`ldd lzbench`
4. 检查环境变量：`env | grep -E "(LD_LIBRARY_PATH|PKG_CONFIG_PATH)"`