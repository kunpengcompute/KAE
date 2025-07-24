
# KAELz4 异步压缩接口用户使用指南
## 一、接口概述

在现代计算环境中，数据压缩常常是提升数据传输效率、存储空间节省的关键手段。然而，传统的压缩方法通常是同步执行，导致在处理大规模数据时可能造成性能瓶颈，特别是在高负载的场景下。为了更好地利用硬件加速器的能力并提高系统的响应能力，我们开发了异步LZ4压缩接口。

该异步接口专为处理高并发、大数据量压缩场景设计。通过引入并发线程处理数据压缩，它能够充分发挥现代多核CPU的并行计算能力，并在硬件加速器KAE的支持下，进一步提升压缩速度。

### 接口特点：

* ​**异步压缩**​：在压缩过程中不阻塞主线程，可以通过回调函数在压缩完成后获得处理结果。
* ​**硬件加速支持**​：通过硬件加速器对压缩过程加速，该接口能够显著提升压缩任务的执行效率，同时降低CPU负载。
* ​**多线程并发处理**​：内部实现采用多线程并发处理，多线程智能调度均衡分发任务，进一步提升整体性能。同时在双加速器硬件环境中，支持自动均匀绑核，将压力平分到2个加速器上，实现资源利用最大化。
* ​**兼容社区LZ4格式**​：该接口生成的压缩数据格式与社区LZ4格式兼容。
* ​**轻松集成**​：该接口可以轻松集成到现有的应用程序中，用户只需调用接口并提供回调函数，便可以快速启动异步压缩，轻松实现高性能数据压缩。

### 使用场景：

* ​**高并发和高负载环境**​：当需要处理大量并发数据压缩任务时，该接口能够通过多线程并发执行来有效避免单一线程阻塞，提升系统响应速度。
* ​**低延迟需求场景**​：在需要低延迟和快速响应的系统中，该接口可以通过不阻塞主线程来保证系统的流畅性。例如，在实时数据传输、分布式存储或流媒体处理等场景中，该接口能有效避免数据压缩过程中的卡顿现象。

## 二、背景依赖和安装编译说明

该接口属于KAE2.0的KAELz4压缩的一部分，硬件环境和操作系统限制见KAE安装前准备章节。

使用该接口需要正确安装KAE2.0，推荐使用源码安装方式安装最新版本KAE，过程详见：[https://www.hikunpeng.com/document/detail/zh/kunpengaccel/compress/devg-kaezip/kunpengaccel\_kaezip\_0029.html](https://www.hikunpeng.com/document/detail/zh/kunpengaccel/compress/devg-kaezip/kunpengaccel_kaezip_0029.html)

* 硬件限制：
  CPU：限制为 Kunpeng 920 7280Z
* 注意事项：
  KAELz4依赖原生的Lz4头文件，确保相关开发套件的安装。安装命令如下：

```
yum install -y make kernel-devel libtool numactl-devel openssl-devel lz4-devel libzstd-devel chrpath
```

## 三、接口函数签名和参数说明

### 回调数据结构体

```c
struct kaelz4_result {
    int status; # 压缩任务状态。详细说明见第四节-错误码说明
    unsigned int flag; # 保留字段
    void *user_data; # 用户调用异步接口时传入的自定义数据指针
    size_t src_size; # 压缩任务原始数据总大小
    size_t dst_len; # 传入时表示目标buffer的大小，要求大于compressBound(srcLen)，回调时表示压缩后大小
    uint32_t *ibuf_crc; # 存放输入数据CRC32校验的指针。如果存在，将对输入数据计算CRC32校验
    uint32_t *obuf_crc; # 存放压缩数据CRC32校验的指针。如果存在，将对压缩后的数据计算CRC32校验
};
```

### 用户回调函数

```c
// 压缩任务完成后，将调用该回调函数。回调压缩的结果
typedef void (*lz4_async_callback)(struct kaelz4_result *result);
```


### 异步压缩初始化

```c
/*! LZ4_async_compress_init() :
*  Register software compress function, initialize Task Queues and Threads on the KAE Side.
*  If not being called before, LZ4_compress_async will not handle any exceptions and simply return failure.
*  Note: Can not be called before fork();
*/
 void LZ4_async_compress_init(void);
```

### block 异步压缩

```c
/**
 * @brief: block compress async api
 * @param: src [IN] : input data
 * @param: dst [OUT] : output data
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*lz4_async_callback)(struct kaelz4_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @return: 0 success, other fail
 * /
int LZ4_compress_async(const void *src, void *dst, lz4_async_callback callback, struct kaelz4_result *result);
```

### frame 异步压缩

```c
/**
 * @brief: fream compress async api
 * @param: src [IN] : input data
 * @param: dst [OUT] : output data
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*lz4_async_callback)(struct kaelz4_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @param: preferences_ptr [IN] : compress preferences. NULL is avaliable. if not NULL  preferences_ptr  should be struct LZ4F_preferences_t data.
 * @return: 0 success, other fail
 * /
int LZ4F_compressFrame_async(const void *src, void *dst, lz4_async_callback callback, struct kaelz4_result *result, const void *preferences_ptr);
​
```

### 异步压缩结束

```c
/*! LZ4_teardown_async_compress() :
 *  Destroy all Task Queues and Threads on the KAE Side.
 */
LZ4LIB_API void LZ4_teardown_async_compress(void);
```

## 四、异常说明

### 错误码枚举:

```c
#define KAE_LZ4_INVAL_PARA 1 # 内部通用错误 
#define KAE_LZ4_INIT_FAIL 2 # 初始化资源失败 
#define KAE_LZ4_COMP_FAIL 3 # 压缩失败 
#define KAE_LZ4_RELEASE_FAIL 4 # 资源释放失败 
#define KAE_LZ4_ALLOC_FAIL 5 # 内存资源申请失败 
#define KAE_LZ4_SET_FAIL 6 # 内部错误
#define KAE_LZ4_HW_TIMEOUT_FAIL 7 # 硬件超时
```

### 切软算场景：

限制：用户调用压缩接口时输入数据必须小于64k时才支持切软算
- 1、支持在KAE驱动异常时自动切软算
- 2、支持在KAE硬件资源耗尽时自动切软算

## 五、使用示例和kzip工具说明

### 使用示例

以 frame 接口示例：
1、对某一段内存进行压缩，同时设置特定的frame格式。
2、在收到回调后，使用开源frame解压接口对压缩内容进行解压。
3、最后比较解压后的内容是否是原始内容。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <lz4.h>
#include <lz4frame.h>
#include <unistd.h>
#include <sys/stat.h>

int g_has_done = 0; // 异步回调是否完成。需要初始化为0。

// 用户自定义数据记录
struct my_custom_data {
    void *src;
    void *dst;
    void *src_decompd;
    size_t src_len;
    size_t dst_len;
    size_t src_decompd_len;
};

// 随机生成256KB的数据
static void generate_random_data(void *data, size_t size) {
    unsigned char *bytes = (unsigned char *)data;
    for (size_t i = 0; i < size; i++) {
        bytes[i] = rand() % 10; 
    }
}


void compression_callback(struct kaelz4_result *result) {
    if (result->status != 0) {
        printf("Compression failed with status: %d\n", result->status);
        return;
    }

    // 在回调中获取压缩后的数据
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;
    void *compressed_data = my_data->dst;
    size_t compressed_size = result->dst_len;

    my_data->dst_len = compressed_size;

    // 使用LZ4解压缩数据
    size_t tmp_src_len = result->src_size * 10;
    // 为解压数据分配内存
    void *dst_buffer = malloc(tmp_src_len);
    if (!dst_buffer) {
        printf("Memory allocation failed for decompressed data.\n");
        return;
    }

    LZ4F_decompressionContext_t dctx;
    LZ4F_createDecompressionContext(&amp;dctx, 100);
    int ret = LZ4F_decompress(dctx, dst_buffer, &amp;tmp_src_len,
                                            compressed_data, &amp;compressed_size, NULL);
    if (ret < 0) {
        printf("Decompression failed with error code: %d\n", ret);
        free(dst_buffer);
        return;
    }
    my_data->src_decompd = dst_buffer;
    my_data->src_decompd_len = tmp_src_len;

    if (my_data->src_decompd_len != my_data->src_len) {
        printf("Test Error: 解压后与原始长度不一样. result->src_size=%ld   原始长度=%ld   压缩后解压长度=%ld \n",
            result->src_size,
            my_data->src_len,
            my_data->src_decompd_len);
    }

    // 比较解压后的数据和原始数据
    if (memcmp(my_data->src_decompd, my_data->src, result->src_size) == 0) {
        printf("Test Success.\n");
    } else {
        printf("Test Error:Decompressed data does not match the original data.\n");
    }

    // 释放解压后的数据
    free(dst_buffer);
    g_has_done = 1;
}

static int test_async_frame_with_perferences(int contentChecksumFlag, int blockChecksumFlag, int contentSizeFlag)
{
    g_has_done = 0;
    size_t src_len = 258 * 1024;  // 256KB
    void *inbuf = malloc(src_len);
    if (!inbuf) {
        printf("Memory allocation failed for input data.\n");
        return -1;
    }
    // 生成随机数据
    generate_random_data(inbuf, src_len);

    // 为压缩数据分配内存
    size_t compressed_size = LZ4F_compressBound(src_len, NULL);
    void *compressed_data = malloc(compressed_size);
    if (!compressed_data) {
        printf("Memory allocation failed for compressed data.\n");
        free(inbuf);
        return -1;
    }

    // 初始化LZ4F压缩的参数
    LZ4F_preferences_t preferences = {0};
    preferences.frameInfo.blockSizeID = LZ4F_max64KB;  // 设定块大小
    if (contentChecksumFlag) {
        preferences.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
    }
    if (blockChecksumFlag) {
        preferences.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
    }
    if (contentSizeFlag) {
        preferences.frameInfo.contentSize = src_len;
    }

    // 异步压缩参数
    struct kaelz4_result result = {0};
    struct my_custom_data mydata = {0};
    mydata.src = inbuf;
    mydata.src_len = src_len;
    mydata.dst = compressed_data;
    result.user_data = &amp;mydata;
    result.src_size = src_len;
    result.dst_len = compressed_size;
    LZ4_async_compress_init();
    int compression_status = LZ4F_compressFrame_async(inbuf, compressed_data,
                                                      compression_callback, &amp;result, &amp;preferences);

    if (compression_status != 0) {
        printf("Compression failed with error code: %d\n", compression_status);
        free(inbuf);
        free(compressed_data);
        return -1;
    }

    while (g_has_done != 1) {
        usleep(100);
    }
    LZ4_teardown_async_compress();

    return compression_status;
}

int main()
{
    return test_async_frame_with_perferences(1, 1, 1);
}

```

```shell
gcc main.c -I/usr/local/kaelz4/include -L/usr/local/kaelz4/lib -llz4 -o kaelz4_frame_async
./kaelz4_frame_async # 输出 Test Success.
```

### kzip工具说明

#### 前置环境设置

- 开启驱动fast模式
  
  ~~~
  rmmod hisi_zip # 删除驱动，这一步执行后，watch命令就看不到那一组256了
  
  #注意是uacc_mode=2,因为是nosva模式；这一步执行后，watch会看到4个256，表示使能正确
  modprobe hisi_zip perf_mode=1 uacce_mode=2 pf_q_num=256
  ~~~
- 设置fast模式下特定有效压缩窗长

    ```
    export KAE_LZ4_WINTYPE=8
    export KAE_LZ4_COMP_TYPE=8
    ```

### 使用步骤

进入kzip工具目录

~~~shell
# 编译打包kzip工具
sh build.sh
~~~

~~~shell
# 查看工具参数说明 export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:$LD_LIBRARY_PATH
./kzip -h
~~~

~~~shell
# 基本功能测试：测试不同数据集下，不同压缩算法，不同分片大小时的压缩解压测试。
sh runFunc.sh
~~~

~~~shell
# frame 异步压缩接口对8k分片数据的性能测试
sh runPerf.sh -A kaelz4async_frame -m 1 -n 12000 -s 8
~~~

~~~shell
# block 异步压缩接口 对8k分片数据的性能测试
sh runPerf.sh -A kaelz4async_block -m 1 -n 12000 -s 8
~~~

## 六、性能优化

* KAE并发线程数量调整：不同的并发线程数会影响压缩处理效率，过多的线程数将消耗更多的KAE队列资源。用户单个压缩进程使用12个并发，能达到较好带宽性能。

    ~~~shell
    # KAE_LZ4_ASYNC_THREAD_NUM: KAE侧单个进程并发启动的线程数量。 
    # 默认启动12个线程去并发处理压缩任务，最大32个 
    export KAE_LZ4_ASYNC_THREAD_NUM=12
    ~~~

* 绑核说明：
  * 可以使用 taskset 或 numactl 对压缩进程进行绑核，可以限制对硬件加速器的使用。
  * 一般至少需要绑定 KAE\_LZ4\_ASYNC\_THREAD\_NUM 个 CPU供KAE侧压缩使用。考虑用户侧逻辑，需要至少绑定 KAE\_LZ4\_ASYNC\_THREAD\_NUM+1 个CPU核心
  * 默认情况下，KAE并发的线程会自动选择进程所处NUMA以及临近NUMA上的硬件加速器以达到最大带宽。
  * 如果只想使用1个加速器，可以将压缩进程仅绑定到单一NUMA的cpu核心上
  * 开启了超线程的机器，一般连续的2个cpu核心是同一个物理。需要间隔绑核或绑定更多的CPU核心数量以达到最大带宽。


## 七、常见问题解答 (FAQ)

### 1、kzip工具支持多进程并发吗

支持的。
目前kzip工具在同步的 lz4 block/frame 接口测试中，需要使用 -m 参数指定进程并发数量进行压测。
在异步的lz4 block/frame 接口测试中，目前单进程下即可打满带宽，多进程并不会带来更多收益。
如果要模拟多进程异步压缩场景，可以使用工具的 -i 参数，`inflight_num` ，最小为1，最大1024，表示当前进程同时进行中的KAE异步压缩接口的任务数量（目前的kzip工具策略：超过该值后，必须要等到前面的压缩任务完成，回调函数完成后，才可以调用接口执行新的压缩任务），相当于用户侧压缩流量控制。目前默认256，是比较高的压缩流量。


# 声明
- 此代码仓计划参与Lz4软件开源，仅作Lz4功能扩展或性能提升，编码风格遵照原生开源软件，继承原生开源软件安全设计，不破坏原生开源软件设计及编码风格和方式，软件的任何漏洞与安全问题，均由相应的上游社区根据其漏洞和安全响应机制解决。请密切关注上游社区发布的通知和版本更新。鲲鹏计算社区对软件的漏洞及安全问题不承担任何责任。