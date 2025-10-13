# KAEZip 压缩接口用户使用指南
- [同步接口](#同步压缩接口)
- [异步接口](#异步压缩接口)

## 同步接口
### 接口介绍
KAEZip同步压缩/解压接口依赖于社区zlib的标准使用方式。在程序执行期间，只需指定libz.so的位置为KAEZip安装所在的目录即可使能KAE加速效果。数据同时支持zlib、gzip、deflate_raw格式。
```shell
export LD_LIBRARY_PATH=/usr/local/kaezip/lib:$LD_LIBRARY_PATH
```
### 接口使用demo
直接编写标准zlib压缩代码即可，可参考测试文件： ```KAEZlib/test/perftest/kaezip_perf.c```

## 异步接口

### API概述
本节介绍了KAEZip提供的异步压缩API、异步解压API，包括适用于高性能场景的核心功能，如会话管理、任务提交和任务轮询。

| 接口                                | 简介                     |
|---------------------------------------|--------------------------|
| `KAEZIP_get_devices`| 获取当前ZIP加速器设备信息 |
| `KAEZIP_create_async_compress_session`| 创建异步压缩任务session       |
| `KAEZIP_compress_async_in_session`        | 提交异步压缩任务        |
| `KAEZIP_async_polling_in_session`          | polling查询异步压缩/解压任务的结果        |
| `KAEZIP_destroy_async_compress_session` | 销毁压缩任务session     |
| `KAEZIP_create_async_decompress_session`| 创建异步解压任务session        |
| `KAEZIP_decompress_async_in_session`        | 提交异步解压任务        |
| `KAEZIP_destroy_async_decompress_session` | 销毁解压任务session     |
| `KAEZIP_reset_session` | 重置任务session     |

### API注意事项
- 约束硬件规格为 Kunpeng 920 7280Z
- 当前异步接口仅支持输出 deflate_raw 格式数据
- 约束每个session只能在同一个线程中使用，所有API接口不保证多线程安全，即不能在多个线程中，调用API接口传入相同的session，否则不保证压缩解压功能正常。不同session之间的资源互斥，建议不同线程创建并使用各自独立的session。

### API详细说明

```c
/**
 * @brief: retrieve the list of available ZIP accelerator devices.
 * @param: num [out] : pointer to store the number of devices.
 * @return: pointer to an array of device descriptors, NULL if no KAE device.
 */
const struct zip_dev *KAEZIP_get_devices(unsigned int *num);

/**
 * @brief: Initialize Task Queues and Threads on the KAE Side.
 * @param: usr_map : function to translate src/dst buf's VA to PA/IOVA
 * @param: config : pointer to device configuration structure used to select KAE device
 * @return: session, NULL if fail
 */
void *KAEZIP_create_async_compress_session(iova_map_fn usr_map, const device_config_t *config);

/**
 * @brief: compress async api
 * @param: sess : session
 * @param: src [IN] : input data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: dst [OUT] : output data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*kaezip_async_callback)(struct kaezip_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaezip_result.
 * @return: 0 success, other fail
 */
int KAEZIP_compress_async_in_session(void *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                     kaezip_async_callback callback, struct kaezip_result *result);

/**
 * @brief: Polling hardware result in session.
 * @param: sess : session
 * @param: budget : process packet num per call.
 */
 void KAEZIP_async_polling_in_session(void *sess, int budget);

/**
 * @brief: Destroy session and hardware ctx.
 * @param: sess : session
 */
void KAEZIP_destroy_async_compress_session(void *sess);

/**
 * @brief: Initialize Task Queues and Threads on the KAE Side for decompress.
 * @param: usr_map : function to translate src/dst buf's VA to PA/IOVA
 * @param: config : pointer to device configuration structure used to select KAE device
 * @return: session, NULL if fail
 */
void *KAEZIP_create_async_decompress_session(iova_map_fn usr_map, const device_config_t *config);

/**
 * @brief: decompress async api
 * @param: sess : session
 * @param: src [IN] : input data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: dst [OUT] : output data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*kaezip_async_callback)(struct kaezip_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaezip_result.
 * @return: 0 success, other fail
 */
int KAEZIP_decompress_async_in_session(void *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                       kaezip_async_callback callback, struct kaezip_result *result);

/**
 * @brief: Destroy decompress session and hardware ctx.
 * @param: sess : session
 */
void KAEZIP_destroy_async_decompress_session(void *sess);

/**
 * @brief: reset session and hardware ctx, all compress tasks will be canceled.
 * @param: sess : session
 */
void KAEZIP_reset_session(void *sess);
```

### 指定加速器设备
KAEZip提供了查询接口用于查询当前ZIP加速器设备的相关信息，同时异步压缩解压接口支持由用户自行选择所需要使用的加速器设备。加速器设备信息的结构体定义如下：
```c
struct zip_dev {
	int numa_id;                  // 所属 NUMA 节点
	char dev_name[256];           // hisi_zip-*
    char dev_root[MAX_STR_SIZE];  // /sys/class/uacce/hizi_zip-*
    unsigned int hw_id;           // 硬件 ID ( - 后面的数字，如 hisi_zip-8)
    unsigned int dev_id;          // 逻辑 ID ( 0,1,2...)
};
```
当前支持3种设备指定策略：
1. 默认策略，根据NUMA亲和性自动选择加速器设备
2. 指定NUMA，使用该NUMA上的ZIP加速器设备
3. 指定设备，使用指定的ZIP加速器设备

具体用法demo如下：
```c
#include "kaezip.h"

int main()
{
    unsigned int num = 0;
    const struct zip_dev *devs = KAEZIP_get_devices(&num);

    if (devs == NULL) {
        return -1; // No KAE device
    }

    // 根据NUMA亲和性自动选择加速器设备
    device_config_t conf_auto = KAE_CONFIG_AUTO();
    // 指定第一个加速器设备
    device_config_t conf_dev  = KAE_CONFIG_BY_DEV(&devs[0]);
    // 指定使用NUMA-0上的加速器设备
    device_config_t conf_numa = KAE_CONFIG_BY_NUMA(0);

    // 创建session时如果设备选择策略为空，则根据NUMA亲和性自动选择加速器设备
    void *sess = KAEZIP_create_async_compress_session(usr_map, NULL);
    void *sess_dev  = KAEZIP_create_async_compress_session(usr_map, &conf_dev);
    void *sess_numa = KAEZIP_create_async_compress_session(usr_map, &conf_numa);
}
```

### API使用demo
本demo组合使用KAEZip异步压缩接口对原始数据进行压缩，通过polling查询deflate_raw格式的压缩结果，针对压缩结果使用标准zlib同步解压的方式和KAEZip异步解压的方式分别进行解压，最终将解压的结果与原始数据进行比对，达到验证异步压缩接口输出的内容是标准deflate_raw格式且异步解压接口可解的测试目的。详细代码和编译运行步骤如下：
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <zlib.h> // for Bytef
#include <fcntl.h> // for O_RDONLY and open
#include <sys/mman.h> // for munmap
#include <inttypes.h>

#include "kaezip.h"

#define HPAGE_SIZE (2 * 1024 * 1024)
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PFN_MASK ((1UL << 55) - 1)

#define TEST_FILE_PATH "../../../scripts/compressTestDataset/calgary"

static int g_has_done = 0;
static int g_inflate_type = 0; // use async decompress or not。0：sync decompress；1：async decompress。

struct my_custom_data {
    void *src;
    void *dst;
    struct kaezip_buffer_list src_list;
    struct kaezip_buffer_list dest_list;
    void *src_decompd;
    struct kaezip_buffer_list src_decompd_list;
    size_t src_len;
    size_t dst_len;
    size_t src_decompd_len;
};
struct cache_page_map {
    uint64_t *entries;
    size_t entries_num;
    void *base_vaddr;
};

static struct cache_page_map* init_cache_page_map(void *base_vaddr, size_t total_size)
{
    struct cache_page_map *cache = malloc(sizeof(struct cache_page_map));
    if (!cache) return NULL;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open /proc/self/pagemap failed");
        free(cache);
        return NULL;
    }

    // 根据申请大小计算需要读取的条目数
    size_t pages_num = total_size / PAGE_SIZE;
    cache->entries_num = pages_num;

    cache->base_vaddr = base_vaddr;

    // 分配缓存空间
    cache->entries = malloc(pages_num * sizeof(uint64_t));
    if (!cache->entries) {
        close(fd);
        free(cache);
        return NULL;
    }

    // 计算文件偏移量（基地址为第一个条目，即申请到的虚拟地址对应的页面）
    uintptr_t base = (uintptr_t)base_vaddr;
    uintptr_t first_offset = (base / PAGE_SIZE) * sizeof(uint64_t);

    // 定位到起始位置
    if (lseek(fd, first_offset, SEEK_SET) != first_offset) {
        perror("lseek failed");
        close(fd);
        free(cache->entries);
        free(cache);
        return NULL;
    }

    if (read(fd, cache->entries, pages_num * sizeof(uint64_t)) != (ssize_t)(pages_num * sizeof(uint64_t))) {
        perror("read cache failed");
        close(fd);
        free(cache->entries);
        free(cache);
        return NULL;
    }
    close(fd);
    return cache;
}

#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)
static void *get_huge_pages(size_t total_size)
{
    void *addr = mmap(
        NULL,
        total_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_1GB,
        -1, 0
    );

    if (addr == MAP_FAILED) {
        fprintf(stderr, "申请内存大页失败。\n");
        fprintf(stderr, "系统可能没有足够的大页可用。\n");
        fprintf(stderr, "请尝试分配更多大页: sudo sysctl vm.nr_hugepages=10000\n");
        exit(EXIT_FAILURE);
    }

    return addr;
}

static uint64_t get_physical_address_cache_page_map(struct cache_page_map *cache, void *vaddr) {
    uintptr_t virtual_addr = (uintptr_t)vaddr;

    uintptr_t base = (uintptr_t)cache->base_vaddr;
    uintptr_t index = (virtual_addr - base) / PAGE_SIZE;

    // printf("uintptr_t index = %ld . entries_num = %ld \n", index, cache->entries_num);
    if (index >= cache->entries_num) {
        fprintf(stderr, "地址超出缓存范围\n");
        return 0;
    }

    uint64_t entry = cache->entries[index];

    if (!(entry & (1ULL << 63))) {
        fprintf(stderr, "页面不存在\n");
        return 0;
    }

    // 提取物理帧号(PFN)
    uint64_t pfn = entry & PFN_MASK;
    return (pfn << PAGE_SHIFT) | (virtual_addr & (PAGE_SIZE - 1));
}

static void* get_physical_address_wrapper(void *usr, void *vaddr, size_t sz)
{
    struct cache_page_map *cache = (struct cache_page_map *)usr;
    uint64_t phys_addr = get_physical_address_cache_page_map(cache, vaddr);
    return (void*)(uintptr_t)phys_addr;
}

// 给tuple_buf分配 input_size 大小的真实物理内存，用于存放压缩前的file数据。 或者用于存放压缩后的数据。
static int prepare_physical_buf(void **tuple_buf, size_t input_size, struct cache_page_map** page_cache, FILE* file)
{
    int huge_page_num = (int)(input_size * sizeof(Bytef) / HPAGE_SIZE) + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
    size_t total_size = huge_page_num * HPAGE_SIZE;

    *tuple_buf = get_huge_pages(total_size);
    if (*tuple_buf == NULL) {
        return -1;
    }
    if(file == NULL) {
        memset(*tuple_buf, 0, total_size);
    } else {
        (void)fread(*tuple_buf, 1, input_size, file);
    }

    struct cache_page_map* cache = init_cache_page_map(*tuple_buf, total_size);
    if (cache == NULL) {
        printf("init_cache_page_map failed\n");
        return -1;
    }
    *page_cache = cache;

    return 0;
}

static void *g_page_info = NULL;
static size_t read_inputFile(const char* fileName, void** input)
{
    FILE* sourceFile = fopen(fileName, "r");
    if (sourceFile == NULL) {
        fprintf(stderr, "%s not exist!\n", fileName);
        return 0;
    }
    int fd = fileno(sourceFile);
    struct stat fs;
    (void)fstat(fd, &fs);
    size_t input_size = fs.st_size;

    prepare_physical_buf(input, input_size, (struct cache_page_map**)&g_page_info, sourceFile);

    fclose(sourceFile);

    return input_size;
}

static void release_huge_pages(void *addr, size_t total_size)
{
    munmap(addr, total_size);
}

static void check_results(struct my_custom_data *my_data) {
    if (my_data->src_decompd_len != my_data->src_len) {
        printf("Test Error: 解压后与原始长度不一样. 原始长度=%ld   压缩后再解压得到长度=%ld \n",
            my_data->src_len,
            my_data->src_decompd_len);
    }

    // 比较解压后的数据和原始数据
    if (memcmp(my_data->src_decompd, my_data->src_list.buf[0].data, my_data->src_decompd_len) == 0) {
        if(g_inflate_type == 0) {
            printf("Test Success for zlib deflate raw with async deflate and sync inflate.\n");
        } else {
            printf("Test Success for zlib deflate raw wuth async deflate and async inflate.\n");
        }
    } else {
        printf("Test Error:Decompressed data does not match the original data.\n");
    }
}

static void decompression_callback3(struct kaezip_result *result)
{
    if (result->status != 0) {
        printf("DeCompression failed with status: %d\n", result->status);
        return;
    }
    // 在回调中获取解压的数据
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;
    void *compressed_data = my_data->src_decompd_list.buf[0].data;
    my_data->src_decompd_len = result->dst_len;

    my_data->src_decompd = compressed_data;

    check_results(my_data);

    g_has_done = 1;
}
static int decompressAsync(struct my_custom_data *mydata)
{
    iova_map_fn usr_map = get_physical_address_wrapper;
    void *desess = KAEZIP_create_async_decompress_session(usr_map);

    // 使用真实的压缩数据长度作为解压时的输入长度。
    mydata->dest_list.buf[0].buf_len = mydata->dst_len;

    // 提供超出原始数据大小的缓冲区，以确保解压时数据不会溢出
    size_t tmp_size = mydata->src_len * 2;
    void *tmp_buf = NULL;
    struct cache_page_map *tmp_page_info = {0};
    prepare_physical_buf(&tmp_buf, tmp_size, &tmp_page_info, NULL);
    struct kaezip_buffer src_decomped_buf_array[128];
    mydata->src_decompd_list.buf_num = 1;
    mydata->src_decompd_list.buf = src_decomped_buf_array;
    mydata->src_decompd_list.buf[0].data = tmp_buf;
    mydata->src_decompd_list.buf[0].buf_len = tmp_size;
    mydata->src_decompd_list.usr_data = tmp_page_info;

    // 异步解压结果
    struct kaezip_result result = {0};
    result.user_data = mydata;

    // 将 mydata->dest_list.buf[0].data 中的数据进行解压，解压结果放在 mydata->src_decompd_list.buf[0].data 中。
    int compression_status = KAEZIP_decompress_async_in_session(desess, &mydata->dest_list, &mydata->src_decompd_list,
                                                      decompression_callback3, &result);

    if (compression_status != 0) {
        printf("deCompression failed with error code: %d\n", compression_status);
        release_huge_pages(tmp_buf, tmp_size);
        return -1;
    }
    while (g_has_done != 1) {
        KAEZIP_async_polling_in_session(desess, 1);
        usleep(100);
    }
    KAEZIP_destroy_async_decompress_session(desess);
    release_huge_pages(tmp_buf, tmp_size);
    return compression_status;
}

static void compression_callback3(struct kaezip_result *result)
{
    if (result->status != 0) {
        printf("Compression failed with status: %d\n", result->status);
        return;
    }
    // 在回调中获取压缩后的数据
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;
    size_t compressed_size = result->dst_len;
    void *compressed_data = my_data->dest_list.buf[0].data;
    my_data->dst_len = compressed_size;

    if (g_inflate_type == 0) {  // 同步解压。
        // 为解压数据分配内存
        size_t tmp_src_len = result->src_size * 10;
        void *dst_buffer = malloc(tmp_src_len);
        if (!dst_buffer) {
            printf("Memory allocation failed for decompressed data.\n");
            return;
        }

        int ret = -1;
        z_stream strm;
        strm.zalloc = (alloc_func)0;
        strm.zfree = (free_func)0;
        strm.opaque = (voidpf)0;
        (void)inflateInit2_(&strm, -15, "1.2.11", sizeof(z_stream));
        strm.next_in = (z_const Bytef *)compressed_data;
        strm.next_out = dst_buffer;
        strm.avail_in = compressed_size;
        strm.avail_out = tmp_src_len;
        ret = inflate(&strm, Z_FINISH);

        tmp_src_len = strm.total_out;
        // inflateReset(&strm);
        (void)inflateEnd(&strm);
        if (ret < Z_OK) {
            printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
        }

        if (ret < 0) {
            printf("Decompression failed with error code: %d\n", ret);
            free(dst_buffer);
            return;
        }
        my_data->src_decompd = dst_buffer;
        my_data->src_decompd_len = tmp_src_len;

        check_results(my_data);
        // 释放解压后的数据
        free(dst_buffer);
        g_has_done = 1;
    } else {
        decompressAsync(my_data);
    }
}

static int test_main()
{
    g_has_done = 0;
    size_t src_len = 0;
    void *inbuf = NULL;

    src_len = read_inputFile(TEST_FILE_PATH, &inbuf);

    iova_map_fn usr_map = get_physical_address_wrapper;
    void *sess = KAEZIP_create_async_compress_session(usr_map);

    // 异步压缩
    struct kaezip_result result = {0};
    struct my_custom_data mydata = {0};

    struct kaezip_buffer src_buf[128];
    mydata.src_list.usr_data = g_page_info;
    mydata.src_list.buf_num = 1;
    mydata.src_list.buf = src_buf;
    mydata.src_list.buf[0].data = inbuf;
    mydata.src_list.buf[0].buf_len = src_len;

    size_t compressed_size = compressBound(src_len);
    void *tuple_buf = NULL;
    struct cache_page_map *tuple_page_info = {0};
    prepare_physical_buf(&tuple_buf, compressed_size, &tuple_page_info, NULL);
    struct kaezip_buffer tuple_buf_array[128];
    mydata.dest_list.buf_num = 1;
    mydata.dest_list.buf = tuple_buf_array;
    mydata.dest_list.buf[0].data = tuple_buf;
    mydata.dest_list.buf[0].buf_len = compressed_size;
    mydata.dest_list.usr_data = tuple_page_info;

    mydata.src_len = src_len;
    result.user_data = &mydata;

    // 将 my_data->src_list.buf[0].data 中的数据压缩，压缩结果放在 my_data->dest_list.buf[0].data 中。
    int compression_status = KAEZIP_compress_async_in_session(sess, &mydata.src_list, &mydata.dest_list,
                                                      compression_callback3, &result);

    if (compression_status != 0) {
        printf("Compression failed with error code: %d\n", compression_status);
        release_huge_pages(inbuf, src_len);
        return -1;
    }

    while (g_has_done != 1) {
        KAEZIP_async_polling_in_session(sess, 1);
        usleep(100);
    }
    KAEZIP_destroy_async_compress_session(sess);

    release_huge_pages(tuple_buf, src_len);

    return compression_status;
}
int main()
{
    int ret = test_main(); // 测试异步压缩 -> 同步解压。
    g_inflate_type = 1; // 测试异步压缩 -> 异步解压。
    ret = test_main();
    return ret;
}
```

编译测试命令：
```shell
# 注意：需修改demo代码中真实测试文件 TEST_FILE_PATH 的路径为合法路径
gcc main.c  -I/usr/local/kaezip/include -L/usr/local/kaezip/lib -lz -lkaezip -o kaezlib_deflate_async_test
export LD_LIBRARY_PATH=/usr/local/kaezip/lib:$LD_LIBRARY_PATH
./kaezlib_deflate_async_test
# 输出：
# Test Success for zlib deflate raw with async deflate and sync inflate.
# Test Success for zlib deflate raw wuth async deflate and async inflate.
```
### API测试工具
可使用kzip工具对异步API进行功能和性能测试，工具地址：KAELz4/test/kzip
使用步骤：
~~~shell
cd KAELz4/test/kzip
# 编译打包kzip工具
sh build.sh

# 查看工具参数说明
export LD_LIBRARY_PATH=/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
./kzip -h

# 1、单IO时延测试：等价串行流程，结果表示单个IO的压缩时延。
sh runPerf.sh -A kaezlibasync_deflate -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 1 -p 1 -f [path to calgary.tar] 

# 2、单核压缩能力测试：单线程加压，结果表示单线程能够提供的压缩带宽与时延。
sh runPerf.sh -A kaezlibasync_deflate -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 4 -p 1 -f [path to calgary.tar] 

# 3、单KAE能力测试：单线程继续加压，结果表示单个KAE能够提供的压缩带宽与时延。
sh runPerf.sh -A kaezlibasync_deflate -m 1 -n 20000 -s [4/8/16/32/64] -r 1 -k 1 -i 8 -p 1 -f [path to calgary.tar] 
~~~




# Kunpeng Zlib Acceleration Engine

- [Introduction](#introduction)
- [License](#license)
- [Requirements](#requirements)
- [Installation Instructions](#installation-instructions)
- [Test Performace](#test-performace)
- [Contribution Guidelines](#contribution-Guidelines)
- [Vulnerability Management](#Vulnerability-Management)
- [Quality Requirements](#Quality-Requirements)
- [Secure Design](#Secure-Design)
- [More Information](#more-information)
- [Copyright](#copyright)

## Introduction

Kunpeng Zlib Acceleration Engine is used to build performance competitiveness of common software libraries on the Kunpeng platform.

As a new function in the HiSilicon Kunpeng 920 processors, Kunpeng Zlib Acceleration Engine provides a hardware-enabled foundation for  compression. It significantly increases the performance across cloud, big data, and storage applications and  platforms.  By using  Kunpeng Zlib Acceleration Engine, you can:

- Have higher-performance compression and decompression
- Maximize CPU utilization

The compression and decompression algorithm supported by Kunpeng Acceleration Engine are:  gzip/zlib 

## License

It is licensed under the zlib License(https://www.zlib.net/zlib_license.html ). For more information, see the LICENSE file. 

## Requirements

- CPU: Kunpeng 920 
- Support Operating System: 
  - CentOS 7.6  4.14.0-115.el7a.0.1.aarch64 version
  - SuSE 15.1 4.12.14-195-default arch64 version
  - NeoKylin 7.6 4.14.0-115.5.1.el7a.06.aarch64 version
  - EulerOS 2.8 4.19.36-vhulk1907.1.0.h410.eulerosv2r8.aarch64 version
  - BCLinux-R7-U6-Server-aarch64 version
  - Kylin 4.0.2 (juniper) 4.15.0-70-generic version
  - Kylin release 4.0.2 (SP2) 4.19.36-vhulk1907.1.0.h403.ky4.aarch64 version
  - UniKylin Linux release 3(Core)  4.18.0-80.ky3.kb21.hw.aarch64 version
  - Ubuntu 18.04.1 LTS 4.15.0-29-generic version   

## Installation Instructions

Clone the Github repository containing the Kunpeng Accelerator Engine Driver.

```
git clone https://github.com/kunpengcompute/KAEzip
```

Download the release version of Kunpeng Accelerator Engine Driver from:

<https://github.com/kunpengcompute/KAEdriver/releases> 

Firstly, build and install the accelerator driver.
Note: To build the Kunpeng Accelerator Engine Driver, install the `kernel-devel` package first.

```
tar -zxf Kunpeng_KAE_driver.tar.gz
cd kae_driver
make
make install
modprobe uacce
modprobe hisi_qm
modprobe hisi_zip
```

Secondly, install the accelerator library:

```
cd warpdrive
sh autogen.sh 
./configure 
make 
make install
```

Then Install KAEzip library:

Download [zlib-1.2.11.tar.gz](https://www.zlib.net/zlib-1.2.11.tar.gz) at KAEzip/open_source.

```
cd KAEzip
sh setup.sh install
```

for more install guid and user guid, get information at:
<https://www.huaweicloud.com/kunpeng/software/kaezip.html>

## Test Performace

```
cd test
make
export LD_LIBRARY_PATH=/usr/local/kaezip/lib
./kaezip_perf -m 8 -l 1024 -n 1000
./kaezip_perf -m 8 -l 1024 -n 1000 -d
```
## Contribution Guidelines

If you want to contribute to KAEzip, please use GitHub [issues](https://github.com/kunpengcompute/KAEzip/issues/new) for tracking requests and bugs.

## Vulnerability Management
Please refer to https://github.com/kunpengcompute/Kunpeng#security

## Quality Requirements
Please refer to [Secure Coding Specifications](https://github.com/kunpengcompute/Kunpeng/blob/master/security/SecureCoding.md).

## Secure Design
Please refer to [Secure Design](https://github.com/kunpengcompute/Kunpeng/blob/master/security/SecureDesign.md).

## More Information

For further assistance and more QAs, contact Huawei Support at:

<https://www.hikunpeng.com/developer/boostkit/library/compression> 

## Copyright

Copyright © 2018 Huawei Corporation. All rights reserved.
