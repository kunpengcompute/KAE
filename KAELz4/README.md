
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
KAELz4异步接口一共支持2种模式，polling模式压缩接口、非polling模式压缩接口。
一共支持3种压缩数据格式：block、frame、lz77_raw：其中blcok与frame格式与社区lz4标准block\frame格式兼容；lz77_raw格式需要调用对应的后处理接口进行转换成标准block\frame格式。
以下章节分别介绍不同polling模式下，不同数据格式的接口组合方式。

### 3.1、polling模式下lz77_raw数据处理成标准lz4数据格式接口说明
本小节介绍了polling模式下，输出lz77_raw格式数据所需的相关接口，以及将lz77_raw格式数据转换为lz4标准block\frame格式的接口
#### 3.1.1、相关结构体
```c
// 基本回调数据格式
struct kaelz4_result {
    int status; # 压缩任务状态。详细说明见第四节-错误码说明
    unsigned int rsvd; # 保留字段
    void *user_data; # 用户调用异步接口时传入的自定义数据指针
    size_t src_size; # 压缩任务原始数据总大小
    size_t dst_len; # 传入时表示目标buffer的大小，要求大于compressBound(srcLen)，回调时表示压缩后大小
    uint32_t *ibuf_crc; # 存放输入数据CRC32校验的指针。如果存在，将对输入数据计算CRC32校验
    uint32_t *obuf_crc; # 存放压缩数据CRC32校验的指针。如果存在，将对压缩后的数据计算CRC32校验
};

// SGL相关数据格式
struct kaelz4_buffer {
    size_t buf_len;
    void *data;
};
struct kaelz4_buffer_list {
    unsigned int buf_num;
    unsigned int rsvd;
    struct kaelz4_buffer *buf;
    void *usr_data;
};
```
#### 3.1.2、用户自定义函数
```c
// 压缩任务完成后，将调用该回调函数。回调压缩的结果
typedef void (*lz4_async_callback)(struct kaelz4_result *result);

// 逻辑地址与物理地址转换函数
typedef void *(*iova_map_fn)(void *usr, void *vaddr, size_t sz);
```
#### 3.1.3、初始化session会话
```
/**
 * @brief: frame compress async api
 * @param: usr_map [IN] : Function for converting virtual addresses to physical addresses.
 * @return: void *sess: compression session
 * /
void *KAELZ4_create_async_compress_session(iova_map_fn usr_map);
```
#### 3.1.4、压缩
```
/**
 * @brief: Get tuple buffer length by src length.
 * @param: src_len [IN] : src length
 */
size_t KAELZ4_compress_get_tuple_buf_len(size_t src_len);

/**
 * @brief: lz77 compress async api
 * @param: sess : session
 * @param: src [IN] : input data, must be sgl
 * @param: tuple [OUT] : tuple buf, lz77 output data, must be sgl, only support buf_num == 1 now.
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*lz4_async_callback)(struct kaelz4_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @return: 0 success, other fail
 */
int KAELZ4_compress_lz77_async_in_session(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *tuple, lz4_async_callback callback, struct kaelz4_result *result);

```
#### 3.1.5、主动polling压缩结果
```
/**
 * @brief: Polling hardware result in session.
 * @param: sess : session
 * @param: budget : process packet num per call.
 */
void KAELZ4_async_polling_in_session(void *sess, int budget);
```
#### 3.1.6、对lz77_raw数据进行格式转换
```
/**
 * @brief: rebuild lz77 data to block
 * @param: src [IN] : input data
 * @param: tuple [OUT] : lz77 output data, only support buf_num == 1 now.
 * @param: dst [OUT] : output data, only support buf_num == 1 now.
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @return: 0 success, other fail
 */
int KAELZ4_rebuild_lz77_to_block(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *tuple, struct kaelz4_buffer_list *dst, struct kaelz4_result *result);

/**
 * @brief: rebuild lz77 data to frame
 * @param: src [IN] : input data
 * @param: tuple [OUT] : lz77 output data, only support buf_num == 1 now.
 * @param: dst [OUT] : output data, only support buf_num == 1 now.
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @param: preferences_ptr [IN] : compress preferences. NULL is avaliable. if not NULL  preferences_ptr  should be struct LZ4F_preferences_t data.
 * @return: 0 success, other fail
 */
int KAELZ4_rebuild_lz77_to_frame(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *tuple, struct kaelz4_buffer_list *dst, struct kaelz4_result *result, const void *preferences_ptr);
```
#### 3.1.7、清理session会话
```
/**
 * @brief: Destroy session and hardware ctx.
 * @param: sess : session
 */
void KAELZ4_destroy_async_compress_session(void *sess);
/**
 * @brief: reset session and hardware ctx, all compress tasks will be canceled.
 * @param: sess : session
 */
void KAELZ4_reset_session(void *sess);
```
#### 3.1.8、整体使用示例Demo
本demo使用polling模式接口，将测试文件压缩为lz77_raw数据格式，随后转换成标准lz4的block数据格式，最后通过解压转换为原始文件。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <lz4.h>
#include <lz4frame.h>
#include <unistd.h>
#include <sys/stat.h>

#include <zlib.h> // for Bytef
#include <fcntl.h> // for O_RDONLY and open
#include <sys/mman.h> // for munmap
#include <inttypes.h>

#define HPAGE_SIZE (2 * 1024 * 1024)  // 2MB大页
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PFN_MASK ((1UL << 55) - 1)

static int g_has_done = 0; // 异步回调是否完成。需要初始化为0。
static int g_file_chunk_size = 256;

struct my_custom_data {
    void *src;
    void *tuple;
    void *dst;
    struct kaelz4_buffer_list src_list;
    struct kaelz4_buffer_list tuple_list;
    struct kaelz4_buffer_list dst_list;
    void *src_decompd;
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
        perror("打开/proc/self/pagemap失败");
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
        perror("lseek失败");
        close(fd);
        free(cache->entries);
        free(cache);
        return NULL;
    }

    // 读取该次申请到的所有条目
    if (read(fd, cache->entries, pages_num * sizeof(uint64_t)) != (ssize_t)(pages_num * sizeof(uint64_t))) {
        perror("读取条目失败");
        close(fd);
        free(cache->entries);
        free(cache);
        return NULL;
    }
    close(fd);
    return cache;
}

static void *get_huge_pages(size_t total_size)
{
    void *addr = mmap(
        NULL,
        total_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
        -1, 0
    ); // 申请内存大页

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

    // 计算在缓存中的条目索引
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

    int huge_page_num = (int)(input_size * sizeof(Bytef) / HPAGE_SIZE) + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
    size_t total_size = huge_page_num * HPAGE_SIZE;
    *input = get_huge_pages(total_size);

    if (*input == NULL) {
        return 0;
    }
    (void)fread(*input, 1, input_size, sourceFile);

    struct cache_page_map* cache = init_cache_page_map(*input, total_size);

    // printf("初始化数据 %ld \n", cache->entries_num);
    // uint64_t phys_addr = get_physical_address_cache_page_map(cache, *input);

    // printf("大页物理地址: 0x%" PRIx64 "\n", phys_addr);
    g_page_info = cache;
    fclose(sourceFile);

    return input_size;
}

static void release_huge_pages(void *addr, size_t total_size)
{
    munmap(addr, total_size);
}
static int prepare_tuple_buf(void **tuple_buf, size_t src_len, struct cache_page_map** page_cache)
{
    size_t tuple_buf_len = KAELZ4_compress_get_tuple_buf_len(g_file_chunk_size * 1024) * (src_len / (g_file_chunk_size * 1024) + 1) * 2;
    size_t huge_page_num = tuple_buf_len * sizeof(Bytef) / HPAGE_SIZE + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
    size_t total_size = huge_page_num * HPAGE_SIZE;
    *tuple_buf = get_huge_pages(total_size);
    // printf("申请的tuple buf大页虚拟地址: %p len: 0x%lx\n", *tuple_buf, total_size);

    if (*tuple_buf == NULL) {
        return -1;
    }

    memset(*tuple_buf, 0, total_size);

    struct cache_page_map* cache = init_cache_page_map(*tuple_buf, total_size);
    if (cache == NULL) {
        printf("init_cache_page_map failed\n");
        return -1;
    }
    // uint64_t phys_addr = get_physical_address_cache_page_map(cache, *tuple_buf);
    // printf("tuple buf大页物理地址: 0x%" PRIx64 "\n", phys_addr);
    *page_cache = cache;

    return 0;
}

static void compression_callback3(struct kaelz4_result *result) {
    if (result->status != 0) {
        printf("Compression failed with status: %d\n", result->status);
        return;
    }
    // 在回调中获取压缩后的数据
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;

    if (KAELZ4_rebuild_lz77_to_block(&my_data->src_list, &my_data->tuple_list, &my_data->dst_list, result) != 0) {
        printf("[user]KAELZ4_rebuild_lz77_to_block : %d\n", result->status);
    }

    size_t compressed_size = result->dst_len;
    void *compressed_data = my_data->dst_list.buf[0].data;

    my_data->dst_len = compressed_size;

    // 使用LZ4解压缩数据
    size_t tmp_src_len = result->src_size * 10;
    // 为解压数据分配内存
    void *dst_buffer = malloc(tmp_src_len);
    if (!dst_buffer) {
        printf("Memory allocation failed for decompressed data.\n");
        return;
    }

    size_t ret =  LZ4_decompress_safe((char *)compressed_data, (char *)dst_buffer, compressed_size, tmp_src_len);
    if (ret < 0) {
        printf("Decompression failed with error code: %ld\n", ret);
        free(dst_buffer);
        return;
    }
    tmp_src_len = ret; // 解压后长度
    my_data->src_decompd = dst_buffer;
    my_data->src_decompd_len = tmp_src_len;

    if (my_data->src_decompd_len != my_data->src_len) {
        printf("Test Error: 解压后与原始长度不一样. result->src_size=%ld   原始长度=%ld   压缩后解压长度=%ld \n",
            result->src_size,
            my_data->src_len,
            my_data->src_decompd_len);
    }

    // 比较解压后的数据和原始数据
    if (memcmp(my_data->src_decompd, my_data->src_list.buf[0].data, result->src_size) == 0) {
        printf("Test Success.\n");
    } else {
        printf("Test Error:Decompressed data does not match the original data.\n");
    }

    // 释放解压后的数据
    free(dst_buffer);
    g_has_done = 1;
}

static int test_lz77_raw_polling(int contentChecksumFlag, int blockChecksumFlag, int contentSizeFlag)
{
    g_has_done = 0;
    size_t src_len = 0;  // 256KB
    void *inbuf = NULL;

    src_len = read_inputFile("../../../scripts/compressTestDataset/calgary", &inbuf);

    // 为压缩数据分配内存
    size_t compressed_size = LZ4F_compressBound(src_len, NULL);
    void *compressed_data = malloc(compressed_size);
    if (!compressed_data) {
        printf("Memory allocation failed for compressed data.\n");
        free(inbuf);
        return -1;
    }

    // 为压缩数据分配内存
    void *compressed_data2 = malloc(compressed_size * 2);
    if (!compressed_data2) {
        printf("Memory allocation failed for compressed data.\n");
        free(inbuf);
        return -1;
    }

    iova_map_fn usr_map = get_physical_address_wrapper;

    void *sess = KAELZ4_create_async_compress_session(usr_map);

    // 异步压缩
    struct kaelz4_result result = {0};
    struct my_custom_data mydata = {0};

    struct kaelz4_buffer src_buf[128];
    mydata.src_list.usr_data = g_page_info;
    mydata.src_list.buf_num = 1;
    mydata.src_list.buf = src_buf;
    mydata.src_list.buf[0].data = inbuf;
    mydata.src_list.buf[0].buf_len = src_len;

    void *tuple_buf = NULL;
    struct cache_page_map *tuple_page_info = {0};
    prepare_tuple_buf(&tuple_buf, src_len, &tuple_page_info);
    struct kaelz4_buffer tuple_buf_array[128];
    mydata.tuple_list.buf_num = 1;
    mydata.tuple_list.buf = tuple_buf_array;
    mydata.tuple_list.buf[0].data = tuple_buf;
    mydata.tuple_list.buf[0].buf_len = KAELZ4_compress_get_tuple_buf_len(src_len);
    mydata.tuple_list.usr_data = tuple_page_info;

    struct kaelz4_buffer dst_buf[128];
    mydata.dst_list.buf_num = 1;
    mydata.dst_list.buf = dst_buf;
    mydata.dst_list.buf[0].data = compressed_data;
    mydata.dst_list.buf[0].buf_len = compressed_size;

    mydata.src_len = src_len;

    result.user_data = &mydata;
    result.src_size = src_len;
    result.dst_len = compressed_size;

    int compression_status = KAELZ4_compress_lz77_async_in_session(sess, &mydata.src_list, &mydata.tuple_list,
                                                      compression_callback3, &result);

    if (compression_status != 0) {
        printf("Compression failed with error code: %d\n", compression_status);
        free(inbuf);
        free(compressed_data);
        return -1;
    }

    while (g_has_done != 1) {
        KAELZ4_async_polling_in_session(sess, 1);
        usleep(100);
    }
    KAELZ4_destroy_async_compress_session(sess);

    release_huge_pages(tuple_buf, src_len);

    return compression_status;
}

int main()
{
    return test_lz77_raw_polling(0, 0, 0);
}
```

```shell
gcc main.c -I/usr/local/kaelz4/include -L/usr/local/kaelz4/lib -llz4 -lkaelz4 -o kaelz4_lz77_raw_dataformat_test
export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:$LD_LIBRARY_PATH
./kaelz4_lz77_raw_dataformat_test # 输出 Test Success.

# tips: 需要注意代码中的测试文件路径的存在 ../../../scripts/compressTestDataset/calgary
# 建议在KAELz4/test/kzip 目录测试运行 ./kaelz4_lz77_raw_dataformat_test
```

### 3.2、polling模式异步压缩接口
本小节介绍了polling模式下，将数据压缩为lz4标准的block\frame格式所需的接口
#### 3.2.1、相关结构体

```c
// 基本回调数据格式
struct kaelz4_result {
    int status; # 压缩任务状态。详细说明见第四节-错误码说明
    unsigned int rsvd; # 保留字段
    void *user_data; # 用户调用异步接口时传入的自定义数据指针
    size_t src_size; # 压缩任务原始数据总大小
    size_t dst_len; # 传入时表示目标buffer的大小，要求大于compressBound(srcLen)，回调时表示压缩后大小
    uint32_t *ibuf_crc; # 存放输入数据CRC32校验的指针。如果存在，将对输入数据计算CRC32校验
    uint32_t *obuf_crc; # 存放压缩数据CRC32校验的指针。如果存在，将对压缩后的数据计算CRC32校验
};

// SGL相关数据格式
struct kaelz4_buffer {
    size_t buf_len;
    void *data;
};
struct kaelz4_buffer_list {
    unsigned int buf_num;
    unsigned int rsvd;
    struct kaelz4_buffer *buf;
    void *usr_data;
};
```
#### 3.2.2、用户自定义函数

```c
// 压缩任务完成后，将调用该回调函数。回调压缩的结果
typedef void (*lz4_async_callback)(struct kaelz4_result *result);

// 逻辑地址与物理地址转换函数
typedef void *(*iova_map_fn)(void *usr, void *vaddr, size_t sz);
```
#### 3.2.3、初始化session会话
```
/**
 * @brief: frame compress async api
 * @param: usr_map [IN] : Function for converting virtual addresses to physical addresses.
 * @return: void *sess: compression session
 * /
void *KAELZ4_create_async_compress_session(iova_map_fn usr_map);
```
#### 3.2.4、压缩
```
/**
 * @brief: block compress async api
 * @param: sess [IN] : this compression task session
 * @param: src [IN] : input data
 * @param: dst [OUT] : output data
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*lz4_async_callback)(struct kaelz4_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @return: 0 success, other fail
 * /
int KAELZ4_compress_async_in_session(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback callback, struct kaelz4_result *result);

/**
 * @brief: frame compress async api
 * @param: sess [IN] : this compression task session
 * @param: src [IN] : input data
 * @param: dst [OUT] : output data
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*lz4_async_callback)(struct kaelz4_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @param: preferences_ptr [IN] : compress preferences. NULL is avaliable. if not NULL  preferences_ptr  should be struct LZ4F_preferences_t data.
 * @return: 0 success, other fail
 * /
int KAELZ4_compress_frame_async_in_session(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback callback, struct kaelz4_result *result, const void *preferences_ptr);
```
#### 3.2.5、主动polling压缩结果
```
/**
 * @brief: Polling hardware result in session.
 * @param: sess : session
 * @param: budget : process packet num per call.
 */
void KAELZ4_async_polling_in_session(void *sess, int budget);
```
#### 3.2.6、清理session会话
```
/**
 * @brief: Destroy session and hardware ctx.
 * @param: sess : session
 */
void KAELZ4_destroy_async_compress_session(void *sess);
/**
 * @brief: reset session and hardware ctx, all compress tasks will be canceled.
 * @param: sess : session
 */
void KAELZ4_reset_session(void *sess);
```
#### 3.2.7、polling接口整体使用示例Demo
本demo使用polling模式接口，通过初始化session上下文，调用frame格式异步压缩接口，
接着主动polling压缩结果，最后在callback回调函数中取得frame格式的压缩结果，并将压缩结果解压为原始数据。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <lz4.h>
#include <lz4frame.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_has_done = 0; // 异步回调是否完成。需要初始化为0。

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
        bytes[i] = rand() % 256;  // 随机生成字节
    }
}

static void compression_callback2(struct kaelz4_result *result) {
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
    LZ4F_createDecompressionContext(&dctx, 100);
    int ret = LZ4F_decompress(dctx, dst_buffer, &tmp_src_len,
                                            compressed_data, &compressed_size, NULL);
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

static int test_frame_polling(int contentChecksumFlag, int blockChecksumFlag, int contentSizeFlag)
{
    g_has_done = 0;
    size_t src_len = 256 * 1024;  // 256KB
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

    void *sess = KAELZ4_create_async_compress_session(NULL);

    // 异步压缩
    struct kaelz4_result result = {0};
    struct my_custom_data mydata = {0};

    struct kaelz4_buffer_list src = {0};
    struct kaelz4_buffer src_buf[128];
    src.usr_data = &mydata;
    src.buf_num = 1;
    src.buf = src_buf;
    src.buf[0].data = inbuf;
    src.buf[0].buf_len = src_len;

    struct kaelz4_buffer dst_buf[128];
    struct kaelz4_buffer_list dst = {0};
    dst.buf_num = 1;
    dst.buf = dst_buf;
    dst.buf[0].data = compressed_data;
    dst.buf[0].buf_len = compressed_size;

    mydata.src = inbuf;
    mydata.src_len = src_len;
    mydata.dst = compressed_data;
    result.user_data = &mydata;
    result.src_size = src_len;
    result.dst_len = compressed_size;

    int compression_status = KAELZ4_compress_frame_async_in_session(sess, &src, &dst,
                                                      compression_callback2, &result, &preferences);

    if (compression_status != 0) {
        printf("Compression failed with error code: %d\n", compression_status);
        free(inbuf);
        free(compressed_data);
        return -1;
    }

    while (g_has_done != 1) {
        KAELZ4_async_polling_in_session(sess, 1);
        usleep(100);
    }
    KAELZ4_destroy_async_compress_session(sess);

    return compression_status;
}
int main()
{
    return test_frame_polling(0, 0, 0);
}
```
```shell
gcc main.c -I/usr/local/kaelz4/include -L/usr/local/kaelz4/lib -llz4 -lkaelz4 -o kaelz4_polling_test
export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:$LD_LIBRARY_PATH
./kaelz4_polling_test # 输出 Test Success.
```

### 3.3、非polling模式异步压缩接口
本小节介绍了非polling模式下，数据通过接口直接被异步压缩处理，最终由callback函数回调压缩结果的相关接口。
#### 3.3.1、相关结构体
```c
// 基本回调数据格式
struct kaelz4_result {
    int status; # 压缩任务状态。详细说明见第四节-错误码说明
    unsigned int rsvd; # 保留字段
    void *user_data; # 用户调用异步接口时传入的自定义数据指针
    size_t src_size; # 压缩任务原始数据总大小
    size_t dst_len; # 传入时表示目标buffer的大小，要求大于compressBound(srcLen)，回调时表示压缩后大小
    uint32_t *ibuf_crc; # 存放输入数据CRC32校验的指针。如果存在，将对输入数据计算CRC32校验
    uint32_t *obuf_crc; # 存放压缩数据CRC32校验的指针。如果存在，将对压缩后的数据计算CRC32校验
};

// SGL相关数据格式
struct kaelz4_buffer {
    size_t buf_len;
    void *data;
};
struct kaelz4_buffer_list {
    unsigned int buf_num;
    unsigned int rsvd;
    struct kaelz4_buffer *buf;
    void *usr_data;
};
```

#### 3.3.2、用户自定义函数
```c
// 压缩任务完成后，将调用该回调函数。回调压缩的结果
typedef void (*lz4_async_callback)(struct kaelz4_result *result);

// 逻辑地址与物理地址转换函数
typedef void *(*iova_map_fn)(void *usr, void *vaddr, size_t sz);
```

#### 3.3.3、异步压缩初始化

```c
/*! LZ4_async_compress_init(iova_map_fn usr_map) :
*  Register software compress function, initialize Task Queues and Threads on the KAE Side.
*  If not being called before, LZ4_compress_async will not handle any exceptions and simply return failure.
*  Note: Can not be called before fork();
* @param: usr_map [IN] : Function for converting virtual addresses to physical addresses
*/
 void LZ4_async_compress_init(iova_map_fn usr_map);
```

#### 3.3.4、block 异步压缩

```c
/**
 * @brief: block compress async api
 * @param: src [IN] : input data
 * @param: dst [OUT] : output data
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*lz4_async_callback)(struct kaelz4_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @return: 0 success, other fail
 * /
 int LZ4_compress_async(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback callback, struct kaelz4_result *result);
```

#### 3.3.5、frame 异步压缩

```c
/**
 * @brief: frame compress async api
 * @param: src [IN] : input data
 * @param: dst [OUT] : output data
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*lz4_async_callback)(struct kaelz4_result *result);
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaelz4_result.
 * @param: preferences_ptr [IN] : compress preferences. NULL is avaliable. if not NULL  preferences_ptr  should be struct LZ4F_preferences_t data.
 * @return: 0 success, other fail
 * /
int LZ4F_compressFrame_async(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst, lz4_async_callback callback, struct kaelz4_result *result, const LZ4F_preferences_t* preferencesPtr);
​
```

#### 3.3.6、异步压缩结束

```c
/*! LZ4_teardown_async_compress() :
 *  Destroy all Task Queues and Threads on the KAE Side.
 */
LZ4LIB_API void LZ4_teardown_async_compress(void);
```
#### 3.3.7、整体使用示例Demo

本demo以普通 frame 格式异步压缩接口示例：
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
    LZ4F_createDecompressionContext(&dctx, 100);
    int ret = LZ4F_decompress(dctx, dst_buffer, &tmp_src_len,
                                            compressed_data, &compressed_size, NULL);
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
    size_t src_len = 256 * 1024;  // 256KB
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

    // 异步压缩
    struct kaelz4_result result = {0};
    struct my_custom_data mydata = {0};

    struct kaelz4_buffer_list src = {0};
    struct kaelz4_buffer src_buf[128];
    src.usr_data = &mydata;
    src.buf_num = 1;
    src.buf = src_buf;
    src.buf[0].data = inbuf;
    src.buf[0].buf_len = src_len;

    struct kaelz4_buffer dst_buf[128];
    struct kaelz4_buffer_list dst = {0};
    dst.buf_num = 1;
    dst.buf = dst_buf;
    dst.buf[0].data = compressed_data;
    dst.buf[0].buf_len = compressed_size;

    mydata.src = inbuf;
    mydata.src_len = src_len;
    mydata.dst = compressed_data;
    result.user_data = &mydata;
    result.src_size = src_len;
    result.dst_len = compressed_size;
    LZ4_async_compress_init(NULL);
    int compression_status = LZ4F_compressFrame_async(&src, &dst,
                                                      compression_callback, &result, &preferences);

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
gcc main.c -I/usr/local/kaelz4/include -L/usr/local/kaelz4/lib -llz4 -o kaelz4_frame_async_test
export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:$LD_LIBRARY_PATH
./kaelz4_frame_async_test # 输出 Test Success.
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
- 3、支持polling接口和通用接口切软算
- 4、不支持SGL模式分段buffer切软算

## 五、kzip工具说明

### kzip工具说明

#### 前置环境设置

- 开启观察KAE硬件队列
    ~~~shell
    # 默认2个CPU的设备能够观察到4个256，表示当前机器上共支持4*256个KAE硬件驱动压缩队列。容器化部署场景中，队列数量跟分配给容器的设备相关。
    watch -n 0.2 cat /sys/class/uacce/hisi_zip-*/available_instances
    ~~~

- 开启驱动fast模式
    ~~~shell
    # 卸载原驱动
    rmmod hisi_zip # 执行后，无法观察到KAE硬件队列。

    # 重新以fast模式加载驱动
    modprobe hisi_zip perf_mode=1 uacce_mode=2 pf_q_num=256 #执行后观察KAE硬件队列会看到4个256，表示使能正确
    ~~~
- 设置fast模式下特定有效压缩窗长
    ```shell
    export KAE_LZ4_WINTYPE=8
    export KAE_LZ4_COMP_TYPE=8
    ```

### 使用步骤

进入kzip工具目录

~~~shell
cd KAELz4/test/kzip
# 编译打包kzip工具
sh build.sh
~~~

~~~shell
# 查看工具参数说明
export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:$LD_LIBRARY_PATH
./kzip -h
~~~

~~~shell
# 基本功能测试：测试不同数据集下，不同压缩算法，不同分片大小时的压缩解压测试。
sh runFunc.sh
~~~

~~~shell
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
~~~

更多测试工具使用说明详见 KAELz4/test/kzip/README.md

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
