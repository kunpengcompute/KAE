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

#define HPAGE_SIZE (2 * 1024 * 1024)  // 2MB大页
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PFN_MASK ((1UL << 55) - 1)

#define TEST_FILE_PATH "../../../scripts/compressTestDataset/calgary"

static int g_has_done = 0; // 异步回调是否完成。需要初始化为0。
static int g_inflate_type = 0; // 是否使用zlib异步解压。0：同步解压；1：异步解压。

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

#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)
static void *get_huge_pages(size_t total_size)
{
    void *addr = mmap(
        NULL,
        total_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_1GB,
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

static int retry_compression(struct my_custom_data *my_data);
static int g_total_trytimes = 0;
static void compression_callback3(struct kaezip_result *result)
{
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;

    if (result->status == 8) {
        if (g_total_trytimes > 6) {
            printf("尝试多次失败，退出\n");
            return;
        }
        g_total_trytimes++;
        printf("Compression callback failed with status: %d , retrying...\n", result->status);

        // 清理旧的压缩目标缓存
        struct kaezip_buffer *buf = &my_data->dest_list.buf[0];
        size_t old_size = buf->buf_len;
        release_huge_pages(buf->data, old_size);

        // 重新分配更大的缓冲区
        size_t new_size = old_size * 2;
        void *new_buf = NULL;
        struct cache_page_map *new_page_info = NULL;
        prepare_physical_buf(&new_buf, new_size, &new_page_info, NULL);

        buf->data = new_buf;
        buf->buf_len = new_size;
        my_data->dest_list.usr_data = new_page_info;

        // 重试压缩
        retry_compression(my_data);
        return;
    }
    if (result->status != 0) {
        printf("Compression failed with status: %d\n", result->status);
        return;
    }
    // 在回调中获取压缩后的数据
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
static int retry_compression(struct my_custom_data *my_data)
{
    iova_map_fn usr_map = get_physical_address_wrapper;
    void *sess = KAEZIP_create_async_compress_session(usr_map);

    struct kaezip_result result = {0};
    result.user_data = my_data;
    g_has_done = 0;

    int status = KAEZIP_compress_async_in_session(sess, &my_data->src_list, &my_data->dest_list,
                                                  compression_callback3, &result);
    if (status != 0) {
        printf("Retry compression failed with status: %d\n", status);
        return -1;
    }
    while (g_has_done != 1) {
        KAEZIP_async_polling_in_session(sess, 1);
        usleep(100);
    }
    KAEZIP_destroy_async_compress_session(sess);
    return 0;
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
    compressed_size = compressed_size / 15; // 分配一个不足的dest空间，测试异常返回值
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
int test_async_err_dst_buf_less_deflate()
{
    int ret = test_main(); // 测试异步压缩 -> 同步解压。
    g_inflate_type = 1; // 测试异步压缩 -> 异步解压。
    ret = test_main();
    return ret;
}
