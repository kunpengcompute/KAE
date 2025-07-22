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
static int g_test_frame = 0; // 是否测试frame格式。
struct my_custom_data {
    void *src;
    void *tuple;
    void *dst;
    struct kaelz4_buffer_list src_list;
    struct kaelz4_buffer_list tuple_list;
    struct kaelz4_buffer_list dst_list;
    void *src_decompd;
    size_t src_len;
    size_t tuple_len;
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
    input_size = 63 * 1024; // 小于64k的测试，KAE侧逻辑比较清晰。

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

static int retry_compression(struct my_custom_data *my_data);
static int g_total_trytimes = 0;

static void compression_callback3(struct kaelz4_result *result) {
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;

    if (result->status != 0) {
        printf("Compression callback failed with status: %d. retrying...\n", result->status);

        g_total_trytimes++;
        if(g_total_trytimes % 1000 == 0) {
            printf("依据尝试重试失败%d次\n", g_total_trytimes);
        }

        g_has_done = -1; // 表示需要重试
        return;
    }
    // 在回调中获取压缩后的数据

    if (g_test_frame == 1) {
        LZ4F_preferences_t preferences = {0};
        preferences.frameInfo.blockSizeID = LZ4F_max64KB;  // 设定块大小
        if (KAELZ4_rebuild_lz77_to_frame(&my_data->src_list, &my_data->tuple_list, &my_data->dst_list, result, &preferences) != 0) {
            printf("[user]KAELZ4_rebuild_lz77_to_frame : %d\n", result->status);
        }
    } else {
        if (KAELZ4_rebuild_lz77_to_block(&my_data->src_list, &my_data->tuple_list, &my_data->dst_list, result) != 0) {
            printf("[user]KAELZ4_rebuild_lz77_to_block : %d\n", result->status);
        }
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

    size_t ret =  -1;
    if (g_test_frame == 1) {
        LZ4F_decompressionContext_t dctx;
        LZ4F_createDecompressionContext(&dctx, 100);
        ret = LZ4F_decompress(dctx, dst_buffer, &tmp_src_len, compressed_data, &compressed_size, NULL);
    } else {
        ret = LZ4_decompress_safe((char *)compressed_data, (char *)dst_buffer, compressed_size, tmp_src_len);
        tmp_src_len = ret; // 解压后长度
    }
    if (ret < 0) {
        printf("Decompression failed with error code: %ld\n", ret);
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
    if (memcmp(my_data->src_decompd, my_data->src_list.buf[0].data, result->src_size) == 0) {
        if (g_test_frame == 1) {
            printf("Test Success for less tuple buf with frame.\n");
        } else {
            printf("Test Success for less tuple buf with  block.\n");
        }
    } else {
        printf("Test Error:Decompressed data does not match the original data.\n");
    }

    // 释放解压后的数据
    free(dst_buffer);
    g_has_done = 1;
}
static int retry_compression(struct my_custom_data *my_data)
{
    iova_map_fn usr_map = get_physical_address_wrapper;
    void *sess = KAELZ4_create_async_compress_session(usr_map);

    struct kaelz4_result result = {0};
    result.user_data = my_data;
    g_has_done = 0;

    size_t old_size = my_data->tuple_len;  // 上一次分配的输出空间大小

    void *tuple_buf = NULL;
    struct cache_page_map *tuple_page_info = {0};

    size_t src_len = old_size + 1 * 1024;
    // 用于快速测试到达边界情况
    size_t limit_len = 60 * 1024;
    if(src_len < limit_len) {
        src_len = old_size * 2;
        src_len = src_len > limit_len ? limit_len : src_len;
    }
    prepare_tuple_buf(&tuple_buf, src_len, &tuple_page_info);
    struct kaelz4_buffer tuple_buf_array[128];
    my_data->tuple_list.buf_num = 1;
    my_data->tuple_list.buf = tuple_buf_array;
    my_data->tuple_list.buf[0].data = tuple_buf;
    my_data->tuple_list.buf[0].buf_len = src_len;
    my_data->tuple_list.usr_data = tuple_page_info;

    my_data->tuple_len = src_len;  // 更新tuple_len为新的尝试长度

    int compression_status = KAELZ4_compress_lz77_async_in_session(sess, &my_data->src_list, &my_data->tuple_list,
                                                                   compression_callback3, &result);

    if (compression_status != 0) {
        printf("Compression failed with error code: %d\n", compression_status);
        return -1;
    }

    while (g_has_done == 0) {
        KAELZ4_compress_async_polling_in_session(sess, 1);
        usleep(100);
    }
    KAELZ4_destroy_async_compress_session(sess);
    release_huge_pages(tuple_buf, src_len);

    return compression_status;
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

    // printf("compressed_size = %ld \n", compressed_size);

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

    // 分配的输出空间小于784字节时，压缩错误值为3
    // 大于784字节时，空间又不足时，压缩错误值为8
    // 外部输入数据较大时，KAE内部分片，当分片的最后一片的空间小于784字节时，压缩错误值为3。
    size_t less_src_len = 100; 

    prepare_tuple_buf(&tuple_buf, src_len, &tuple_page_info);
    struct kaelz4_buffer tuple_buf_array[128];
    mydata.tuple_list.buf_num = 1;
    mydata.tuple_list.buf = tuple_buf_array;
    mydata.tuple_list.buf[0].data = tuple_buf;
    mydata.tuple_list.buf[0].buf_len = less_src_len;
    mydata.tuple_list.usr_data = tuple_page_info;

    struct kaelz4_buffer dst_buf[128];
    mydata.dst_list.buf_num = 1;
    mydata.dst_list.buf = dst_buf;
    mydata.dst_list.buf[0].data = compressed_data;
    mydata.dst_list.buf[0].buf_len = compressed_size;

    mydata.src_len = src_len;
    mydata.tuple_len = mydata.tuple_list.buf[0].buf_len;

    result.user_data = &mydata;

    int compression_status = KAELZ4_compress_lz77_async_in_session(sess, &mydata.src_list, &mydata.tuple_list,
                                                                   compression_callback3, &result);

    if (compression_status != 0) {
        printf("Compression failed with error code: %d\n", compression_status);
        free(inbuf);
        free(compressed_data);
        return -1;
    }

    while (g_has_done == 0) {
        KAELZ4_compress_async_polling_in_session(sess, 1);
        usleep(100);
    }
    KAELZ4_destroy_async_compress_session(sess);

    release_huge_pages(tuple_buf, src_len);
    while(g_has_done == -1) {
        // 重试压缩
        retry_compression(&mydata);
    }

    return compression_status;
}
int test_async_err_dst_buf_less_lz77_raw()
{
    int ret = test_lz77_raw_polling(0, 0, 0);
    g_test_frame = 1;
    ret = test_lz77_raw_polling(0, 0, 0);
    return ret;
}
