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
#include <sys/mman.h>
#include <inttypes.h>

#define HPAGE_SIZE (2 * 1024 * 1024)  // 2MB大页
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PFN_MASK ((1UL << 55) - 1)

static int g_has_done = 0; // 异步回调是否完成。需要初始化为0。
static void *g_page_info = NULL;
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

struct my_custom_data {
    void *src;
    void *dst;
    void *src_decompd;
    size_t src_len;
    size_t dst_len;
    size_t src_decompd_len;
};

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
        fprintf(stderr, "请尝试分配更多大页: sudo sysctl vm.nr_hugepages=1000\n");
        exit(EXIT_FAILURE);
    }

    return addr;
}
static void release_huge_pages(void *addr, size_t total_size)
{
    munmap(addr, total_size);
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
    // input_size = 255 * 1024; // 仅取一部分进行测试

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

static void compression_callback4(struct kaelz4_result *result) {
    if (result->status != 0) {
        printf("Compression failed with status: %d\n", result->status);
        return;
    }

    // 在回调中获取压缩后的数据
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;
    struct kaelz4_buffer_list *dst = (struct kaelz4_buffer_list *)my_data->dst;
    void *compressed_data = dst->buf[0].data;
    size_t compressed_size = result->dst_len;


    my_data->dst_len = compressed_size;

    // 使用LZ4解压缩数据
    size_t tmp_src_len = result->src_size * 200;
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


    struct kaelz4_buffer_list *src = (struct kaelz4_buffer_list *)my_data->src;
    size_t total = 0;
    for (unsigned int i = 0; i < src->buf_num; ++i) {
        total += src->buf[i].buf_len;
    }

    void *source = malloc(total);
    size_t offset = 0;
    for (unsigned int i = 0; i < src->buf_num; ++i) {
        if (src->buf[i].data && src->buf[i].buf_len > 0) {
            memcpy((char *)source + offset, src->buf[i].data, src->buf[i].buf_len);
            offset += src->buf[i].buf_len;
        }
    }

    // 比较解压后的数据和原始数据
    if (memcmp(my_data->src_decompd, source, result->src_size) == 0) {
        printf("Test Success.\n");
    } else {
        printf("Test Error:Decompressed data does not match the original data.\n");
    }

    // 释放解压后的数据
    free(dst_buffer);
    g_has_done = 1;
}


static void* get_physical_address_wrapper(void *usr, void *vaddr, size_t sz)
{
    struct cache_page_map *cache = (struct cache_page_map *)usr;
    uint64_t phys_addr = get_physical_address_cache_page_map(cache, vaddr);
    // printf("vaddr: %p pa:0x%lx\n", vaddr, phys_addr);
    return (void*)(uintptr_t)phys_addr;
}

static int test_async_frame_and_sgl(int contentChecksumFlag, int blockChecksumFlag, int contentSizeFlag)
{
    g_has_done = 0;
    size_t src_len = 0;
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

    iova_map_fn usr_map = get_physical_address_wrapper;
    LZ4_async_compress_init(usr_map);

    // 异步压缩
    struct kaelz4_result result = {0};
    struct my_custom_data mydata = {0};

    struct kaelz4_buffer_list src = {0};
    struct kaelz4_buffer src_buf[128];
    src.buf_num = 1; // change buf_num to 1, 2, 3... to test different SGLs
    src.buf = src_buf;
    unsigned int tmp_size = src_len / src.buf_num;
    for (int i = 0; i < src.buf_num - 1; i++) {
        src.buf[i].data = inbuf + tmp_size * i;
        src.buf[i].buf_len = tmp_size;
    }
    src.buf[src.buf_num - 1].data = inbuf + tmp_size * (src.buf_num - 1);
    src.buf[src.buf_num - 1].buf_len = src_len - tmp_size * (src.buf_num - 1);
    src.usr_data = g_page_info;

    struct kaelz4_buffer dst_buf[128];
    struct kaelz4_buffer_list dst = {0};
    dst.buf_num = 1;
    dst.buf = dst_buf;
    dst.buf[0].data = compressed_data;
    dst.buf[0].buf_len = compressed_size;

    mydata.src = &src;
    mydata.src_len = src_len;
    mydata.dst = &dst;
    result.user_data = &mydata;
    result.src_size = src_len;
    result.dst_len = compressed_size;

    int compression_status = LZ4F_compressFrame_async(&src, &dst,
                                                      compression_callback4, &result, &preferences);

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

    int huge_page_num = (int)(src_len * sizeof(Bytef) / HPAGE_SIZE) + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
    size_t total_size = huge_page_num * HPAGE_SIZE;
    release_huge_pages(inbuf, total_size);

    return compression_status;
}
int test_async_SGL_data()
{
    return test_async_frame_and_sgl(0, 0, 0);
}
