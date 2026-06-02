# KAEZip Compression API User Guide

- [Synchronous APIs](#synchronous-apis)
- [Asynchronous APIs](#asynchronous-apis)

## Synchronous APIs

### API Description

The KAEZip synchronous compression/decompression APIs depend on the standard usage of zlib in the community. During program execution, you only need to specify the location of libz.so to the directory where KAEZip is installed to enable KAE acceleration. The data can be in zlib, gzip, or deflate_raw format.

```shell
export LD_LIBRARY_PATH=/usr/local/kaezip/lib:$LD_LIBRARY_PATH
```

### API Usage Demo

You can directly compile the standard zlib compression code. For details, see the `KAEZlib/test/perftest/kaezip_perf.c` test file.

For details about the function and performance test procedure, see [Testing the KAEZlib Library](https://www.hikunpeng.com/document/detail/en/kunpengaccel/kae/usermanual/kunpengaccel_06_0020.html).

## Asynchronous APIs

### API Overview

This section describes the asynchronous compression and decompression APIs provided by KAEZip, including core functions applicable to high-performance scenarios, such as session management, task submission, and task polling.

| API                               | Introduction                    |
|---------------------------------------|--------------------------|
| `KAEZIP_get_devices`| Obtains information about the current ZIP accelerator device.|
| `KAEZIP_create_async_compress_session`| Creates a session for an asynchronous compression task (deflate-raw format).      |
| `KAEZIP_create_async_compress_session_zlib`| Creates a session for an asynchronous compression task (zlib format).      |
| `KAEZIP_compress_async_in_session`        | Submits an asynchronous compression task.       |
| `KAEZIP_async_polling_in_session`          | Queries the result of an asynchronous compression or decompression task in polling mode.       |
| `KAEZIP_destroy_async_compress_session` | Destroys the session of a compression task.    |
| `KAEZIP_create_async_decompress_session`| Creates a session for an asynchronous decompression task (deflate-raw format)       |
| `KAEZIP_create_async_decompress_session_zlib`| Creates a session for an asynchronous decompression task (zlib format)       |
| `KAEZIP_decompress_async_in_session`        | Submits an asynchronous decompression task.       |
| `KAEZIP_destroy_async_decompress_session` | Destroys the session of a decompression task.    |
| `KAEZIP_reset_session` | Resets the task session.    |

### Constraints

- The hardware must be the new Kunpeng 920 model.
- Each session must be used within a single thread. The APIs are not thread-safe, meaning you cannot share a session across multiple threads. Doing so may cause compression and decompression functions to behave unexpectedly. Resources of different sessions are mutually exclusive. You are advised to create and use independent sessions in different threads.

### API Details

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

### Specifying an Accelerator Device

KAEZip provides an API for querying information about the current ZIP accelerator device. In addition, the asynchronous compression and decompression APIs allow you to select the required accelerator device. The structure of the accelerator device information is defined as follows:

```c
struct zip_dev {
	int numa_id;                  // NUMA node to which the device belongs
	char dev_name[256];           // hisi_zip-*
    char dev_root[MAX_STR_SIZE];  // /sys/class/uacce/hizi_zip-*
    unsigned int hw_id;           // Hardware ID (the number after the hyphen, for example, hisi_zip-8)
    unsigned int dev_id;          // Logical ID (0, 1, 2...)
};
```

Currently, you can specify a device via the following ways:
1. Use the default policy, which automatically selects an accelerator device based on NUMA affinity.
2. Specify a NUMA node and select a ZIP accelerator device on the NUMA node.
3. Specify a ZIP accelerator device.

The demo is as follows:

```c
#include "kaezip.h"

int main()
{
    unsigned int num = 0;
    const struct zip_dev *devs = KAEZIP_get_devices(&num);

    if (devs == NULL) {
        return -1; // No KAE device
    }

    // Automatically selects an accelerator device based on NUMA affinity.
    device_config_t conf_auto = KAE_CONFIG_AUTO();
    // Specifies the first accelerator device.
    device_config_t conf_dev  = KAE_CONFIG_BY_DEV(&devs[0]);
    // Specifies an accelerator device on NUMA-0.
    device_config_t conf_numa = KAE_CONFIG_BY_NUMA(0);

    // If the device selection policy is empty when a session is created, an accelerator device is automatically selected based on NUMA affinity.
    void *sess = KAEZIP_create_async_compress_session(usr_map, NULL);
    void *sess_dev  = KAEZIP_create_async_compress_session(usr_map, &conf_dev);
    void *sess_numa = KAEZIP_create_async_compress_session(usr_map, &conf_numa);
}
```

### API Usage Demo

In the following demo, KAEZip asynchronous compression APIs are used to compress raw data. The compression result in deflate_raw format is queried by polling and decompressed in standard zlib synchronous decompression mode and KAEZip asynchronous decompression mode. The decompression results are then compared with the raw data to verify that the output of the asynchronous compression APIs is in deflate_raw format and can be decompressed by the asynchronous decompression APIs. The detailed code, compilation, and running procedure are as follows.

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
static int g_inflate_type = 0; // Use async decompression or not. 0: sync decompression; 1: async decompression

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

    // Calculate the number of entries to be read based on allocated size.
    size_t pages_num = total_size / PAGE_SIZE;
    cache->entries_num = pages_num;

    cache->base_vaddr = base_vaddr;

    // Allocate the cache space.
    cache->entries = malloc(pages_num * sizeof(uint64_t));
    if (!cache->entries) {
        close(fd);
        free(cache);
        return NULL;
    }

    // Calculate the file offset (the base address is the first entry, that is, the page corresponding to the allocated virtual address).
    uintptr_t base = (uintptr_t)base_vaddr;
    uintptr_t first_offset = (base / PAGE_SIZE) * sizeof(uint64_t);

    // Locate the start position.
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
        fprintf(stderr, "Failed to apply for huge pages.\n");
        fprintf(stderr, "The system may not have enough huge pages.\n");
        fprintf(stderr, "Try to allocate more huge pages: sudo sysctl vm.nr_hugepages=10000\n");
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
        fprintf(stderr, "The address is out of the cache range.\n");
        return 0;
    }

    uint64_t entry = cache->entries[index];

    if (!(entry & (1ULL << 63))) {
        fprintf(stderr, "The page does not exist.\n");
        return 0;
    }

    // Obtain the physical frame number (PFN).
    uint64_t pfn = entry & PFN_MASK;
    return (pfn << PAGE_SHIFT) | (virtual_addr & (PAGE_SIZE - 1));
}

static void* get_physical_address_wrapper(void *usr, void *vaddr, size_t sz)
{
    struct cache_page_map *cache = (struct cache_page_map *)usr;
    uint64_t phys_addr = get_physical_address_cache_page_map(cache, vaddr);
    return (void*)(uintptr_t)phys_addr;
}

// Allocate real physical memory of the size specified by input_size to tuple_buf, to store file data before compression or compressed data.
static int prepare_physical_buf(void **tuple_buf, size_t input_size, struct cache_page_map** page_cache, FILE* file)
{
    int huge_page_num = (int)(input_size * sizeof(Bytef) / HPAGE_SIZE) + 1; //Huge pages are 2 MB in size. Any requested allocation must be an integer multiple of this size.
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
        printf("Test Error: The length after decompression is different from the original length. Original length=%ld. Length after decompression=%ld \n",
            my_data->src_len,
            my_data->src_decompd_len);
    }

    // Compare the decompressed data with the original data.
    if (memcmp(my_data->src_decompd, my_data->src_list.buf[0].data, my_data->src_decompd_len) == 0) {
        if(g_inflate_type == 0) {
            printf("Test Success for zlib deflate raw with async deflate and sync inflate.\n");
        } else {
            printf("Test Success for zlib deflate raw with async deflate and async inflate.\n");
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
    // Obtain decompressed data in the callback.
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

    // Use the actual compressed data length as the input length during decompression.
    mydata->dest_list.buf[0].buf_len = mydata->dst_len;

    // Provide a buffer that exceeds the original data size to ensure that no data overflows during decompression.
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

    // Asynchronously decompress the result.
    struct kaezip_result result = {0};
    result.user_data = mydata;

    // Decompress the data in mydata->dest_list.buf[0].data and save the decompression result in mydata->src_decompd_list.buf[0].data.
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
    // Obtain compressed data from the callback.
    struct my_custom_data *my_data = (struct my_custom_data *)result->user_data;
    size_t compressed_size = result->dst_len;
    void *compressed_data = my_data->dest_list.buf[0].data;
    my_data->dst_len = compressed_size;

    if (g_inflate_type == 0) { // Decompress data synchronously.
        // Allocate memory for decompressed data.
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
        // Release decompressed data.
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

    // Perform asynchronous compression.
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

    // Compress the data in my_data->src_list.buf[0].data and store the compressed data in my_data->dest_list.buf[0].data.
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
    int ret = test_main(); // Test asynchronous compression and synchronous decompression.
    g_inflate_type = 1; // Test asynchronous compression and asynchronous decompression.
    ret = test_main();
    return ret;
}
```

Run the compilation command.

```shell
# Note: Change the path of the actual test file (TEST_FILE_PATH) in the demo code to a valid path.
gcc main.c  -I/usr/local/kaezip/include -L/usr/local/kaezip/lib -lz -lkaezip -o kaezlib_deflate_async_test
```

Run the test file.

```
export LD_LIBRARY_PATH=/usr/local/kaezip/lib:$LD_LIBRARY_PATH
./kaezlib_deflate_async_test
```

The command output is as follows:

```
# Test Success for zlib deflate raw with async deflate and sync inflate.
# Test Success for zlib deflate raw with async deflate and async inflate.
```

### API Test Tool

You can use the kzip tool to test the functions and performance of asynchronous APIs. For details, see `scripts/perftest/kzip/README_EN.md`.

## Statements

- This code repository contributes to the zlib open-source project solely for performance optimization. It strictly adheres to the coding style and methods, as well as security design of the native open-source software. Any vulnerability and security issues of the software shall be resolved by the corresponding upstream communities according to their response mechanisms. Please pay attention to the notifications and version updates released by the upstream communities. The Kunpeng computing community does not assume any responsibility for software vulnerabilities and security issues.
