#define _GNU_SOURCE
#include <sched.h>

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <sys/shm.h>
#include <math.h>
#include <numa.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "lz4.h"
#include "alg/manage.h"
#include "delayRecord.h"
#include "compress_ctx.h"

#include "datagen.h"   /* RDG_generate */

#define KB *(1 << 10)
#define MB *(1 << 20)
#define GB *(1U << 30)

int g_file_chunk_size = 0; // 测试分片大小。 默认 0kb 不分片
int g_log_level = 1; // 打印日志级别。 0：不统计时延。 1:时延统计
int g_cpu_threads_per_core = 1; // 是否开启超线程。 1: 未开启。 2:开启
int g_enable_huge_pages = 0; // 是否使用内存大页
int g_enable_polling_mode = 0; // 是否使用单线程polling模式

#define HPAGE_SIZE (2 * 1024 * 1024)  // 2MB大页
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PFN_MASK ((1UL << 55) - 1)

struct cache_page_map {
    uint64_t *entries;
    size_t entries_num;
    void *base_vaddr;
};

struct cache_page_map* init_cache_page_map(void *base_vaddr, size_t total_size)
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

uint64_t get_physical_address_cache_page_map(struct cache_page_map *cache, void *vaddr) {
    uintptr_t virtual_addr = (uintptr_t)vaddr;

    // 计算在缓存中的条目索引
    uintptr_t base = (uintptr_t)cache->base_vaddr;
    uintptr_t index = (virtual_addr - base) / PAGE_SIZE;

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

void free_cache_page_map(struct cache_page_map *cache) {
    if (cache) {
        free(cache->entries);
        free(cache);
    }
}

void *get_huge_pages(size_t total_size)
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

void release_huge_pages(void *addr, size_t total_size)
{
    munmap(addr, total_size);
}

void* get_physical_address_wrapper(void *usr, void *vaddr, size_t sz)
{
    struct cache_page_map *cache = (struct cache_page_map *)usr;
    uint64_t phys_addr = get_physical_address_cache_page_map(cache, vaddr);
    return (void*)(uintptr_t)phys_addr;
}


static uLong read_inputFile(struct compress_ctx *ctx, const char* fileName, void** input)
{
    FILE* sourceFile = fopen(fileName, "r");
    if (sourceFile == NULL) {
        fprintf(stderr, "%s not exist!\n", fileName);
        return 0;
    }
    int fd = fileno(sourceFile);
    struct stat fs;
    (void)fstat(fd, &fs);

    uLong input_size = fs.st_size;

    if (g_enable_huge_pages) {
        int huge_page_num = (int)(input_size * sizeof(Bytef) / HPAGE_SIZE) + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
        size_t total_size = huge_page_num * HPAGE_SIZE;
        *input = get_huge_pages(total_size);
        printf("申请的大页虚拟地址: %p\n", *input);

        if (*input == NULL) {
            return 0;
        }
        (void)fread(*input, 1, input_size, sourceFile);

        struct cache_page_map* cache = init_cache_page_map(*input, total_size);
        uint64_t phys_addr = get_physical_address_cache_page_map(cache, *input);

        printf("大页物理地址: 0x%" PRIx64 "\n", phys_addr);
        ctx->page_info = cache;
    } else {
        *input = malloc(input_size * sizeof(Bytef));
            if (*input == NULL) {
                return 0;
            }
        (void)fread(*input, 1, input_size, sourceFile);
    }

    fclose(sourceFile);

    return input_size;
}

static void save_metadata_to_file(
    const char *metadata_filename, struct fragment_metadata *fragments, unsigned int fragment_count)
{
    FILE *file = fopen(metadata_filename, "wb");
    if (file == NULL) {
        perror("Failed to open metadata file");
        return;
    }
    // 写入分片数量
    fwrite(&fragment_count, sizeof(unsigned int), 1, file);

    // 写入每个分片的元数据（偏移量和长度）
    for (unsigned int i = 0; i < fragment_count; i++) {
        fwrite(&fragments[i], sizeof(struct fragment_metadata), 1, file);
    }

    fclose(file);
}
// 从文件中读取元数据
static void load_metadata_from_file(
    const char *in_filename, struct fragment_metadata **fragments, unsigned int *fragment_count)
{
    size_t meta_file_length = strlen(in_filename) + strlen(".meta") + 1;  // +1 用于'\0'结束符
    char *metadata_filename = (char *)malloc(meta_file_length);  // 分配内存
    if (metadata_filename == NULL) {
        perror("Failed to allocate memory");
        exit(-1);
    }
    // 拼接文件名
    snprintf(metadata_filename, meta_file_length, "%s.meta", in_filename);

    FILE *file = fopen(metadata_filename, "rb");
    if (file == NULL) {
        perror("Failed to open metadata file");
        return;
    }
    // 读取分片数量
    fread(fragment_count, sizeof(unsigned int), 1, file);
    // 为分片元数据分配内存
    *fragments = (struct fragment_metadata *)malloc(*fragment_count * sizeof(struct fragment_metadata));
    if (*fragments == NULL) {
        perror("Failed to allocate memory for fragment metadata");
        fclose(file);
        return;
    }

    // 读取每个分片的元数据
    fread(*fragments, sizeof(struct fragment_metadata), *fragment_count, file);

    fclose(file);
    free(metadata_filename);
}

static struct compress_out_buf *get_buf_node_and_del_it(struct compress_out_buf **out_buf_list, unsigned int sn)
{
    struct compress_out_buf *prev = NULL;
    struct compress_out_buf *current = *out_buf_list;
    while (current != NULL) {
        if (current->sn == sn) {
            // 如果是第一个节点
            if (prev == NULL) {
                // 移动头指针
                *out_buf_list = current->next;
            } else {
                // 删除当前节点，调整前一个节点的 next 指针
                prev->next = current->next;
            }

            // 返回匹配的节点（如果需要）
            return current;
        }

        prev = current;
        current = current->next;
    }

    return NULL;
}

static size_t write_outputFile_2(const char* outFileName, void* output, uLong output_size)
{
    FILE* outputFile = fopen(outFileName, "w");
    if (!outputFile) {
        fprintf(stderr, "%s create failed!\n", outFileName);
        return 0;
    }
    size_t count = fwrite(output, sizeof(Bytef), output_size, outputFile);
    fclose(outputFile);
    return count;
}

static size_t write_outputFile(const char* outFileName, struct compress_out_buf **out_buf_list, unsigned int output_num)
{
    FILE* outputFile = fopen(outFileName, "w");
    if (!outputFile) {
        fprintf(stderr, "%s create failed!\n", outFileName);
        return 0;
    }

    struct fragment_metadata *fragments = (struct fragment_metadata *)malloc(output_num * sizeof(struct fragment_metadata));
    if (fragments == NULL) {
        perror("Failed to allocate memory");
        return -1;
    }
    unsigned int base_offset = 0; // 记录每个分片的偏移量。

    size_t count = 0;
    unsigned int num = 0;
    while (output_num > num) {
        struct compress_out_buf *out_buf_node = get_buf_node_and_del_it(out_buf_list, num);
        if (out_buf_node == NULL)
            break;

        fragments[num].offset = base_offset;
        fragments[num].len = out_buf_node->len; // 假设每个分片固定大小 100
        base_offset += fragments[num].len; // 更新下一个分片的偏移量
        uint32_t tmp_crc = crc32(0, out_buf_node->buf_addr, out_buf_node->len);
        if (out_buf_node->obuf_crc != 0 && out_buf_node->obuf_crc != tmp_crc) {
            printf("Obuf crc err ! expected 0x%x recv 0x%x\n", tmp_crc, out_buf_node->obuf_crc);
            return -1;
        }
        tmp_crc = crc32(0, out_buf_node->src, out_buf_node->src_len);
        if (out_buf_node->ibuf_crc != 0 && out_buf_node->ibuf_crc != tmp_crc) {
            printf("Ibuf crc err ! expected 0x%x recv 0x%x\n", tmp_crc, out_buf_node->ibuf_crc);
            return -1;
        }

        count += fwrite(out_buf_node->buf_addr, sizeof(Bytef), out_buf_node->len, outputFile);
        num++;

        free(out_buf_node);
    }

    size_t meta_file_length = strlen(outFileName) + strlen(".meta") + 1;  // +1 用于'\0'结束符
    char *meta_filename = (char *)malloc(meta_file_length);  // 分配内存
    if (meta_filename == NULL) {
        perror("Failed to allocate memory");
        return -1;
    }
    // 拼接文件名
    snprintf(meta_filename, meta_file_length, "%s.meta", outFileName);
    save_metadata_to_file(meta_filename, fragments, output_num);

    free(meta_filename);
    fclose(outputFile);
    free(fragments);
    return count;
}

static uint8_t *get_compress_input(size_t input_sz)
{
    uint8_t *inbuf = (uint8_t *)malloc(input_sz * sizeof(uint8_t));
    if (inbuf == NULL) {
        return NULL;
    }

    memset(inbuf, 0, input_sz);
    srand((unsigned int)time(NULL));
    int i = 0;
    for (i = 0; i < input_sz; i++) {
        inbuf[i] = (uint8_t)rand() % 254 + 1;
    }

    return inbuf;
}
// 获取当前 ns 时间
static uint64_t get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static void compress_async_polling(struct compress_param *param)
{
    struct compress_ctx *ctx = param->ctx;

    while (unlikely(param->done != 1)) {
        if (ctx->sess && ctx->algorithm->poll)
            ctx->algorithm->poll(ctx->sess, 1);
        else {
            ctx->param_index = (ctx->param_index + 1) % ctx->inflight_num;
            param = &ctx->param_buf[ctx->param_index];
        }
    }
    param->done = 0;

    if (param->loop_index > 0) {
        ctx->out_total_len += param->dst_len;
        ctx->finish_num++;
        return;
    }

    if (param->result.status != 0 && ctx->chunk_len <= 64 * 1024) {
        printf("Async compress callback status not ok!\n============== exit =============\n");
        exit(-1);
    }

    struct compress_out_buf *out_buf = (struct compress_out_buf *)malloc(sizeof(struct compress_out_buf));
    if (out_buf == NULL) {
        return;
    }

    out_buf->len = param->dst_len;
    out_buf->buf_addr = param->dst.buf[0].data;
    out_buf->src_len = param->src_len;
    out_buf->src = param->src.buf[0].data;
    out_buf->next = NULL;
    out_buf->sn = param->sn;
    out_buf->ibuf_crc = param->ibuf_crc;
    out_buf->obuf_crc = param->obuf_crc;

    ctx->out_total_len += param->dst_len;
    if (ctx->out_buf_tail) {
        ctx->out_buf_tail->next = out_buf;
    } else {
        ctx->out_buf_list = out_buf;
    }
    ctx->out_buf_tail = out_buf;
    ctx->finish_num++;
}

static void compress_async_callback(struct kaelz4_result *result)
{
    // printf("[user]异步 callback 了！！\n");
    if (result->status != 0) {
        printf("[user]回调压缩异常 : %d\n", result->status);
    }
    struct compress_param *param = (struct compress_param *)result->user_data;

    if (param->ctx->is_lz77_mode) {
        const char *alg_name = param->ctx->algorithm->name;
        if(strcmp(alg_name, "kaelz4async_lz77_frame") == 0) {
            if (KAELZ4_rebuild_lz77_to_frame(&param->src, &param->tuple, &param->dst, result, NULL) != 0) {
                printf("[user]KAELZ4_rebuild_lz77_to_block : %d\n", result->status);
            }
        } else {
            if (KAELZ4_rebuild_lz77_to_block(&param->src, &param->tuple, &param->dst, result) != 0) {
                printf("[user]KAELZ4_rebuild_lz77_to_block : %d\n", result->status);
            }
        }
    }

    param->dst_len = result->dst_len;
    if ((param->ctx->algorithm->async_compress != NULL && param->ctx->compress_or_decompress != 0) ||
        ((param->ctx->algorithm->async_decompress != NULL && param->ctx->compress_or_decompress == 0))) {
        wmb();
    }

    if (g_log_level == 1) {
        uint64_t end = get_ns();
        uint64_t timeonce = end - param->start_time;
        if(timeonce > 0) {
            record_latency(param->ctx->all_delays, timeonce, param->sn);
        }
    }

    param->done = 1;
    return;
}

static int do_real_compression(struct compress_ctx *ctx, const struct kaelz4_buffer_list *src, unsigned int *src_len,
                        struct kaelz4_buffer_list *dst, unsigned int *dst_len, void *param)
{
    if (ctx->compress_or_decompress) { // 压缩流程。
        if (ctx->algorithm->async_compress) {
            return ctx->algorithm->async_compress(ctx->sess, src, dst, compress_async_callback, param);
        } else {
            return ctx->algorithm->compress(src->buf[0].data, src_len, dst->buf[0].data, dst_len);
        }
    } else { // 解压逻辑
        if (ctx->algorithm->async_decompress) {
            return ctx->algorithm->async_decompress(src, dst, compress_async_callback, param);
        } else {
            return ctx->algorithm->decompress(src->buf[0].data, src_len, dst->buf[0].data, dst_len);
        }
    }
    return 0;
}

static void compress_ctx_init(struct compress_ctx *ctx, int compress_or_decompress, unsigned int inflight_num,
                       unsigned int chunk_len, compression_algorithm_t *algorithm, int is_test_crc)
{
    ctx->algorithm = algorithm;
    ctx->chunk_len = chunk_len;
    ctx->sn = 0;
    ctx->finish_num = 0;
    ctx->compress_or_decompress = compress_or_decompress;
    ctx->out_buf_list = NULL;
    ctx->out_buf_tail = NULL;
    ctx->sess = NULL;
    ctx->out_total_len = 0;
    ctx->thread_id = 0;
    ctx->inflight_num = inflight_num;
    ctx->with_crc = is_test_crc;
    ctx->src_buf_num = 1;
    if (g_file_chunk_size && (g_file_chunk_size * 1024) <= HPAGE_SIZE && ctx->algorithm->async_compress != NULL && ctx->compress_or_decompress != 0) {
        g_enable_huge_pages = 1;
        ctx->src_buf_num = 4;
    }

    ctx->all_delays = (uint64_t *)malloc(sizeof(uint64_t) * MAX_LATENCY_COUNT);
    memset(ctx->param_buf, 0, ctx->inflight_num * sizeof(struct compress_param));
    ctx->param_index = 0;
    ctx->is_lz77_mode = 0;

    int is_test_lz77_block = strcmp(algorithm->name, "kaelz4async_lz77") == 0;
    int is_test_lz77_frame = strcmp(algorithm->name, "kaelz4async_lz77_frame") == 0;
    if ((is_test_lz77_block || is_test_lz77_frame) && ctx->compress_or_decompress != 0) {
        if (g_file_chunk_size == 0 || g_file_chunk_size * 1024 > HPAGE_SIZE) {
            // TBM: 当前chunk_size超过2M kzip不支持lz77模式，因为大页内存不连续
            ctx->algorithm = get_algorithm("kaelz4async_block");
            if (is_test_lz77_frame) {
                ctx->algorithm = get_algorithm("kaelz4async_frame");
            }
            return;
        }
        ctx->is_lz77_mode = 1;
        g_enable_polling_mode = 1;
    }
}

static void compress_ctx_destory(struct compress_ctx *ctx)
{
    struct compress_out_buf *out_buf_list = ctx->out_buf_list;
    while (out_buf_list != NULL) {
        ctx->out_buf_list = ctx->out_buf_list->next;
        free(out_buf_list);
        out_buf_list = ctx->out_buf_list;
    }
    ctx->out_buf_list = NULL;
    ctx->out_buf_tail = NULL;
}
#define MAX_CPUS 512 // 最大可绑核数量。
static int g_taskset_cpus_arr[MAX_CPUS];
static int g_config_bind_cpus_count = 0; // 配置文件中传入的绑定的cpu核心数量
/**
* 绑核参数解析。将-b 参数解析为实际可用的cpu核数组
* 支持逗号分割和横线范围绑核。
* 最大支持 MAX_CPUS 个绑核。
* @params [in] char * range 实际用户输入的-b参数。例如：  3,4,6-10,12
* @params [out] int * tasksetCpuArr。实际解析出来的cpu绑核列表。 例如：[3,4,6,7,8,9,10,12]
* @params [out] int * bindCpusCount。实际解析出来的cpu绑核个数。默认从0开始
* @return void
*/
void parseTasksetLists(char *range, int *tasksetCpuArr, int *bindCpusCount){
    char *token;
    token = strtok(range, ","); // 拆分解析逗号
    while (token != NULL) {
        int start, end;
        char *dash = strchr(token, '-'); // 查找横杠表示范围
        if (dash) {
            // 解析范围，如 "1-3"
            *dash = '\0';
            start = atoi(token);
            end = atoi(dash + 1);

            // 将范围内的所有 CPU 加入数组
            for (int i = start; i <= end; i++) {
                tasksetCpuArr[(*bindCpusCount)++] = i;
                if (*bindCpusCount > MAX_CPUS) {
                    goto parse_config_end;
                }
            }
        } else {
            // 单个 CPU 核，如 "2"
            tasksetCpuArr[(*bindCpusCount)++] = atoi(token);
            if (*bindCpusCount > MAX_CPUS) {
                goto parse_config_end;
            }
        }
        token = strtok(NULL, ",");
    }
    parse_config_end:
    *bindCpusCount = MAX_CPUS;
}
/**
 * 绑定CPU亲和
 * @params [in] i 并发的进程或线程数
 * @params [in] process_or_pthread 当前启动的是进程还是线程。 1: 进程。 其他: 线程
 */
static void set_cpu_affinity_for_child(int i, int process_or_pthread)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);           // 清空 CPU 集合
    int use_engine_nums = 2;   // 要使用的加速器数量； 可参数控制
    int super_thread_rate = g_cpu_threads_per_core; // 当前机器超线程的超级倍数；可自动读取
    int cpus_per_numa = 40 * super_thread_rate; // 每个numa对应的cpu核心数量。920 默认 40，开超线程就80。
    int coreid = (int)(i/use_engine_nums)*super_thread_rate + (cpus_per_numa * (i % use_engine_nums)) ;
    if (g_config_bind_cpus_count > 0) {
        if (i > g_config_bind_cpus_count) { // 如果并发数大于配置的绑核数量，直接不管多出来的并发了。
            return;
        }
        coreid = g_taskset_cpus_arr[i]; //  每个线程或进程使用一个固定的绑核。
    }
    CPU_SET(coreid, &mask);
    if (process_or_pthread == 1) { // 为进程绑核
        if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
            perror("sched_setaffinity failed");
            exit(EXIT_FAILURE);
        }
    } else { // 为线程绑核
        if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) != 0) {
            perror("pthread_setaffinity_np failed");
            pthread_exit(NULL);  // 退出线程
        }
    }
}

static uLong get_src_content(struct compress_ctx *ctx, const char* in_filename, void **inbuf)
{
    uLong src_len;
    if (in_filename) {
        // fprintf(stdout, "compress filename : %s\n", in_filename);
        src_len = read_inputFile(ctx, in_filename, inbuf);
    } else {
        *inbuf = get_compress_input(ctx->chunk_len);
        src_len = ctx->chunk_len;
    }
    if (!*inbuf) {
        fprintf(stderr, "inbuf is NULL!\n");
        return -1;
    }
    return src_len;
}

#define PRINT_DELAY_DATA_LEN 6
static void printf_perf_data(struct compress_ctx *ctx, struct timeval start, struct timeval stop, uLong src_len,
                      const char* in_filename, const char* out_filename,int multi)
{
    gettimeofday(&stop, NULL);
    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    uLong stream_len = ctx->compress_or_decompress ? src_len * ctx->loop_times : ctx->out_total_len;
    float speed1 = 1000000.0 / time1 * multi * stream_len / (1 << 20);
    float iops = 1000.0 * ctx->sn / time1;

    printf("%s %s perf result when loop %d times: ", ctx->algorithm->name, ctx->compress_or_decompress ?
            "compress" : "decompress", ctx->loop_times);
    printf( "file:%s. chunk %d kb.\ntime used: %lus, speed = %.1fMB/s (%.3fGB/s), ",
           in_filename, g_file_chunk_size, time1 / 1000000, speed1, speed1 / 1024);
    printf("iops = %.3fk, %s latency avg = %.3fus, latency avg per io = %.3fus\n",
        iops,
        ctx->compress_or_decompress ? "compress" : "decompress",
        1.0 * time1 / ctx->sn,
        1.0 * time1 / ctx->sn * ctx->inflight_num);
    if (g_log_level) {
        double resp_latencies[PRINT_DELAY_DATA_LEN] = {0};
        int p_counts[PRINT_DELAY_DATA_LEN] = {-200, 0, 50, 90, 99, 999};
        get_percent_latencies(ctx->all_delays, resp_latencies, p_counts, PRINT_DELAY_DATA_LEN, ctx->sn);
        printf("%s delay result: chunk %d kb. inflightNum: %d, total test %d times.  \n",
                ctx->algorithm->name, g_file_chunk_size, ctx->inflight_num, ctx->sn);
        printf("P_avg : %.2f us\n", get_average_latency(ctx->all_delays, ctx->sn));
        for (int i = 0; i < PRINT_DELAY_DATA_LEN; ++i) {
            if (p_counts[i] == 0) {
                printf("P_min : %.2f us\n", resp_latencies[i]);
            } else if (p_counts[i] <= -1) {
                printf("P_max : %.2f us\n", resp_latencies[i]);
            } else {
                printf("P%-4d : %.2f us\n", p_counts[i], resp_latencies[i]);
            }
        }
        char *cahr_print_table_data = getenv("PRINT_TABLE_DATA");;
        if (cahr_print_table_data != NULL) {
            char *task_queue_num = getenv("KAE_LZ4_ASYNC_THREAD_NUM");
            int kae_task_num = 12;
            if (task_queue_num != NULL) {
                kae_task_num = atoi(task_queue_num);
            }
            printf( "console.log('kae-threads:%d, file:%s. chunk %d kb. inflightNum: %d, alg:%s ');",
                kae_task_num, in_filename, g_file_chunk_size,  ctx->inflight_num, ctx->algorithm->name);
            // // function t(r){console.log(r.split(' ').join('	'));}
            double this_rate = (double)src_len * ctx->loop_times / ctx->out_total_len;
            printf("t('%d 1-KAE %.3f %.3fGB/s 0 0 0 %.2fs %.2fus %.2fus %.2fus %.2fus %.2fus %.2fus %.2fus %d+1') \n",
                g_file_chunk_size,
                this_rate,
                speed1 / 1024,
                time1 / 1000000.0,
                get_average_latency(ctx->all_delays, ctx->sn),
                resp_latencies[0],
                resp_latencies[1],
                resp_latencies[2],
                resp_latencies[3],
                resp_latencies[4],
                resp_latencies[5],
                kae_task_num);
        }
    }

    double compress_rate = (double)src_len * ctx->loop_times / ctx->out_total_len;
    fprintf(stdout, "compress_size is %luB = %.3lfMB, compress_rate is %.3f\n",
        ctx->out_total_len, 1.0 * (float)ctx->out_total_len / (1 << 20), compress_rate);
    if (out_filename && ctx->thread_id == 0) {
        write_outputFile(out_filename, &(ctx->out_buf_list), ctx->sn / ctx->loop_times);
    }
}

static int wait_for_all_fork_done()
{
    int ret = -1;
    while (1) {
        ret = wait(NULL);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
    }
    return 0;
}

static int do_comp_and_decomp_with_full_file(
    struct compress_ctx *ctx, void *inbuf, uLong src_len, void *outbuf, uLong output_sz, unsigned long *out_offset)
{
    struct compress_param *param = NULL;

    while (ctx->param_buf[ctx->param_index].done != 0) {
        compress_async_polling(&ctx->param_buf[ctx->param_index]);
    }
    param = &ctx->param_buf[ctx->param_index];
    ctx->param_index = (ctx->param_index + 1) % ctx->inflight_num;
    // 单次接口调用时延
    if (g_log_level == 1) {
        param->start_time = get_ns();
    }
    param->done = 2;
    param->ctx = ctx;
    param->sn = ctx->sn;
    param->loop_index = ctx->loop_index;

    uLong output_sz_tmp = output_sz;
    void *dst_start = outbuf + *out_offset;
    param->dst.buf_num = 1;
    param->dst.buf = param->dst_buf;
    param->dst.buf[0].data = dst_start;
    param->dst.buf[0].buf_len = output_sz_tmp;
    param->src.buf_num = ctx->src_buf_num;
    param->src.buf = param->src_buf;
    unsigned int tmp_size = src_len / param->src.buf_num;
    for (int i = 0; i < param->src.buf_num - 1; i++) {
        param->src.buf[i].data = inbuf + tmp_size * i;
        param->src.buf[i].buf_len = tmp_size;
    }
    param->src.buf[param->src.buf_num - 1].data = inbuf + tmp_size * (param->src.buf_num - 1);
    param->src.buf[param->src.buf_num - 1].buf_len = src_len - tmp_size * (param->src.buf_num - 1);
    param->src.usr_data = ctx->page_info;
    param->src_len = src_len;
    param->ibuf_crc = 0;
    param->obuf_crc = 0;
    if (ctx->with_crc == 1) {
        param->result.ibuf_crc = &param->ibuf_crc;
        param->result.obuf_crc = &param->obuf_crc;
    } else {
        param->result.ibuf_crc = NULL;
        param->result.obuf_crc = NULL;
    }
    param->result.user_data = param;
    param->result.src_size = src_len;
    param->result.dst_len = output_sz_tmp;
    int ret = do_real_compression(ctx, &param->src, (unsigned int *)&src_len, &param->dst, (unsigned int *)&output_sz_tmp, &param->result);
    if (ctx->algorithm->async_compress == NULL || (ctx->compress_or_decompress == 0 && ctx->algorithm->async_decompress == NULL)) {
        param->result.dst_len = output_sz_tmp;
        compress_async_callback(&param->result);
    }
    ctx->sn++;
    return ret;
}
static int do_comp_with_split_file(
    struct compress_ctx *ctx, void *inbuf, uLong src_len, void *outbuf, uLong output_sz, unsigned long *out_offset)
{
    int ret = 0;
    unsigned int remaining = src_len;
    int chunk_size = g_file_chunk_size * 1024;

    void *start_buf = inbuf;
    while (remaining > 0) {
        struct compress_param *param = NULL;

        while (ctx->param_buf[ctx->param_index].done != 0) {
            compress_async_polling(&ctx->param_buf[ctx->param_index]);
        }
        param = &ctx->param_buf[ctx->param_index];
        ctx->param_index = (ctx->param_index + 1) % ctx->inflight_num;
        // 单次接口调用时延
        if (g_log_level == 1) {
            param->start_time = get_ns();
        }
        param->done = 2;
        param->ctx = ctx;
        param->sn = ctx->sn;
        param->loop_index = ctx->loop_index;
        unsigned int chunk_src_len = (remaining > chunk_size) ? chunk_size : remaining;
        unsigned int chunk_len_this_loop = chunk_src_len;  // chunk_src_len 作为 src_len 传入压缩解压函数，可能会被修改

        unsigned int output_size_chunk = ctx->algorithm->bound(chunk_size);  // 实际本次压缩后产物的长度
        output_size_chunk += 4;
        output_size_chunk -= output_size_chunk % 4;
        uLong output_sz_tmp = output_size_chunk;
        void *dst_start = outbuf + *out_offset;  // 使用总内存里面的部分空间
        param->dst.buf_num = 1;
        param->dst.buf = param->dst_buf;
        param->dst.buf[0].data = dst_start;
        param->dst.buf[0].buf_len = output_sz_tmp;
        param->src.buf_num = ctx->src_buf_num;
        param->src.buf = param->src_buf;
        param->src.usr_data = ctx->page_info;
        unsigned int tmp_size = chunk_len_this_loop / param->src.buf_num;
        size_t tmp_offset = 0;
        for (int i = 0; i < param->src.buf_num; i++) {
            param->src.buf[i].data = start_buf + tmp_offset;
            if (((start_buf - inbuf + tmp_offset) % HPAGE_SIZE) + tmp_size <= HPAGE_SIZE) {
                param->src.buf[i].buf_len = tmp_size;
            } else {
                param->src.buf[i].buf_len = HPAGE_SIZE - ((start_buf - inbuf + tmp_offset) % HPAGE_SIZE);
            }
            tmp_offset += param->src.buf[i].buf_len;
        }

        if (tmp_offset < chunk_len_this_loop) {
            param->src.buf[param->src.buf_num].data = start_buf + tmp_offset;
            param->src.buf[param->src.buf_num].buf_len = chunk_len_this_loop - tmp_offset;
            param->src.buf_num++;
        }
        param->src_len = chunk_len_this_loop;
        param->ibuf_crc = 0;
        param->obuf_crc = 0;
        if (ctx->with_crc == 1) {
            param->result.ibuf_crc = &param->ibuf_crc;
            param->result.obuf_crc = &param->obuf_crc;
        } else {
            param->result.ibuf_crc = NULL;
            param->result.obuf_crc = NULL;
        }
        param->result.user_data = param;
        param->result.src_size = chunk_len_this_loop;
        param->result.dst_len = output_sz_tmp;
        if (!ctx->is_lz77_mode) {
            ret = do_real_compression(
                ctx, &param->src, (unsigned int *)&chunk_len_this_loop, &param->dst, (unsigned int *)&output_sz_tmp, &param->result);
        } else {
            param->tuple.buf_num = 1;
            param->tuple.buf = param->tuple_buf;
            param->tuple.buf[0].data = ctx->tuple_buf + ctx->tuple_buf_offset;
            param->tuple.buf[0].buf_len = KAELZ4_compress_get_tuple_buf_len(chunk_len_this_loop);
            param->tuple.usr_data = ctx->tuple_page_info;
            ctx->tuple_buf_offset += param->tuple.buf[0].buf_len;
            if (ctx->tuple_buf_offset > ctx->tuple_buf_len) {
                printf("ctx->tuple_buf_offset[0x%lx] > ctx->tuple_buf_len[0x%lx]\n", ctx->tuple_buf_offset, ctx->tuple_buf_len);
                return -1;
            }
            ret = do_real_compression(ctx, &param->src, (unsigned int *)&chunk_len_this_loop, &param->tuple, (unsigned int *)&output_sz_tmp, &param->result);
        }
        if (ret != 0) {
            printf("Error: do_real_compression error. ret = %d \nexit\n", ret);
            return ret;
        }
        if (ctx->algorithm->async_compress == NULL || (ctx->compress_or_decompress == 0 && ctx->algorithm->async_decompress == NULL)) {
            param->result.dst_len = output_sz_tmp;
            compress_async_callback(&param->result);
        }
        ctx->sn++;

        // 更新输入和剩余长度
        start_buf += chunk_len_this_loop;
        remaining -= chunk_len_this_loop;
        *out_offset += output_size_chunk;
    }
    return ret;
}

static int prepare_tuple_buf(struct compress_ctx *ctx, size_t src_len)
{
    size_t tuple_buf_len = KAELZ4_compress_get_tuple_buf_len(g_file_chunk_size * 1024) * (src_len / (g_file_chunk_size * 1024) + 1) * 2;
    size_t huge_page_num = tuple_buf_len * sizeof(Bytef) / HPAGE_SIZE + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
    size_t total_size = huge_page_num * HPAGE_SIZE;
    ctx->tuple_buf = get_huge_pages(total_size);
    printf("申请的tuple buf大页虚拟地址: %p len: 0x%lx\n", ctx->tuple_buf, total_size);

    if (ctx->tuple_buf == NULL) {
        return -1;
    }

    memset(ctx->tuple_buf, 0, total_size);

    struct cache_page_map* cache = init_cache_page_map(ctx->tuple_buf, total_size);
    if (cache == NULL) {
        printf("init_cache_page_map failed\n");
        return -1;
    }
    uint64_t phys_addr = get_physical_address_cache_page_map(cache, ctx->tuple_buf);

    printf("tuple buf大页物理地址: 0x%" PRIx64 "\n", phys_addr);
    ctx->tuple_page_info = cache;
    ctx->tuple_buf_offset = 0;
    ctx->tuple_buf_len = tuple_buf_len;
    return 0;
}

static int start_work(struct compress_ctx *ctx, const char* in_filename, const char* out_filename, int multi,
                      int window_bits, int level)
{
    void *inbuf = NULL;
    uLong src_len = get_src_content(ctx, in_filename, &inbuf);
    // fprintf(stdout, "input_size is %luB\n", src_len);
    ctx->src_buf = inbuf;
    ctx->src_len = src_len;
    if (multi == 0) { multi = 1; }

    int ret = 0;
    int i, j;
    pid_t pid_child = 1;
    fflush(stdout);
    fflush(stderr);

    for (i = 0; i < multi - 1; i++) {
        pid_child = fork();
        if (pid_child == 0 || pid_child == -1) {
            if (g_config_bind_cpus_count > 0) {
                set_cpu_affinity_for_child(i, 1);
            }
            break;
        }
    }
    // 单进程下测试时不给唯一的父进程绑核。
    if (pid_child > 0) {
        if (g_config_bind_cpus_count > 0 && multi > 1) {
            set_cpu_affinity_for_child(multi - 1, 1);
        }
    }

    iova_map_fn usr_map = NULL;
    if (ctx->src_buf_num != 1)
        usr_map = get_physical_address_wrapper;

    if (g_enable_polling_mode) {
        ctx->sess = KAELZ4_create_async_compress_session(usr_map);
    } else {
        LZ4_async_compress_init(usr_map);
    }

    uLong output_sz;
    if(ctx->compress_or_decompress) { // 压缩空间预估理论上不同算法各有自己的计算规则
        if (ctx->algorithm->bound) {
            output_sz = ctx->algorithm->bound(src_len);
        } else {
            output_sz = compressBound(src_len) * 2; // 这是zlib的压缩后空间测算
        }
        output_sz *= 2;
    } else { // 解压极端情况：1、压缩率超高，需要最大250倍以上的空间。 2、压缩率超低，需要的空间最大不超过1G
        output_sz = MIN(src_len * 300, 1*1024*1024*1024);
    }
    // tips: 对文件分片压缩时,此处针对整体文件预估的空间是不足的。在循环次数较多时，空间会不够，可以继续增大。
    void *outbuf = malloc(output_sz * sizeof(uint8_t) * 2);
    if (outbuf == NULL) {
        printf("Error: 申请解压空间失败: %.3f G \n", 1.0 * (output_sz * sizeof(uint8_t) * ctx->loop_times)/(1 << 30) );
        return -1;
    }

    if (ctx->is_lz77_mode) {
        if (prepare_tuple_buf(ctx, src_len) != 0) {
            return -1;
        }
    }

    struct timeval start, stop;
    gettimeofday(&start, NULL);
    unsigned long out_offset = 0; // 用于选择 outbuf 填充数据的偏移值。
    // 要循环压缩解压多少次
    for (j = 0; j < ctx->loop_times; j++) {
        ctx->loop_index = j;
        if (j > 0) { // 为第1次之后的循环的产物复用空间
            out_offset = output_sz;
            ctx->tuple_buf_offset = ctx->tuple_buf_len / 2;
        }
        if (g_file_chunk_size != 0) { // 分片逻辑
            ret = do_comp_with_split_file(ctx, inbuf, src_len, outbuf, output_sz, &out_offset);
        } else { // 原始文件整体丢入
            ret = do_comp_and_decomp_with_full_file(ctx, inbuf, src_len, outbuf, output_sz, &out_offset);
        }
        if(ret < 0) {
            printf("Error: 压缩解压失败 ret=%d \n", ret);
        }
    }

    while (ctx->sn != ctx->finish_num) {
        while (ctx->param_buf[ctx->param_index].done != 0) {
            compress_async_polling(&ctx->param_buf[ctx->param_index]);
        }

        ctx->param_index = (ctx->param_index + 1) % ctx->inflight_num;
    }

    if (pid_child > 0 && ret >= 0) {
        ret = wait_for_all_fork_done();

        printf_perf_data(ctx, start, stop, src_len, in_filename, out_filename, multi);
        printf("\nall process done====================。 \n \n");
    }

    if (g_enable_huge_pages) {
        int huge_page_num = (int)(src_len * sizeof(Bytef) / HPAGE_SIZE) + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
        size_t total_size = huge_page_num * HPAGE_SIZE;
        release_huge_pages(inbuf, total_size);
    } else {
        free(inbuf);
    }
    free(outbuf);

    return ret;
}
static int start_work_decompress(
    struct compress_ctx *ctx, const char *in_filename, const char *out_filename, int multi, int window_bits, int level);
static void *start_work_thread(void *arg)
{
    struct thread_compress_args *args = (struct thread_compress_args *)arg;
    struct compress_ctx *ctx = &args->ctx;
    const char *in_filename = args->in_filename;
    const char *out_filename = args->out_filename;
    int multi = args->multi;
    int window_bits = args->window_bits;
    int level = args->level;
    if (ctx->compress_or_decompress || g_file_chunk_size == 0)
        start_work(ctx, in_filename, out_filename, multi, window_bits, level);
    else
        start_work_decompress(ctx, in_filename, out_filename, multi, window_bits, level);

    compress_ctx_destory(&args->ctx);
    free(args);  // 释放 args
    return NULL;
}
// 分片解压。
// 读取本地源数据信息。读取本地总文件信息。逐个块解压 --> 写文件拼接到一起
static int start_work_decompress(
    struct compress_ctx *ctx, const char *in_filename, const char *out_filename, int multi, int window_bits, int level)
{
    void *inbuf = NULL;
    uLong src_len = get_src_content(ctx, in_filename, &inbuf);

    // 从文件读取元数据
    struct fragment_metadata *loaded_fragments = NULL;
    unsigned int fragment_count;
    load_metadata_from_file(in_filename, &loaded_fragments, &fragment_count);
    // // // 打印读取的元数据
    // for (unsigned int i = 0; i < fragment_count; i++) {
    //     printf("Fragment %d: Offset = %u, Length = %u\n", i + 1, loaded_fragments[i].offset, loaded_fragments[i].len);
    // }

    ctx->src_buf = inbuf;
    ctx->src_len = src_len;
    if (multi == 0) { multi = 1; }

    uLong output_sz = MIN(src_len * 300, 1*1024*1024*1024);
    void *outbuf = malloc(output_sz * sizeof(uint8_t) * 2);
    if (outbuf == NULL) {
        printf("Error: 申请解压空间失败: %.3f G \n", 1.0 * (output_sz * sizeof(uint8_t) * ctx->loop_times)/(1 << 30) );
        return -1;
    }

    int ret;
    int i, j;
    pid_t pid_child = 1;
    fflush(stdout);
    fflush(stderr);

    for (i = 0; i < multi - 1; i++) {
        pid_child = fork();
        if (pid_child == 0 || pid_child == -1) {
            break;
        }
    }

    if (ctx->src_buf_num != 1)
        LZ4_async_compress_init(get_physical_address_wrapper);
    else
        LZ4_async_compress_init(NULL);

    struct timeval start, stop;
    gettimeofday(&start, NULL);

    size_t out_offset = 0; // 总内存中的偏移，每一小块儿使用不同的偏移。
    // 解压仅1次
    for (j = 0; j < ctx->loop_times; j++) {
        if (j > 0) { // 为第1次之后的循环的产物复用空间
            out_offset = output_sz;
        }
        if (g_file_chunk_size != 0) { // 分片逻辑
            for (int k = 0; k < fragment_count; k++) {
                size_t this_offset = loaded_fragments[k].offset;
                size_t this_src_len = loaded_fragments[k].len;

                struct compress_param *param = NULL;

                while (ctx->param_buf[ctx->param_index].done != 0) {
                    compress_async_polling(&ctx->param_buf[ctx->param_index]);
                }
                param = &ctx->param_buf[ctx->param_index];
                ctx->param_index = (ctx->param_index + 1) % ctx->inflight_num;
                // 单次接口调用时延
                if (g_log_level == 1) {
                    param->start_time = get_ns();
                }
                param->done = 2;
                param->ctx = ctx;
                param->sn = ctx->sn;
                param->loop_index = j;

                size_t output_size_chunk = MIN(this_src_len * 300, 1*1024*1024*1024); // 预估本次压缩后产物的长度
                void *dst_start = outbuf + out_offset;  // 使用总内存里面的部分空间
                param->dst.buf_num = 1;
                param->dst.buf = param->dst_buf;
                param->dst.buf[0].data = dst_start;
                param->dst.buf[0].buf_len = output_size_chunk;
                param->src.buf_num = 1;
                param->src.buf = param->src_buf;
                param->src.buf[0].data = inbuf + this_offset;
                param->src.buf[0].buf_len = this_src_len;
                param->src_len = this_src_len;
                param->ibuf_crc = 0;
                param->obuf_crc = 0;
                if (ctx->with_crc == 1) {
                    param->result.ibuf_crc = &param->ibuf_crc;
                    param->result.obuf_crc = &param->obuf_crc;
                } else {
                    param->result.ibuf_crc = NULL;
                    param->result.obuf_crc = NULL;
                }
                param->result.user_data = param;
                param->result.src_size = this_src_len;
                param->result.dst_len = output_size_chunk;
                ret = do_real_compression(ctx, &param->src, (unsigned int *)&this_src_len,
                                          &param->dst, (unsigned int *)&output_size_chunk, &param->result);

                if(ret != 0) {
                    printf("Error: sn %d len=%d;offset=%lx. end=%lx.do_real_compression decomp error. ret = %d \nexit\n ",
                           param->sn, loaded_fragments[k].len, this_offset, this_offset +  loaded_fragments[k].len, ret);
                    write_outputFile_2(
                        "./error-split-file-compressed-data.compressed", inbuf + this_offset, loaded_fragments[k].len);
                    return ret;
                }
                if (ctx->algorithm->async_compress == NULL || (ctx->compress_or_decompress == 0 && ctx->algorithm->async_decompress == NULL)) {
                    param->result.dst_len = output_size_chunk;
                    compress_async_callback(&param->result);
                }
                ctx->sn++;

                if (ctx->compress_or_decompress == 0 && ctx->algorithm->async_decompress && g_file_chunk_size) {
                    output_size_chunk = g_file_chunk_size * 1024 * 2;
                }
                out_offset += output_size_chunk; // 偏移本次解压实际使用的空间
            }
        }
    }

    while (ctx->sn != ctx->finish_num) {
        while (ctx->param_buf[ctx->param_index].done != 0) {
            compress_async_polling(&ctx->param_buf[ctx->param_index]);
        }

        ctx->param_index = (ctx->param_index + 1) % ctx->inflight_num;
    }

    if (pid_child > 0) {
        ret = wait_for_all_fork_done();

        printf_perf_data(ctx, start, stop, src_len, in_filename, out_filename, multi);
        printf("\nall decompress done==================== \n \n");
    }
    if (g_enable_huge_pages) {
        int huge_page_num = (int)(src_len * sizeof(Bytef) / HPAGE_SIZE) + 1; // 大页大小为2M，申请大页时申请大小需为大页大小的整数倍
        size_t total_size = huge_page_num * HPAGE_SIZE;
        release_huge_pages(inbuf, total_size);
    } else {
        free(inbuf);
    }
    free(outbuf);

    return ret;
}
static void format_cpu_env(char *str)
{
    char *token = strtok(str, "-");
    int count = 0;

    while (token != NULL) {
        count++;
        if (count == 3) {
            // 获取第3个字段并转换为整数
            g_cpu_threads_per_core = atoi(token);
            break;  // 一旦获取到第3个字段，跳出循环
        }
        token = strtok(NULL, "-");
    }
}
static void auto_get_parent_cpu_affinity(int *arr, int *count)
{
    // 子线程中获取父进程的亲和性
    cpu_set_t parent_affinity;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &parent_affinity) == -1) {
        perror("sched_getaffinity");
        return;
    }
    // 打印父进程的亲和性
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &parent_affinity)) {
            arr[(*count)++] = i;
        }
    }
}

static void init_env_config()
{
    char *taskset_cpu_config = getenv("USER_BIND_CPU_CONFIG");
    if (taskset_cpu_config != NULL) {
        parseTasksetLists(taskset_cpu_config, g_taskset_cpus_arr, &g_config_bind_cpus_count);
    } else {
        auto_get_parent_cpu_affinity(g_taskset_cpus_arr, &g_config_bind_cpus_count);
    }
}

int compare_files(char *file_un, char *file_de) {
    FILE* file1 = fopen(file_un, "rb");
    FILE* file2 = fopen(file_de, "rb");
    int result = 0;
    while (1) {
        char byte1 = fgetc(file1); // 从文件中读取一个字节
        char byte2 = fgetc(file2);

        if (byte1 != byte2) { // 读出字节不同，文件内容不同
            result = 1;
            break;
        }

        if (feof(file1) || feof(file2)) {
            break; // 任意一个文件到达末尾
        }
    }
        // 检查两个文件是否同时到达末尾
    if (!feof(file1) || !feof(file2)) {
        result = 1; // 文件长度不同，内容不同
    }

    fclose(file1);
    fclose(file2);
    return result;
}

int round_trip_fuzztest(uint32_t RDGseed)
{
    uint64_t RDGsize = 64 * 1024; // 默认值64K
    double RDGlitProba = 0.0; // lit分布概率，一般不用改
    int RGDproba = 50; // 数据可压缩程度 0-100

    int compress = 1;
    int ret = 0;
    int multi = 1;
    int threadNum = 1;
    int loop_times = 1000;
    int inflight_num = 256;
    uLong chunk_len = 1024;
    int window_bits = 15;
    int level = 1;

    char algorithm_name[25] = {0};

 // Fuzz 测试循环次数
    uint64_t run_times = 104104 * 2;

    char *algorithm_options[2] = {"kaelz4async_block", "kaelz4async_frame"};
    int file_chunk_size_options[13] = {2 KB, 4 KB, 8 KB, 16 KB, 32 KB, 64 KB, 128 KB, 256 KB, 512 KB, 1 MB, 2 MB, 4 MB, 8 MB};
    int random_data_size_options[13] = {16 KB, 32 KB, 64 KB, 64 KB + 5, 96 KB, 128 KB, 128 KB + 5, 512 KB, 1 MB, 4 MB, 16 MB, 64 MB, 128 MB};
    int compress_proba_options[11] = {0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    int muti_options[1] = {1};
    int threadNum_options[1] = {1};
    int loop_times_options[4] = {1, 1000, 2000, 5000};
    int inflight_num_options[7] = {24, 48, 64, 128, 256, 512, 1024};

    int params_num = 8;
    int option_counts[8] = {2, 13, 13, 11, 1, 1, 4, 7}; // 每个参数的选项数量
    int indices[8] = {0}; // 每个参数的当前选项索引

    for (int i = 0; i < run_times; ++i) {

        compress = (i + 1) % 2; // 先压缩后解压
        char* input_filename = (compress == 1) ? "uncomp_data" : "comped_data";
        char* output_filename = (compress == 1) ? "comped_data" : "decomp_data";

        // 迭代法遍历各种参数组合
        if (compress == 1) { // 每次测试压缩时读入参数，解压时维持压缩时参数
            strcpy(algorithm_name, algorithm_options[indices[0]]);
            g_file_chunk_size = file_chunk_size_options[indices[1]];
            g_file_chunk_size /= 1024; // 转换成KB
            RDGsize = random_data_size_options[indices[2]];
            RGDproba = compress_proba_options[indices[3]];
            multi = muti_options[indices[4]];
            threadNum = threadNum_options[indices[5]];
            loop_times = loop_times_options[indices[6]];
            inflight_num = inflight_num_options[indices[7]];

            // 生成随机数据
            char *RDGbuffer = (char *)malloc(RDGsize);

            RDG_genBuffer(RDGbuffer, RDGsize, (double)(RGDproba / 100), RDGlitProba, RDGseed);
            FILE *file_in = fopen(input_filename, "wb");

            size_t written = fwrite(RDGbuffer, sizeof(char), RDGsize, file_in);
            if (written != RDGsize) {
                printf("Error: write file failed\n");
                return 0;
            }
            fclose(file_in);
            free(RDGbuffer);
            // 更新迭代索引
            int j = params_num - 1;
            while(j >= 0) {
                indices[j]++;
                if (indices[j] < option_counts[j]) {
                    break;
                }
                indices[j] = 0;
                j--;
            }
            if (j < 0) {
                printf("seed : %d Fuzz test done, seed + 1.\n", RDGseed);
                ++RDGseed;
            }
        }

        const char* in_filename  = input_filename;
        const char* out_filename = output_filename;
        chunk_len *= 1024;
        printf("kzip fuzz test: algorithm: %s, multi process %d, threadNum %d, data length: %lu(KB), loop times: %d, window_bits : %d, level : %d, chunk: %d(KB), %s, in_file : %s, out_file : %s,\n",
                algorithm_name, multi, threadNum, RDGsize/1024, loop_times, window_bits, level, g_file_chunk_size, compress == 1 ? "compress" : "decompress", in_filename, out_filename);

        compression_algorithm_t *algorithm = get_algorithm(algorithm_name);
        if (!algorithm) {
            printf("Error: Algorithm %s not found.\n", algorithm_name);
            return -1;
        }
        struct compress_ctx ctx;
        compress_ctx_init(&ctx, compress, inflight_num, chunk_len, algorithm, 0);
        ctx.loop_times = loop_times;
        if (!ctx.compress_or_decompress) {
            ctx.loop_times = 1;
            multi = 1;
        }
        LZ4_async_compress_init(NULL);
        if (!ctx.compress_or_decompress && g_file_chunk_size > 0) { // 如果是分片解压，单独处理
            ret = start_work_decompress(&ctx, in_filename, out_filename, multi, window_bits, level);
        } else {
            if (threadNum > 1) {
                pthread_t threads[threadNum];
                int j;
                for (j = 0; j < threadNum; j++) {
                    struct thread_compress_args *args = malloc(sizeof(struct thread_compress_args));
                    compress_ctx_init(&args->ctx, compress, inflight_num, chunk_len, algorithm, 0);
                    args->ctx.thread_id = j;
                    args->ctx.loop_times = loop_times;
                    args->in_filename = in_filename;
                    args->out_filename = out_filename;
                    args->multi = multi;
                    args->window_bits = window_bits;
                    args->level = level;
                    if (pthread_create(&threads[j], NULL, start_work_thread, args) != 0) {
                        perror("pthread_create failed");
                        exit(EXIT_FAILURE);
                    }
                }
                for (j = 0; j < threadNum; j++) {
                    pthread_join(threads[j], NULL);
                }
            } else {
                ret = start_work(&ctx, in_filename, out_filename, multi, window_bits, level);
            }
        }
        if (ret < 0) {
            printf("kzip fuzz failed ! seed : %u, %s, file : %s\n", RDGseed, compress == 1 ? "compress" : "decompress", in_filename);
            return ret;
        }
        if (!compress) { // 解压后比较两个文件内容是否一致
            ret = compare_files("uncomp_data", "decomp_data"); // 返回值1时表示文件不同，返回值0时表示文件相同
            if (ret != 0) {
                printf("Error: find difference between uncomp_data and decomp_data! \n");
                compress_ctx_destory(&ctx);
                return ret;
            }
        }
        compress_ctx_destory(&ctx);
    }
    printf("kzip fuzz test done. all test succeess.\n");
    return ret;
}

static void usage(void)
{
    printf("usage: \n");
    printf("  -A: set algorithm type(kaelz4|kaelz4_frame|kaelz4async_block|kaelz4async_frame). default is kaelz4\n");
    printf("  -d: compress or decompress\n");
    printf("  -m: multi process. default is 2. use fork() to start multi process\n");
    printf("  -t: thread num. default is 1. if thread num > 1, use pthread_create for multi compression. \n");
    printf("  -i: inflight num for calling async compression at same time. default 16\n");
    printf("  -f: input  filename(-l useless if this work)\n");
    printf("  -g:  show delay data in compression results or not. default: 0\n");
    printf("  -o: output filename\n");
    printf("  -n: loop times\n");
    printf("  -s: input file split chunk size(KB)\n");
    printf("  -F: start fuzz test, and set random data seed, default seed : 0 \n");
    printf("  -P: use Huge Pages to save uncompress data \n");
    printf("  -p: use polling mode to wait for async operation done\n");
    printf("  -r: take crc32 checksum when data is callback.default: 0 \n");
    printf("  example: ./kzip -A kaelz4 -m 2 -f ./kzip -o ./kzip.compressd -n 1000\n");
    printf("           ./kzip -A kaelz4 -d -m 2  -f ./kzip.compressd -o ./kzip.origin  -n 1000\n");
}
int main(int argc, char **argv)
{
    // 初始化所有算法
    initialize_algorithms();
    init_env_config();

    const char *optstring = "dm:l:n:w:f:o:v:A:hg:s:c:i:t:T:F:r:P:p:";
    int ret = 0;
    int o = 0;
    int multi = 1;
    int level = 6;
    uLong chunk_len = 1024;
    int loop_times = 1000;
    int compress = 1;
    int window_bits = 15;
    char input_filename[64] = {0};
    char output_filename[64] = {0};
    char algorithm_name[25] = "kaelz4";
    char cpuConfigStr[20] = "4-40-1-4"; // 默认的920B配置：未开超线程，使用全部的4个加速器。
    int inflight_num = 256;
    int threadNum = 1;
    int isSceneTest = 0;
    // Fuzz RDG
    int fuzztest = 0;
    uint32_t RDGseed = 0; // 随机数据生成种子
    int is_test_crc = 0; // 是否每次都带上crc32校验值

    while ((o = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (o) {
            case 'A':
                strcpy(algorithm_name, optarg);
                break;
            case 'c':
                strcpy(cpuConfigStr, optarg);
                break;
            case 'd':
                compress = 0;
                break;
            case 'F':
                fuzztest = 1;
                RDGseed = (uint32_t)atoi(optarg);
                break;
            case 'f':
                strcpy(input_filename, optarg);
                break;
            case 'g':
                g_log_level = atoi(optarg);
                break;
            case 'i':
                inflight_num = atoi(optarg);
                if (inflight_num > 1024)
                    inflight_num = 1024;
                break;
            case 'l':
                chunk_len = atoi(optarg);
                break;
            case 'm':
                multi = atoi(optarg);
                break;
            case 'n':
                loop_times = atoi(optarg);
                break;
            case 'o':
                strcpy(output_filename, optarg);
                break;
            case 'P':
                g_enable_huge_pages = 1;
                break;
            case 'p':
                g_enable_polling_mode = atoi(optarg);
                break;
	        case 'r':
                is_test_crc = atoi(optarg);
                break;
            case 's':
                g_file_chunk_size = atoi(optarg);
                break;
            case 'T':
                isSceneTest = atoi(optarg);
                break;
            case 't':
                threadNum = atoi(optarg);
                break;
	        case 'v':
                level = atoi(optarg);
                break;
            case 'w':
                window_bits = atoi(optarg);
                break;
            case 'h':
                usage();
                return 0;
        }
    }

    ret = vaild_algorithm(algorithm_name);
    if(ret != 0) { return ret; }

    if (argc <= 1) {
        usage();
        printf("\ndefault input parameter used\n");
    }
    format_cpu_env(cpuConfigStr);

    const char* in_filename  = input_filename[0] == 0 ? NULL : input_filename;
    const char* out_filename = output_filename[0]== 0 ? NULL : output_filename;
    chunk_len *= 1024;

    if (isSceneTest == 1) {
        return scene_tests_run();
    }
    if (fuzztest == 1) {
        ret = round_trip_fuzztest(RDGseed);
        return ret;
    }

    printf("kzip perf parameter: algorithm: %s, multi process %d, threadNum %d, stream length: %lu(KB), loop times: %d, window_bits : %d, level : %d, chunk: %d\n",
        algorithm_name, multi, threadNum, chunk_len/1024, loop_times, window_bits, level, g_file_chunk_size);

    // 获取用户指定的算法
    compression_algorithm_t *algorithm = get_algorithm(algorithm_name);

    if (!algorithm) {
        printf("Error: Algorithm %s not found.\n", algorithm_name);
        return -1;
    }

    struct compress_ctx ctx;
    compress_ctx_init(&ctx, compress, inflight_num, chunk_len, algorithm, is_test_crc);
    ctx.loop_times = loop_times;

    if (!ctx.compress_or_decompress && g_file_chunk_size > 0 && threadNum == 1) { // 如果是分片解压，单独处理
        ret = start_work_decompress(&ctx, in_filename, out_filename, multi, window_bits, level);
    } else {
        if (threadNum > 1) {
            pthread_t threads[threadNum];
            int j;
            for (j = 0; j < threadNum; j++) {
                struct thread_compress_args *args = malloc(sizeof(struct thread_compress_args));
                compress_ctx_init(&args->ctx, compress, inflight_num, chunk_len, algorithm, is_test_crc);
                args->ctx.thread_id = j;
                args->ctx.loop_times = loop_times;
                args->in_filename = in_filename;
                args->out_filename = out_filename;
                args->multi = multi;
                args->window_bits = window_bits;
                args->level = level;
                if (pthread_create(&threads[j], NULL, start_work_thread, args) != 0) {
                    perror("pthread_create failed");
                    exit(EXIT_FAILURE);
                }
            }
            for (j = 0; j < threadNum; j++) {
                pthread_join(threads[j], NULL);
            }
        } else {
           ret = start_work(&ctx, in_filename, out_filename, multi, window_bits, level);
        }
    }

    if (ctx.sess)
        KAELZ4_destroy_async_compress_session(ctx.sess);
    else
        LZ4_teardown_async_compress();

    compress_ctx_destory(&ctx);
    return ret;
}
