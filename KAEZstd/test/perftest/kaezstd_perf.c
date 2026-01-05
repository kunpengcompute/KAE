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
#include <zstd.h>      // presumes zstd library is installed
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "common.h"

enum CompressFunc {
    ZSTD_COMPRESS_STREAM2,
    ZSTD_COMPRESS,
};

enum TestMode {
    TEST_COMPRESS_ONLY = 0,
    TEST_DECOMPRESS_ONLY = 1,
    TEST_COMPRESS_DECOMPRESS = 2,
};

typedef struct {
    void* buffIn;
    void* buffOut;
    size_t buffInSize;
    size_t buffOutSize;
    ZSTD_CCtx* cctx;
    ZSTD_DCtx* dctx;
} resources;

typedef struct {
    int streamLen; // Original requested length, or file size
    int cLevel;
    int loopTimes;
    int core_id;
    int thread_id;
    int process_id;
    enum CompressFunc func;
    int test_mode;
    uint64_t bytes_processed;
    uint64_t time_us;
    
    // Shared buffers (Pre-allocated in main)
    const uint8_t* shared_inbuf;
    size_t shared_inSize;
    const uint8_t* shared_compressed_buf;
    size_t shared_compressed_size;
} ThreadArgs;

typedef struct {
    uint64_t total_bytes;
    uint64_t total_time_us;
    uint64_t min_time_us;
    uint64_t max_time_us;
    int worker_count;
    pthread_mutex_t mutex;
    int mutex_initialized;  // 标志mutex是否已初始化
} Statistics;

// 全局统计（用于多进程模式）
Statistics* g_stats = NULL;

uint8_t *CompressInputGet(size_t inputSize)
{
    uint8_t *inbuf = (uint8_t *)malloc(inputSize * sizeof(uint8_t));
    if (inbuf == NULL) {
        printf("%s  malloc failed\n", __func__);
        return NULL;
    }

    memset(inbuf, 0, inputSize);
    srand((unsigned int)time(NULL) + (unsigned int)getpid() + (unsigned int)pthread_self());
    size_t i = 0;
    for (i = 0; i < inputSize; i++) {
        inbuf[i] = (uint8_t)rand() % 254 + 1;
    }

    return inbuf;
}

static uint8_t* LoadFile(const char* filename, size_t* outSize)
{
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsize < 0) {
        fclose(f);
        fprintf(stderr, "Failed to get file size\n");
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(fsize);
    if (!buf) {
        fclose(f);
        fprintf(stderr, "Malloc failed for file content\n");
        return NULL;
    }
    
    size_t readSize = fread(buf, 1, fsize, f);
    fclose(f);
    
    if (readSize != (size_t)fsize) {
        free(buf);
        fprintf(stderr, "Failed to read full file\n");
        return NULL;
    }
    
    *outSize = (size_t)fsize;
    return buf;
}

static resources CompressCreateResources(uint8_t *inbuf, int streamLen, int cLevel)
{
    resources ress;
    ress.buffInSize = streamLen;
    ress.buffOutSize = ZSTD_compressBound(streamLen);
    ress.buffIn = inbuf;
    ress.buffOut = malloc_orDie(ress.buffOutSize);
    ress.cctx = ZSTD_createCCtx();
    CHECK(ress.cctx != NULL, "ZSTD_createCCtx() failed!");
    CHECK_ZSTD(ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_compressionLevel, cLevel));
    ress.dctx = NULL;
    return ress;
}

static resources DecompressCreateResources(size_t compressedSize)
{
    resources ress;
    ress.buffInSize = compressedSize;
    ress.buffOutSize = compressedSize * 2; // 解压后可能更大
    ress.buffIn = NULL;
    ress.buffOut = malloc_orDie(ress.buffOutSize);
    ress.cctx = NULL;
    ress.dctx = ZSTD_createDCtx();
    CHECK(ress.dctx != NULL, "ZSTD_createDCtx() failed!");
    return ress;
}

static resources CompressStreamCreateResources(int cLevel)
{
    resources ress;
    ress.buffInSize = ZSTD_CStreamInSize();
    ress.buffOutSize = ZSTD_CStreamOutSize();
    ress.buffIn = malloc_orDie(ress.buffInSize);
    ress.buffOut = malloc_orDie(ress.buffOutSize);
    ress.cctx = ZSTD_createCCtx();
    CHECK(ress.cctx != NULL, "ZSTD_createCCtx() failed!");
    CHECK_ZSTD(ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_compressionLevel, cLevel));
    CHECK_ZSTD(ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_checksumFlag, 1));
    ress.dctx = NULL;
    return ress;
}

static resources DecompressStreamCreateResources()
{
    resources ress;
    ress.buffInSize = ZSTD_DStreamInSize();
    ress.buffOutSize = ZSTD_DStreamOutSize();
    ress.buffIn = malloc_orDie(ress.buffInSize);
    ress.buffOut = malloc_orDie(ress.buffOutSize);
    ress.cctx = NULL;
    ress.dctx = ZSTD_createDCtx();
    CHECK(ress.dctx != NULL, "ZSTD_createDCtx() failed!");
    return ress;
}

static void FreeResources(resources ress)
{
    if (ress.cctx) {
        ZSTD_freeCCtx(ress.cctx);
    }
    if (ress.dctx) {
        ZSTD_freeDCtx(ress.dctx);
    }
    if (ress.buffIn && ress.cctx) { // Only free if allocated by us
        free(ress.buffIn);
    }
    if (ress.buffOut) {
        free(ress.buffOut);
    }
}

static size_t ReadFromInput(void *buffer, size_t sizeToRead, uint8_t *src, int totalBytesLeft)
{
    int cpySize = sizeToRead <= totalBytesLeft ? sizeToRead : totalBytesLeft;
    memcpy(buffer, src, cpySize);
    return cpySize;
}

// 块模式压缩
static size_t CompressBlock(uint8_t* inbuf, size_t inSize, uint8_t* outbuf, size_t outSize, int cLevel)
{
    ZSTD_CCtx* cctx = ZSTD_createCCtx();
    CHECK(cctx != NULL, "ZSTD_createCCtx() failed!");
    CHECK_ZSTD(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, cLevel));
    
    size_t const cSize = ZSTD_compressCCtx(cctx, outbuf, outSize, inbuf, inSize, cLevel);
    CHECK_ZSTD(cSize);
    
    ZSTD_freeCCtx(cctx);
    return cSize;
}

// 流模式压缩
static size_t CompressStream(uint8_t* inbuf, size_t inSize, uint8_t* outbuf, size_t outSize, int cLevel)
{
    resources ress = CompressStreamCreateResources(cLevel);
    size_t const toRead = ress.buffInSize;
    size_t read;
    uint8_t *src = inbuf;
    uint8_t *dst = outbuf;
    int totalBytesLeft = inSize;
    size_t totalOutputSize = 0;
    
    while ((read = ReadFromInput(ress.buffIn, toRead, src, totalBytesLeft))) {
        totalBytesLeft -= read;
        src += read;
        
        int const lastChunk = (read < toRead);
        ZSTD_EndDirective const mode = lastChunk ? ZSTD_e_end : ZSTD_e_continue;
        
        ZSTD_inBuffer input = { ress.buffIn, read, 0 };
        int finished;
        do {
            ZSTD_outBuffer output = { ress.buffOut, ress.buffOutSize, 0 };
            size_t const remaining = ZSTD_compressStream2(ress.cctx, &output, &input, mode);
            CHECK_ZSTD(remaining);
            if (totalOutputSize + output.pos > outSize) {
                fprintf(stderr, "Compressed output buffer too small\n");
                exit(1);
            }
            memcpy(dst, ress.buffOut, output.pos);
            dst += output.pos;
            totalOutputSize += output.pos;
            finished = lastChunk ? (remaining == 0) : (input.pos == input.size);
        } while (!finished);
        CHECK(input.pos == input.size,
              "Impossible: zstd only returns 0 when the input is completely consumed!");
    }
    
    FreeResources(ress);
    return totalOutputSize;
}

// 块模式解压
static size_t DecompressBlock(uint8_t* inbuf, size_t inSize, uint8_t* outbuf, size_t outSize)
{
    unsigned long long const rSize = ZSTD_getFrameContentSize(inbuf, inSize);
    CHECK(rSize != ZSTD_CONTENTSIZE_ERROR, "not compressed by zstd!");
    CHECK(rSize != ZSTD_CONTENTSIZE_UNKNOWN, "original size unknown!");
    CHECK((size_t)rSize <= outSize, "output buffer too small");
    
    size_t const dSize = ZSTD_decompress(outbuf, outSize, inbuf, inSize);
    CHECK_ZSTD(dSize);
    CHECK(dSize == (size_t)rSize, "Decompressed size mismatch!");
    
    return dSize;
}

// 流模式解压
static size_t DecompressStream(uint8_t* inbuf, size_t inSize, uint8_t* outbuf, size_t outSize)
{
    resources ress = DecompressStreamCreateResources();
    size_t const toRead = ress.buffInSize;
    size_t read;
    uint8_t *src = inbuf;
    uint8_t *dst = outbuf;
    int totalBytesLeft = inSize;
    size_t totalOutputSize = 0;
    size_t lastRet = 0;
    
    while ((read = ReadFromInput(ress.buffIn, toRead, src, totalBytesLeft))) {
        totalBytesLeft -= read;
        src += read;
        
        ZSTD_inBuffer input = { ress.buffIn, read, 0 };
        while (input.pos < input.size) {
            ZSTD_outBuffer output = { ress.buffOut, ress.buffOutSize, 0 };
            size_t const ret = ZSTD_decompressStream(ress.dctx, &output, &input);
            CHECK_ZSTD(ret);
            if (totalOutputSize + output.pos > outSize) {
                fprintf(stderr, "Decompressed output buffer too small\n");
                exit(1);
            }
            memcpy(dst, ress.buffOut, output.pos);
            dst += output.pos;
            totalOutputSize += output.pos;
            lastRet = ret;
        }
    }
    
    if (lastRet != 0) {
        fprintf(stderr, "EOF before end of stream: %zu\n", lastRet);
        exit(1);
    }
    
    FreeResources(ress);
    return totalOutputSize;
}

// 更新统计信息（线程安全，仅用于单进程多线程模式）
static void UpdateStatistics(Statistics* stats, uint64_t bytes, uint64_t time_us)
{
    if (stats == NULL) return;
    
    // 只在mutex已初始化时使用互斥锁
    if (stats->mutex_initialized) {
        pthread_mutex_lock(&stats->mutex);
    }
    stats->total_bytes += bytes;
    stats->total_time_us += time_us;
    if (stats->min_time_us == 0 || time_us < stats->min_time_us) {
        stats->min_time_us = time_us;
    }
    if (time_us > stats->max_time_us) {
        stats->max_time_us = time_us;
    }
    stats->worker_count++;
    if (stats->mutex_initialized) {
        pthread_mutex_unlock(&stats->mutex);
    }
}

// 线程工作函数
void* ThreadWorker(void* arg)
{
    ThreadArgs* args = (ThreadArgs*)arg;
    struct timeval start, end;
    uint64_t total_bytes = 0;
    
    // CPU亲和性设置
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(args->core_id, &cpuSet);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuSet), &cpuSet) == -1) {
        fprintf(stderr, "Thread %d: Failed to set CPU affinity to core %d\n", 
                args->thread_id, args->core_id);
    }
    
    // 预分配输出buffer，排除在计时之外
    uint8_t* local_compressed_buf = NULL;
    uint8_t* local_decompressed_buf = NULL;
    size_t max_compressed_size = ZSTD_compressBound(args->shared_inSize);
    size_t max_decompressed_size = args->shared_inSize * 2; // 安全裕量
    
    if (args->test_mode == TEST_COMPRESS_ONLY || args->test_mode == TEST_COMPRESS_DECOMPRESS) {
        local_compressed_buf = (uint8_t*)malloc(max_compressed_size);
        if (!local_compressed_buf) {
             fprintf(stderr, "Thread %d: Malloc failed for compressed buf\n", args->thread_id);
             return NULL;
        }
    }
    
    if (args->test_mode == TEST_DECOMPRESS_ONLY || args->test_mode == TEST_COMPRESS_DECOMPRESS) {
        local_decompressed_buf = (uint8_t*)malloc(max_decompressed_size);
        if (!local_decompressed_buf) {
             fprintf(stderr, "Thread %d: Malloc failed for decompressed buf\n", args->thread_id);
             if (local_compressed_buf) free(local_compressed_buf);
             return NULL;
        }
    }
    
    // 开始计时
    gettimeofday(&start, NULL);
    
    for (int i = 0; i < args->loopTimes; ++i) {
        size_t current_compressed_size = 0;

        if (args->test_mode == TEST_COMPRESS_ONLY || args->test_mode == TEST_COMPRESS_DECOMPRESS) {
            // 压缩
            if (args->func == ZSTD_COMPRESS) {
                current_compressed_size = CompressBlock((uint8_t*)args->shared_inbuf, args->shared_inSize, 
                                                      local_compressed_buf, max_compressed_size, args->cLevel);
            } else {
                current_compressed_size = CompressStream((uint8_t*)args->shared_inbuf, args->shared_inSize, 
                                                       local_compressed_buf, max_compressed_size, args->cLevel);
            }
            total_bytes += args->shared_inSize;
        }
        
        if (args->test_mode == TEST_DECOMPRESS_ONLY || args->test_mode == TEST_COMPRESS_DECOMPRESS) {
            // 解压
            const uint8_t* srcBuf;
            size_t srcSize;
            
            if (args->test_mode == TEST_DECOMPRESS_ONLY) {
                srcBuf = args->shared_compressed_buf;
                srcSize = args->shared_compressed_size;
            } else {
                srcBuf = local_compressed_buf;
                srcSize = current_compressed_size;
            }
            
            size_t decompressed_size = args->func == ZSTD_COMPRESS ?
                DecompressBlock((uint8_t*)srcBuf, srcSize, local_decompressed_buf, max_decompressed_size) :
                DecompressStream((uint8_t*)srcBuf, srcSize, local_decompressed_buf, max_decompressed_size);
            
            // 统计解压的数据量（通常统计压缩前的大小作为吞吐量基准，或者压缩后的大小）
            // 原代码使用 compressed_size。
            // 这里我们保持原代码逻辑，统计的是“处理的字节数”。对于解压，通常是输入字节数。
            total_bytes += srcSize;
            
            // 简单验证
            if (args->test_mode == TEST_DECOMPRESS_ONLY) {
                 // 如果是只解压模式，解压后应该等于原始大小
                 if (decompressed_size != args->shared_inSize) {
                      fprintf(stderr, "Thread %d: Decompression size mismatch\n", args->thread_id);
                      exit(1);
                 }
            } else {
                 if (decompressed_size != args->shared_inSize) {
                      fprintf(stderr, "Thread %d: Decompression size mismatch\n", args->thread_id);
                      exit(1);
                 }
            }
        }
    }
    
    gettimeofday(&end, NULL);
    
    // 清理线程局部buffer
    if (local_compressed_buf) free(local_compressed_buf);
    if (local_decompressed_buf) free(local_decompressed_buf);

    uint64_t time_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
    
    args->bytes_processed = total_bytes;
    args->time_us = time_us;
    
    // 更新统计信息
    if (g_stats != NULL) {
        UpdateStatistics(g_stats, total_bytes, time_us);
    }
    
    return NULL;
}

// 进程工作函数
void ProcessWorker(int process_id, int num_threads, int streamLen, int cLevel, 
                   int loopTimes, enum CompressFunc func, int test_mode, int start_core_id,
                   const uint8_t* shared_inbuf, size_t shared_inSize,
                   const uint8_t* shared_compressed_buf, size_t shared_compressed_size)
{
    pthread_t* threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
    ThreadArgs* thread_args = (ThreadArgs*)malloc(num_threads * sizeof(ThreadArgs));
    
    if (threads == NULL || thread_args == NULL) {
        fprintf(stderr, "Process %d: Failed to allocate memory\n", process_id);
        exit(1);
    }
    
    // 为每个线程创建独立的参数
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].streamLen = streamLen;
        thread_args[i].cLevel = cLevel;
        thread_args[i].loopTimes = loopTimes;
        thread_args[i].core_id = start_core_id + i;
        thread_args[i].thread_id = i;
        thread_args[i].process_id = process_id;
        thread_args[i].func = func;
        thread_args[i].test_mode = test_mode;
        thread_args[i].bytes_processed = 0;
        thread_args[i].time_us = 0;
        // 传递共享buffer
        thread_args[i].shared_inbuf = shared_inbuf;
        thread_args[i].shared_inSize = shared_inSize;
        thread_args[i].shared_compressed_buf = shared_compressed_buf;
        thread_args[i].shared_compressed_size = shared_compressed_size;
    }
    
    // 创建线程
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, ThreadWorker, &thread_args[i]) != 0) {
            fprintf(stderr, "Process %d: Failed to create thread %d\n", process_id, i);
            exit(1);
        }
    }
    
    // 等待所有线程完成
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    free(thread_args);
}

// 主测试函数
void DoTestPerf(int num_processes, int num_threads, int streamLen, int cLevel, 
                int loopTimes, enum CompressFunc func, int test_mode,
                const uint8_t* shared_inbuf, size_t shared_inSize,
                const uint8_t* shared_compressed_buf, size_t shared_compressed_size)
{
    struct timeval start, stop;
    pid_t* pids = NULL;
    int start_core_id = 35; // 默认起始CPU核心ID
    
    // 初始化统计结构
    if (num_processes == 0) {
        g_stats = (Statistics*)malloc(sizeof(Statistics));
        memset(g_stats, 0, sizeof(Statistics));
        pthread_mutex_init(&g_stats->mutex, NULL);
        g_stats->mutex_initialized = 1;
    } else {
        g_stats = NULL;
    }
    
    if (num_processes > 0) {
        // 多进程模式
        pids = (pid_t*)malloc(num_processes * sizeof(pid_t));
        if (pids == NULL) {
            fprintf(stderr, "Failed to allocate memory for process IDs\n");
            exit(1);
        }
        
        gettimeofday(&start, NULL);
        
        // 创建子进程
        for (int i = 0; i < num_processes; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                // 子进程
                ProcessWorker(i, num_threads, streamLen, cLevel, loopTimes, func, test_mode, 
                            start_core_id + i * num_threads,
                            shared_inbuf, shared_inSize, shared_compressed_buf, shared_compressed_size);
                exit(0);
            } else if (pid < 0) {
                fprintf(stderr, "Failed to fork process %d\n", i);
                exit(1);
            } else {
                pids[i] = pid;
            }
        }
        
        // 等待所有子进程完成
        for (int i = 0; i < num_processes; i++) {
            int status;
            waitpid(pids[i], &status, 0);
        }
        
        gettimeofday(&stop, NULL);
        free(pids);
    } else {
        // 单进程多线程模式
        gettimeofday(&start, NULL);
        ProcessWorker(0, num_threads, streamLen, cLevel, loopTimes, func, test_mode, start_core_id,
                      shared_inbuf, shared_inSize, shared_compressed_buf, shared_compressed_size);
        gettimeofday(&stop, NULL);
    }
    
    // 计算总耗时
    uint64_t total_time_us = (stop.tv_sec - start.tv_sec) * 1000000 + 
                            (stop.tv_usec - start.tv_usec);
    
    // 计算总数据量
    uint64_t total_bytes = 0;
    int total_workers = (num_processes > 0 ? num_processes : 1) * num_threads;
    
    // 重新计算总数据量：基于实际处理的数据
    // 注意：如果是Decompress Only，我们用的是 shared_compressed_size 作为输入
    // 如果是Compress Only，我们用的是 shared_inSize
    // 在这里简单估算，或者依赖 g_stats (单进程)
    
    if (num_processes == 0 && g_stats) {
        total_bytes = g_stats->total_bytes;
    } else {
        // 多进程模式下，我们无法直接获取准确的总字节数（除非用共享内存统计）
        // 所以这里还是使用理论值
        if (test_mode == TEST_COMPRESS_ONLY || test_mode == TEST_COMPRESS_DECOMPRESS) {
            total_bytes = (uint64_t)shared_inSize * loopTimes * total_workers;
            if (test_mode == TEST_COMPRESS_DECOMPRESS) {
                // 计算通量性能，暂时定义为：原始文件大小/压缩解压耗时
                total_bytes += (uint64_t)shared_inSize * loopTimes * total_workers;
            }
        } else {
            // Decompress only
            // 使用 shared_compressed_size
            total_bytes = (uint64_t)shared_inSize * loopTimes * total_workers;
        }
    }
    
    // 计算带宽
    double total_bandwidth_gbps = (double)total_bytes / total_time_us * 1000000.0 / (1 << 30);
    double avg_bandwidth_gbps = total_bandwidth_gbps / total_workers;
    
    // 输出统计信息
    const char* mode_str = (test_mode == TEST_COMPRESS_ONLY) ? "compress" :
                          (test_mode == TEST_DECOMPRESS_ONLY) ? "decompress" : "compress+decompress";
    const char* func_str = (func == ZSTD_COMPRESS) ? "block" : "stream";
    
    printf("\n=== kaezstd performance test results ===\n");
    printf("Test mode: %s (%s)\n", mode_str, func_str);
    printf("Processes: %d, Threads per process: %d, Total workers: %d\n", 
           num_processes > 0 ? num_processes : 1, num_threads, total_workers);
    printf("Stream length: %zu bytes, Loop times: %d, Compression level: %d\n",
           shared_inSize, loopTimes, cLevel);
    printf("Total time: %lu us (%.3f s)\n", total_time_us, total_time_us / 1000000.0);
    printf("Total data processed: %.3f GB\n", (double)total_bytes / (1 << 30));
    printf("Total bandwidth: %.3f GB/s\n", total_bandwidth_gbps);
    printf("Average bandwidth per worker: %.3f GB/s\n", avg_bandwidth_gbps);
    if (g_stats && g_stats->worker_count > 0) {
        printf("Workers reported: %d\n", g_stats->worker_count);
        if (g_stats->min_time_us > 0) {
            printf("Min worker time: %lu us, Max worker time: %lu us\n",
                   g_stats->min_time_us, g_stats->max_time_us);
        }
    }
    printf("========================================\n\n");
    
    // 清理统计结构
    if (num_processes == 0 && g_stats != NULL && g_stats->mutex_initialized) {
        pthread_mutex_destroy(&g_stats->mutex);
        free(g_stats);
    }
    g_stats = NULL;
}

static void Usage(void)
{
    printf("usage: \n");
    printf("  -p: number of processes (default 0, single process mode)\n");
    printf("  -t: number of threads per process (default 4)\n");
    printf("  -l: stream length(KB) (ignored if -i is used)\n");
    printf("  -n: loop times\n");
    printf("  -c: compression level\n");
    printf("  -f: compression function\n");
    printf("      0 - zstd_compressStream2 (stream mode)\n");
    printf("      1 - zstd_compress (block mode)\n");
    printf("  -d: test mode\n");
    printf("      0 - compress only\n");
    printf("      1 - decompress only\n");
    printf("      2 - compress + decompress\n");
    printf("  -i: input file path (if set, uses file content instead of random data)\n");
    printf("  -h: show this help\n");
}

int main(int argc, char **argv)
{
    int o = 0;
    const char *optstring = "c:p:l:n:f:t:d:i:h";
    int num_processes = 0;
    int num_threads = 4;
    int streamLen = 1024;
    int loopTimes = 1;
    int cLevel = 1;
    enum CompressFunc cFunction = ZSTD_COMPRESS_STREAM2;
    int test_mode = TEST_COMPRESS_ONLY;
    char* input_file = NULL;
    
    while ((o = getopt(argc, argv, optstring)) != -1) {
        switch (o) {
            case 'p':
                num_processes = atoi(optarg);
                break;
            case 't':
                num_threads = atoi(optarg);
                break;
            case 'l':
                streamLen = atoi(optarg);
                break;
            case 'n':
                loopTimes = atoi(optarg);
                break;
            case 'c':
                cLevel = atoi(optarg);
                break;
            case 'f':
                cFunction = atoi(optarg);
                break;
            case 'd':
                test_mode = atoi(optarg);
                break;
            case 'i':
                input_file = optarg;
                break;
            case 'h':
                Usage();
                return 0;
            default:
                Usage();
                return 1;
        }
    }
    
    if (argc <= 1) {
        Usage();
        printf("\ndefault input parameters will be used\n");
    }
    
    setenv("KAE_ZSTD_LEVEL", (char *)&cLevel, 1);
    
    // 准备数据
    uint8_t* inBuf = NULL;
    size_t inSize = 0;
    uint8_t* compressedBuf = NULL;
    size_t compressedSize = 0;
    
    if (input_file) {
        inBuf = LoadFile(input_file, &inSize);
        if (!inBuf) {
            fprintf(stderr, "Failed to load input file\n");
            return 1;
        }
        printf("Loaded input file: %s, size: %zu bytes\n", input_file, inSize);
    } else {
        inSize = streamLen * 1024; // KB to Bytes
        inBuf = CompressInputGet(inSize);
        if (!inBuf) {
            fprintf(stderr, "Failed to generate random input\n");
            return 1;
        }
        printf("Generated random input, size: %zu bytes\n", inSize);
    }
    
    // 如果需要测试解压，预先压缩
    if (test_mode == TEST_DECOMPRESS_ONLY || test_mode == TEST_COMPRESS_DECOMPRESS) {
        // 对于 compress+decompress，ThreadWorker 会自己压缩。
        // 但对于 decompress only，我们需要预先压缩好的数据。
        // 为了方便，我们在 decompress only 模式下生成 compressedBuf。
        // 在 compress+decompress 模式下，ThreadWorker 内部产生压缩数据用于解压，
        // 所以不需要预先压缩，除非我们也想测试“标准”解压速度？
        // 原始代码在 compress+decompress 模式下是：压缩 -> 解压。
        // 原始代码在 decompress only 模式下是：预压缩 -> 循环(解压)。
        // 我们保持这个逻辑。
        
        if (test_mode == TEST_DECOMPRESS_ONLY) {
             size_t maxCS = ZSTD_compressBound(inSize);
             compressedBuf = (uint8_t*)malloc(maxCS);
             if (!compressedBuf) {
                 fprintf(stderr, "Malloc failed for pre-compression\n");
                 free(inBuf);
                 return 1;
             }
             
             if (cFunction == ZSTD_COMPRESS) {
                 compressedSize = CompressBlock(inBuf, inSize, compressedBuf, maxCS, cLevel);
             } else {
                 compressedSize = CompressStream(inBuf, inSize, compressedBuf, maxCS, cLevel);
             }
             printf("Pre-compressed data size: %zu bytes\n", compressedSize);
        }
    }
    
    printf("kaezstd perf parameters:\n");
    printf("  Processes: %d, Threads per process: %d\n", num_processes, num_threads);
    printf("  Stream length: %zu bytes, Loop times: %d\n", inSize, loopTimes);
    printf("  Compression level: %d\n", cLevel);
    printf("  Compression function: %s (%d)\n", 
           cFunction == ZSTD_COMPRESS ? "block" : "stream", cFunction);
    printf("  Test mode: %s (%d)\n",
           test_mode == TEST_COMPRESS_ONLY ? "compress only" :
           test_mode == TEST_DECOMPRESS_ONLY ? "decompress only" : "compress+decompress",
           test_mode);
           
    DoTestPerf(num_processes, num_threads, inSize, cLevel, loopTimes, cFunction, test_mode,
               inBuf, inSize, compressedBuf, compressedSize);
    
    // 清理
    if (inBuf) free(inBuf);
    if (compressedBuf) free(compressedBuf);
    
    return 0;
}
