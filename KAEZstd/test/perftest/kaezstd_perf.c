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

#include "common.h"

uint8_t *g_inbuf = NULL;
int g_threadnum=5;

enum CompressFunc {
    ZSTD_COMPRESS_STREAM2,
    ZSTD_COMPRESS,
};

typedef struct {
    void* buffIn;
    void* buffOut;
    size_t buffInSize;
    size_t buffOutSize;
    ZSTD_CCtx* cctx;
} resources;

uint8_t *CompressInputGet(size_t inputSize)
{
    uint8_t *inbuf = (uint8_t *)malloc(inputSize * sizeof(uint8_t));
    if (inbuf == NULL) {
        printf("%s  malloc failed\n", __func__);
        return NULL;
    }

    memset(inbuf, 0, inputSize);
    srand((unsigned int)time(NULL));
    int i = 0;
    for (i = 0; i < inputSize; i++) {
        inbuf[i] = (uint8_t)rand() % 254 + 1;
    }

    return inbuf;
}

static resources CompressCreateResources(uint8_t *inbuf, int streamLen)
{
    resources ress;
    ress.buffInSize = streamLen;
    ress.buffOutSize = ZSTD_compressBound(streamLen);
    ress.buffIn = inbuf;
    ress.buffOut = malloc_orDie(ress.buffOutSize);
    ress.cctx = ZSTD_createCCtx();
    CHECK(ress.cctx != NULL, "ZSTD_createCCtx() failed!");

    return ress;
}

static void FreeResources(resources ress)
{
    ZSTD_freeCCtx(ress.cctx);
    // free(ress.buffIn);
    free(ress.buffOut);
}

struct ThreadArgs {
    int streamLen;
    int cLevel;
    int loopTimes;
    int core_id;
};

void* thread_function(void* arg) {
    // printf("[liuyang]in thread\n");
    struct ThreadArgs* args = (struct ThreadArgs*)arg;
    int streamLen = args->streamLen;
    int cLevel = args->cLevel;
    int loopTimes = args->loopTimes;
    int core_id = args->core_id;
    // 绑核操作
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet); // 清空cpuSet
    // 将线程绑定到第0个CPU内核
    CPU_SET(core_id, &cpuSet);

    // 设置CPU亲和性
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuSet), &cpuSet) == -1) {
        fprintf(stderr, "Failed to set CPU affinity\n");
        return NULL;
    }

    for (int i = 0; i < loopTimes; ++i) {
        // 生成随机输入
        // uint8_t *inbuf = CompressInputGet(streamLen);
        // if (inbuf == NULL) {
        //     return NULL;
        // }

        // 初始化
        resources const ress = CompressCreateResources(g_inbuf, streamLen);

        /* Compress using the context.
        * If you need more control over parameters, use the advanced API:
        * ZSTD_CCtx_setParameter(), and ZSTD_compress2().
        */
        size_t const cSize = ZSTD_compressCCtx(ress.cctx, ress.buffOut, ress.buffOutSize,
            ress.buffIn, ress.buffInSize, cLevel);
        CHECK_ZSTD(cSize);
        FreeResources(ress);
    }

    return NULL;
}

// 块压缩：一次性将所有输入都输入压缩
void DoCompressPerf(int multi, int streamLen, int cLevel, int loopTimes)
{
    pid_t pidChild = 0;
    struct timeval start, stop;
    int core_id;

    g_inbuf = CompressInputGet(streamLen);
    if (g_inbuf == NULL) {
        return;
    }

    for (int i = 0; i < multi; i++) {
        pidChild = fork();
        if (pidChild == 0) {
            //子进程
            core_id = i + 35; //开始绑核的cpuid
            break;
        } else if (pidChild < 0) {
            printf("%s fork failed\n", __func__);
        }
    }

    if (pidChild > 0) {
        gettimeofday(&start, NULL);
    }

    if (pidChild == 0) {
        pthread_t threads[100];
        struct ThreadArgs args = {streamLen, cLevel, loopTimes, core_id};

        for (int i = 0; i < g_threadnum; i++) {
            pthread_create(&threads[i], NULL, thread_function, &args);
        }

        for (int i = 0; i < g_threadnum; i++) {
            pthread_join(threads[i], NULL);
        }

    }

    if (pidChild > 0) {
        int ret = -1;
        while (1) {
            ret = wait(NULL);
            if (ret == -1) {
                if (errno == EINTR) {
                    continue;
                }
                free(g_inbuf);
                break;
            }
        }
    }

    if (pidChild > 0 || multi == 0) {
        if (multi == 0) {
            multi = 1;
        }
        gettimeofday(&stop, NULL);
        uint64_t time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
        float speed1 = 1000000.0 / time1 * loopTimes * multi * g_threadnum * streamLen / 1024 / 1024 / 1024;
        printf("kaezstd %s perf result:\n", "compress");
        printf("     time used: %lu us, speed = %.3f GB/s\n", time1, speed1);
    }


}

static resources CompressStream2CreateResources(int cLevel)
{
    resources ress;
    ress.buffInSize = ZSTD_CStreamInSize();   /* can always read one full block */
    ress.buffOutSize= ZSTD_CStreamOutSize();  /* can always flush a full block */
    ress.buffIn = malloc_orDie(ress.buffInSize);
    ress.buffOut= malloc_orDie(ress.buffOutSize);
    // 创建ZSTD压缩上下文
    ress.cctx = ZSTD_createCCtx();
    CHECK(ress.cctx != NULL, "ZSTD_createCCtx() failed!");

    /* Set any compression parameters you want here.
     * They will persist for every compression operation.
     * Here we set the compression level, and enable the checksum.
     */
    CHECK_ZSTD( ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_compressionLevel, cLevel) );
    CHECK_ZSTD( ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_checksumFlag, 1) );

    return ress;
}

static size_t ReadFromInput(void *buffer, size_t sizeToRead, uint8_t *src, int totalBytesLeft)
{
    int cpySize = sizeToRead <= totalBytesLeft ? sizeToRead : totalBytesLeft;
    memcpy(buffer, src, cpySize);
    return cpySize;
}

static void DoMultiCompressStream2(resources ress, uint8_t *inbuf, int streamLen)
{
    /* Reset the context to a clean state to start a new compression operation.
     * The parameters are sticky, so we keep the compression level and extra
     * parameters that we set in createResources_orDie().
     */
    // CHECK_ZSTD( ZSTD_CCtx_reset(ress.cctx, ZSTD_reset_session_only) );

    size_t const toRead = ress.buffInSize;
    size_t read;
    uint8_t *src = inbuf;
    int totalBytesLeft = streamLen;
    while ( (read = ReadFromInput(ress.buffIn, toRead, src, totalBytesLeft)) ) {
        totalBytesLeft -= read;
        src += read;
        /* This loop is the same as streaming_compression.c.
         * See that file for detailed comments.
         */
        int const lastChunk = (read < toRead);
        ZSTD_EndDirective const mode = lastChunk ? ZSTD_e_end : ZSTD_e_continue;

        ZSTD_inBuffer input = { ress.buffIn, read, 0 };
        int finished;
        do {
            ZSTD_outBuffer output = { ress.buffOut, ress.buffOutSize, 0 };
            size_t const remaining = ZSTD_compressStream2(ress.cctx, &output, &input, mode);
            CHECK_ZSTD(remaining);
            finished = lastChunk ? (remaining == 0) : (input.pos == input.size);
        } while (!finished);
        CHECK(input.pos == input.size,
              "Impossible: zstd only returns 0 when the input is completely consumed!");
    }
}

void DoCompressStream2Perf(int multi, int streamLen, int cLevel, int loopTimes)
{
    // // 生成随机输入
    // uint8_t *inbuf = CompressInputGet(streamLen);
    // if (inbuf == NULL) {
    //     return;
    // }

    printf("[liuyang]\n");
    pid_t pidChild = 0;
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    for (int i = 0; i < multi; i++) {
        pidChild = fork();
        if (pidChild == 0) {
            break;
        } else if (pidChild < -1) {
            printf("%s fork failed\n", __func__);
        }
    }

    // if (pidChild == 0) {
    for (int i = 0; i < 5; i++) {
        // 生成随机输入
        uint8_t *inbuf = CompressInputGet(streamLen);
        if (inbuf == NULL) {
            return;
        }

        resources const ress = CompressStream2CreateResources(cLevel);
        CHECK_ZSTD( ZSTD_CCtx_reset(ress.cctx, ZSTD_reset_session_only) );
        for (int i = 0; i < loopTimes; ++i) {
            DoMultiCompressStream2(ress, inbuf, streamLen);
        }

        FreeResources(ress);
    }
    // }

    if (pidChild > 0) {
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
    }

    if (pidChild > 0 || multi == 0) {
        if (multi == 0) {
            multi = 1;
        }
        gettimeofday(&stop, NULL);
        uint64_t time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
        float speed1 = 1000000.0 / time1 * 5 * loopTimes * multi * streamLen / 1024 / 1024 / 1024;
        printf("kaezstd %s perf result:\n", "compress");
        printf("     time used: %lu us, speed = %.3f GB/s\n", time1, speed1);
    }

    // FreeResources(ress);
}

static void Usage(void)
{
    printf("usage: \n");
    printf("  -m: multi process \n");
    printf("  -l: stream length(KB)\n");
    printf("  -n: loop times\n");
    printf("  -c: compress level\n");
    printf("  -f: compress function\n");
    printf("      0 - zstd_compressStream2\n");
    printf("      1 - zstd_compress\n");
    printf("  -t: the number of compress threads (default 4), only for zstd_compressStream2 and zstd_compress2\n");
    printf("  example: ./kaezstd_perf -c 1 -m 0 -f 0 -t 4 -l 1024 -n 1\n");
}

int main(int argc, char **argv)
{
    int o = 0;
    const char *optstring = "c:m:l:n:f:t:h";
    int multi = 0;
    int streamLen = 1024;
    int loopTimes = 1;
    int cLevel = 1; // 压缩等级
    enum CompressFunc cFunction = ZSTD_COMPRESS_STREAM2; // 压缩函数
    g_threadnum = 4; // 线程个数
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (o) {
            case 'm':
                multi = atoi(optarg);
                if (multi < 0) {
                    printf("Error: the number of process must be larger than 0\n");
                    exit(1);
                }
                break;
            case 'l':
                streamLen = atoi(optarg);
                if (streamLen <= 0) {
                    printf("Error: stream length must be larger than 0\n");
                    exit(1);
                }
                break;
            case 'n':
                loopTimes = atoi(optarg);
                if (loopTimes <= 0) {
                    printf("Error: loop times must be larger than 0\n");
                    exit(1);
                }
                break;
            case 'c':
                cLevel = atoi(optarg);
                if (cLevel < 0) {
                    printf("Error: compress function is out of range\n");
                    exit(1);
                }
                break;
            case 'f':
                cFunction = atoi(optarg);
                if (cFunction < 0 || cFunction > 3) {
                    printf("Error: compress function is out of range\n");
                    exit(1);
                }
                break;
            case 't':
                g_threadnum = atoi(optarg);
                if (g_threadnum <= 0) {
                    printf("Error: compress threads is out of range\n");
                    exit(1);
                }
                break;
            case 'h':
                Usage();
                return 0;
        }
    }

    if (argc <= 1) {
        Usage();
        printf("\ndefault input parameter used\n");
    }
    setenv("KAE_ZSTD_LEVEL", (char *)&cLevel, 1);
    printf("kaezstd perf parameter: multi process %d, stream length: %d(KB), compress level: %d, "
        "compress function: %d, loop times: %d, g_threadnum: %d\n",
        multi, streamLen, cLevel, cFunction, loopTimes, g_threadnum);

    streamLen = 1000 * streamLen;

    switch (cFunction)
    {
        case ZSTD_COMPRESS_STREAM2:
            DoCompressStream2Perf(multi, streamLen, cLevel, loopTimes);
            break;
        case ZSTD_COMPRESS:
            DoCompressPerf(multi, streamLen, cLevel, loopTimes);
            break;
        default:
            printf("Error: no such compress funciton\n");
            break;
    }
}
