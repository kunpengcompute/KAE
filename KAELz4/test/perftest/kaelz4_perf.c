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
#include <lz4.h>      // presumes lz4 library is installed
#define __USE_GNU
#include <sched.h>
#include <pthread.h>

uint8_t *g_inbuf = NULL;
int g_threadnum = 15;
int core_seq = 0;

enum CompressFunc {
    LZ4_BLOCKCOMPRESS,
    LZ4_STREAMINGCOMPRESS,
};

struct ThreadArgs {
    int blocksize;
    int streamLen;
    int cLevel;
    int loopTimes;
    int core_id;
};

// 获取指定大小的随机数据流
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


// 块压缩模式：数据切块随后调用LZ4压缩接口
static void DoBlockCompressPerf_next(int streamLen, int cLevel, int bsize)
{
    int inpOffset = 0;
    int DataLen = streamLen;

    for (; ;)
    {
        int inpBytes = 0;
        char *src = &g_inbuf[inpOffset];
        if (streamLen <= 0)
        {
            break;
        }
        if (streamLen >= bsize)
        {
            inpOffset += bsize;
            inpBytes = bsize;
        }
        else
        {
            inpOffset += streamLen;
            inpBytes = streamLen;
        }
        streamLen -= inpBytes;

        char *const dst = (char*) malloc(LZ4_COMPRESSBOUND(inpBytes));
        const int cmpBytes = LZ4_compress_fast(src, dst, inpBytes, LZ4_COMPRESSBOUND(inpBytes), cLevel);
        free(dst);

        if (cmpBytes <= 0)
        {
            break;
            printf("LZ4 compress error\n");
        }
    }
}

void* thread_function(void* arg) {
    struct ThreadArgs* args = (struct ThreadArgs*)arg;
    int streamLen = args->streamLen;
    int cLevel = args->cLevel;
    int loopTimes = args->loopTimes;
    int core_id = args->core_id;
    int bsize = args->blocksize;
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
        DoBlockCompressPerf_next(streamLen, cLevel, bsize);
    }

    return NULL;
}

void DoCompressPerf(int multi, int streamLen, int cLevel, int loopTimes, int bsize)
{
    pid_t pidChild = 0;
    struct timeval start, stop;
    int core_id = 0;

    g_inbuf = CompressInputGet(streamLen);
    if (g_inbuf == NULL) {
        return;
    }

    for (int i = 0; i < multi; i++) {
         pidChild = fork();
         if (pidChild == 0) {
             //子进程
            core_id = i + core_seq; //开始绑核的cpuid
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
        struct ThreadArgs args = {bsize, streamLen, cLevel, loopTimes, core_id};

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
        float speed1 = 1000000.0 / time1 * loopTimes * multi * g_threadnum * streamLen / (1 << 30);
        printf("kaelz4 %s perf result:\n", "compress");
        printf("     time used: %lu us, speed = %.3f GB/s\n", time1, speed1);
    }
}

static void Usage(void)
{
    printf("usage: \n");
    printf("  -m: multi process \n");
    printf("  -n: loop times\n");
    printf("  -l: stream length(KB)\n");
    printf("  -c: compress level\n");
    printf("  -b: block size(KB)\n");
    printf("  -s: core sequence\n");
    printf("  -t: thread number\n");
    printf("  example: ./kaelz4_perf -c 1 -l 64000 -m 10 -b 64\n");
}

int main(int argc, char **argv)
{
    int o = 0;
    const char *optstring = "c:l:h:b:m:n:s:t:";
    int multi = 10;
    int loopTimes = 1;
    int streamLen = 64000;
    int cLevel = 1; // 压缩等级
    int bsize = 64; // 切块大小
    enum CompressFunc cFunction = LZ4_BLOCKCOMPRESS; // 压缩模式
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if (optstring == NULL)
        {
            continue;
        }
        switch (o) {
            case 't':
                g_threadnum = atoi(optarg);
                if (g_threadnum < 0) {
                    printf("Error: the number of thread must be larger than 0\n");
                    exit(1);
                }
                break;
            case 's':
                core_seq = atoi(optarg);
                if (core_seq < 0 || core_seq > 319) {
                    printf("Error: the sequence of core must be larger than 0 and smaller than 320\n");
                    exit(1);
                }
                break;
            case 'm':
                multi = atoi(optarg);
                if (multi < 0) {
                    printf("Error: the number of process must be larger than 0\n");
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
            case 'l':
                streamLen = atoi(optarg);
                if (streamLen <= 0) {
                    printf("Error: stream length must be larger than 0\n");
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
            case 'b':
                bsize = atoi(optarg);
                if (bsize < 0 || bsize > 64) {
                    printf("Error: compress function is out of range\n");
                    exit(1);
                }
                break;
            case 'h':
                Usage();
                return 0;
            default:
                printf("Error: Incorrect parameters\n");
                Usage();
                return 0;
        }
    }

    if (argc <= 1) {
        Usage();
        printf("\ndefault input parameter used\n");
    }
    printf("kaelz4 perf parameter: multi process %d, stream length: %d(KB), block size: %d(KB), compress level: %d, "
        "compress function: %d, loop times: %d, g_threadnum: %d, core sequence: %d ~ %d\n",
        multi, streamLen, bsize, cLevel, cFunction, loopTimes, g_threadnum, core_seq, core_seq + multi - 1);

    streamLen = 1024 * streamLen;
    bsize = 1024 * bsize;

    switch (cFunction)
    {
        case LZ4_BLOCKCOMPRESS:
            //DoBlockCompressPerf_old(streamLen, cLevel, bsize);
            DoCompressPerf(multi, streamLen, cLevel, loopTimes, bsize);
            break;
        default:
            printf("Error: no such compress funciton\n");
            break;
    }

    return 0;
}
