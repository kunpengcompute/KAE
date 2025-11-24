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
#include <snappy-c.h>      // presumes snappy library is installed
#define __USE_GNU
#include <sched.h>
#include <pthread.h>

uint8_t *g_inbuf = NULL;
int g_threadnum = 15;
int core_seq = 2;           // 绑核开始的 cpuid。
int g_show_perf_print = 0;  // 是否展示性能数据，默认0不展示。 1：仅展示最后一次时延和压缩比例。 2：展示每次的单次时延
int g_use_cpu_number = 1;   // 使用的加速器数量。使得绑核值会均匀分到几个加速器上

enum CompressFunc {
    SNAPPY_BLOCKCOMPRESS,
};

struct ThreadArgs {
    size_t blocksize;
    size_t streamLen;
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
    size_t i = 0;
    for (i = 0; i < inputSize; i++) {
        inbuf[i] = (uint8_t)rand() % 254 + 1;
    }

    return inbuf;
}
static size_t read_inputFile(const char *fileName, void **input)
{
    FILE *sourceFile = fopen(fileName, "r");
    if (sourceFile == NULL) {
        fprintf(stderr, "%s not exist!\n", fileName);
        return 0;
    }
    size_t fd = fileno(sourceFile);
    struct stat fs;
    (void)fstat(fd, &fs);

    size_t input_size = fs.st_size;
    *input = malloc(input_size);
    if (*input == NULL) {
        return 0;
    }
    (void)fread(*input, 1, input_size, sourceFile);
    fclose(sourceFile);

    return input_size;
}

// 块压缩模式：数据切块随后调用SNAPPY压缩接口
static void DoBlockCompressPerf_next(size_t streamLen, size_t cLevel, size_t bsize)
{
    size_t inputOffset = 0;
    size_t totalCompressed = 0;
    const size_t totalInput = streamLen;
    uint64_t singleTime = 0;

    // 预先计算最大压缩缓冲区大小
    const size_t maxCompressBufSize = snappy_max_compressed_length(bsize);
    char* const compressBuf = (char*)malloc(maxCompressBufSize);
    if (compressBuf == NULL) {
        fprintf(stderr, "Failed to allocate compress buffer\n");
        return;
    }

    // 分块处理输入数据
    while (streamLen > 0) {
        const size_t inputBytes = (streamLen >= bsize) ? bsize : streamLen;
        // 当前块的起始地址
        const char* src = &g_inbuf[inputOffset];

        // 记录压缩开始时间
        struct timeval start, end;
        gettimeofday(&start, NULL);

        // 执行压缩
        size_t compressedBytes = maxCompressBufSize;  // 传入缓冲区大小，输出实际压缩后大小
        const snappy_status status = snappy_compress(src, inputBytes, compressBuf, &compressedBytes);

        // 计算压缩耗时
        gettimeofday(&end, NULL);
        singleTime = (end.tv_sec - start.tv_sec) * 1000000LL + (end.tv_usec - start.tv_usec);

        if (g_show_perf_print == 2) {
            printf("status: %d, input size: %zu, compressed size: %zu\n", status, inputBytes, compressedBytes);
            printf("单次时延: %.4f milliseconds\n", singleTime / 1000.0);
        }

        if (status != SNAPPY_OK || compressedBytes <= 0) {
            fprintf(stderr, "KAESnappy compress error\n");
            break;
        }

        totalCompressed += compressedBytes;
        inputOffset += inputBytes;
        streamLen -= inputBytes;
    }

    free(compressBuf);

    if (g_show_perf_print == 1) {
        const float compressRate = (totalInput > 0) ? (float)totalCompressed / totalInput : 0.0f;
        printf("最后一次压缩时延: %.2f milliseconds, 压缩比: %.3f\n",
               singleTime / 1000.0, compressRate);
    }
}

void *thread_function(void *arg)
{
    struct ThreadArgs *args = (struct ThreadArgs *)arg;
    size_t streamLen = args->streamLen;
    size_t cLevel = args->cLevel;
    size_t loopTimes = args->loopTimes;
    size_t core_id = args->core_id;
    size_t bsize = args->blocksize;
    // 绑核操作
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);  // 清空cpuSet
    // 将线程绑定到第0个CPU内核
    CPU_SET(core_id, &cpuSet);

    // 设置CPU亲和性
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuSet), &cpuSet) == -1) {
        fprintf(stderr, "Failed to set CPU affinity\n");
        return NULL;
    }

    for (size_t i = 0; i < loopTimes; ++i) {
        DoBlockCompressPerf_next(streamLen, cLevel, bsize);
    }

    return NULL;
}

void DoCompressPerf(size_t multi, size_t streamLenP, size_t cLevel, size_t loopTimes, size_t bsize, const char *in_filename)
{
    pid_t pidChild = 0;
    struct timeval start, stop;
    int core_id = 0;

    size_t streamLen = streamLenP;
    if (in_filename != NULL) {
        void *inbuf = NULL;
        streamLen = read_inputFile(in_filename, &inbuf);
        g_inbuf = inbuf;
        printf("get input file : %s\n", in_filename);
    } else {
        g_inbuf = CompressInputGet(streamLenP);
        printf("get random input data\n");
    }
    if (g_inbuf == NULL) {
        return;
    }

    for (size_t i = 0; i < multi; i++) {
        pidChild = fork();
        if (pidChild == 0) {
            if (g_use_cpu_number > 1) {
                // 子进程开始绑核的cpuid。
                //  针对一组numa80个核的机器，连续并均匀分配到N个不同加速器。连续分配测速会小一点
                // 开始绑核的cpuid：间隔不连续绑核。均匀分片到前N个CPU上。
                core_id = i + core_seq + (80 * (i % g_use_cpu_number));
            } else {
                core_id = i * 2 + core_seq;  // 单个numa连续绑核
            }
            if (g_use_cpu_number > 1) {
                printf("bind core: %d.\n", core_id);
            }
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

        for (size_t i = 0; i < g_threadnum; i++) {
            pthread_create(&threads[i], NULL, thread_function, &args);
        }

        for (size_t i = 0; i < g_threadnum; i++) {
            pthread_join(threads[i], NULL);
        }
    }

    if (pidChild > 0) {
        size_t ret = -1;
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
        printf("kaesnappy %s perf result:\n", "compress");
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
    printf("  -C: bind cpu numbers\n");
    printf("  -f: use this file for input data\n");
    printf("  -t: thread number\n");
    printf("  example: ./kaesnappy_perf -C 1 -l 64000 -m 10 -t 2 -b 64\n");
    printf("           ./kaesnappy_perf -C 1 -f calgary.tar -m 10 -t 2 -b 64\n");
}

int main(int argc, char **argv)
{
    size_t o = 0;
    const char *optstring = "c:l:h:b:m:n:s:t:f:C:";
    int multi = 10;
    int loopTimes = 1;
    size_t streamLen = 64000;
    int cLevel = 1;                                   // 压缩等级
    size_t bsize = 64;                                   // 切块大小
    enum CompressFunc cFunction = SNAPPY_BLOCKCOMPRESS;  // 压缩模式
    char input_filename[128] = {0};
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if (optstring == NULL) {
            continue;
        }
        switch (o) {
            case 'C':
                g_use_cpu_number = atoi(optarg);
                break;
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
                break;
            case 'f':
                strcpy(input_filename, optarg);
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
    printf("kaesnappy perf parameter: multi process %d, stream length: %zu(KB), block size: %zu(KB), compress level: %d, "
           "compress function: %d, loop times: %d, g_threadnum: %d, core sequence start: %d, use %d cpu. \n",
        multi,
        streamLen,
        bsize,
        cLevel,
        cFunction,
        loopTimes,
        g_threadnum,
        core_seq,
        g_use_cpu_number);

    streamLen = 1024 * streamLen;
    bsize = 1024 * bsize;
    const char *in_filename = input_filename[0] == 0 ? NULL : input_filename;
    switch (cFunction) {
        case SNAPPY_BLOCKCOMPRESS:
            DoCompressPerf(multi, streamLen, cLevel, loopTimes, bsize, in_filename);
            break;
        default:
            printf("Error: no such compress funciton\n");
            break;
    }

    return 0;
}
