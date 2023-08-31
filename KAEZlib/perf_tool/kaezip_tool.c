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

void usage(void)
{
    printf("usage: \n");
    // printf("  -m: multi process \n");
    printf("  -s: stream length(KB)\n");
    printf("  -n: input data expanded n times.\n");
    printf("  -d: compress or uncompress, (0 for compress, 1 for uncompress) .\n");
    printf("  -l: compress levle, [0-9]\n");
    printf("  -f: input file\n");
    printf("  example: ./kaezip_perf -s 1024 -l 1 -n 1000\n");
    printf("           ./kaezip_perf -f filename -l 1 -n 1000\n");
    printf("           ./kaezip_perf -d 0 -l 1 -f filename -o filename.out\n");
    printf("           ./kaezip_perf -d 1 -f compressedfile -o decompressedfile\n");
}

static uLong read_inputFile(const char* fileName, void** input, int loop_times)
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
    *input = malloc(input_size * sizeof(Bytef) * loop_times);
    if (*input == NULL) {
        return 0;
    }

    for (int i = 0; i < loop_times; i++) {
        (void)fread(*input + i * input_size, 1, input_size, sourceFile);
        fseek(sourceFile, 0, SEEK_SET);
    }

    fclose(sourceFile);

    return input_size * loop_times;
}

uint8_t *get_compress_input(size_t input_sz)
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

void do_perf_compress2(int level, unsigned char* output, uLong* output_sz, const unsigned char* inbuf, uLong stream_len)
{
    int ret = 0;
    int output_sz_bak = *output_sz;//因为每次压缩*output_sz值会变化，循环的时候需要初始化成一开始的情况。
    fflush(stdout);
    fflush(stderr);

    struct timeval start, stop;
    gettimeofday(&start, NULL);

    *output_sz = output_sz_bak;
    ret = compress2(output, output_sz, inbuf, stream_len, level);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:compress2 failed, ret is:%d.\n", ret);
        exit(-1);
    }

    gettimeofday(&stop, NULL);
    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    float speed1 = 1000000.0 / time1 * stream_len / (1 << 20); //单位MB/s  
    float compressRate =  (float)*output_sz/ (float)stream_len;
    // printf("[%ld]/[%ld]\n", *output_sz, stream_len);
    printf("zip compress perf result: time used: %lu us, compress speed = %.3f MB/s, compress rate = %.3f\n", time1, speed1, compressRate);

    return;
}

void do_perf_uncompress2(unsigned char* decompressedData, uLong* decompressedSize, unsigned char* compressedData, uLong *compressedSize)
{
    int ret = 0;

    fflush(stdout);
    fflush(stderr);

    struct timeval start, stop;
    gettimeofday(&start, NULL);

    ret = uncompress2(decompressedData, decompressedSize, compressedData, compressedSize);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
        exit(-1);
    }

    gettimeofday(&stop, NULL);
    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    float speed1 = 1000000.0 / time1 * (*compressedSize) / (1 << 20); //单位MB/s  
    printf("zip uncompress perf result: time used: %lu us, uncompress speed = %.3f MB/s\n", time1, speed1);

    return;
}

int do_perf(const char* in_filename, uLong stream_len, int loop_times, int level)
{
    // 获取压缩数据：inbuf stream_len
    void *inbuf = NULL;
    if (in_filename) {
        fprintf(stdout, "compress filename : %s\n", in_filename);
        stream_len = read_inputFile(in_filename, &inbuf, loop_times);
    } else {
        stream_len = stream_len * loop_times;
        inbuf = get_compress_input(stream_len);
    }
    if (!inbuf) {
        fprintf(stderr, "inbuf is NULL!\n");
        return -1;
    }
    // printf("[KAE]input_size is %luB\n", stream_len);
    
    // 获取目的空间buf compressedData compressedSize
    uLong blen = compressBound(stream_len);
    uLong compressedSize = blen;
    void *compressedData = malloc(blen);
    if (compressedData == NULL) {
        return -1;
    }
    memset(compressedData, 0, compressedSize);

    // 获取解压缩数据空间：
    uLong decompressedSize = stream_len;
    void *decompressedData = NULL;
    decompressedData = malloc(stream_len);
    if (compressedData == NULL) {
        return -1;
    }
                            
    do_perf_compress2(level, compressedData, &compressedSize, inbuf, stream_len);
    do_perf_uncompress2(decompressedData, &decompressedSize, compressedData, &compressedSize);

    if(decompressedSize != stream_len){
        printf("[KAE_ERR] 压缩前后大小不一致：%ld ==> %ld\n", stream_len, decompressedSize);
        exit(-1);
    }

    free(inbuf);
    free(compressedData);
    free(decompressedData);
    return 0;
}

int do_compress(const char* inputFile, const char* outputFile, int level)
{
    if (inputFile == NULL || outputFile == NULL) {
        usage();
        return 1;
    }
    int ret;
    void *inbuf = NULL;
    void *outbuf = NULL;
    uLong stream_len;
    // 打开输入文件获取数据内容
    stream_len = read_inputFile(inputFile, &inbuf, 1);

    // 创建输出文件
    FILE *fileoutput = fopen(outputFile, "wb");
    if (fileoutput == NULL) {
        printf("[ERROR]Failed to create fileoutput file.\n");
        return 1;
    }

    // 获取目的空间buf compressedData compressedSize
    uLong blen = compressBound(stream_len);
    uLong compressedSize = blen;
    outbuf = malloc(blen);
    if (outbuf == NULL) {
        printf("[ERROR]malloc compressed Data failed.\n");
        return -1;
    }
    memset(outbuf, 0, compressedSize);

    // do compress
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    ret = compress2(outbuf, &compressedSize, inbuf, stream_len, level);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:compress2 failed, ret is:%d.\n", ret);
        exit(-1);
    }
    gettimeofday(&stop, NULL);

    //write compressed file
     if (fwrite(outbuf, 1, compressedSize, fileoutput) != compressedSize) {
        printf("Failed to write fileoutput file.\n");
        fclose(fileoutput);
        free(inbuf);
        free(outbuf);
        return 1;
    }

    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
    float speed1 = 1000000.0 / time1 * stream_len / (1 << 20); //单位MB/s  
    printf("zip compress file %s result: time used: %lu us, speed is %.3f MB/s\n", inputFile, time1, speed1);

    fclose(fileoutput);
    free(inbuf);
    free(outbuf);
    return 0;
}

int do_uncompress(const char* inputFile, const char* outputFile, int level)
{
    if (inputFile == NULL || outputFile == NULL) {
        usage();
        return 1;
    }
    int ret;
    void *inbuf = NULL;
    void *outbuf = NULL;
    uLong stream_len;
    // 打开输入文件获取数据内容
    stream_len = read_inputFile(inputFile, &inbuf, 1);

    // 创建输出文件
    FILE *fileoutput = fopen(outputFile, "wb");
    if (fileoutput == NULL) {
        printf("[ERROR]Failed to create fileoutput file.\n");
        return 1;
    }

    // 获取目的空间buf compressedData compressedSize
    uLong decompressSize = stream_len * 5;
    outbuf = malloc(decompressSize);
    if (outbuf == NULL) {
        printf("[ERROR]malloc decompress Data failed.\n");
        return -1;
    }
    memset(outbuf, 0, decompressSize);

    // do compress
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    ret = uncompress2(outbuf, &decompressSize, inbuf, &stream_len);
    if (ret != Z_OK) {
        printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
        exit(-1);
    }
    gettimeofday(&stop, NULL);

    //write compressed file
     if (fwrite(outbuf, 1, decompressSize, fileoutput) != decompressSize) {
        printf("Failed to write fileoutput file.\n");
        fclose(fileoutput);
        free(inbuf);
        free(outbuf);
        return 1;
    }

    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
    float speed1 = 1000000.0 / time1 * stream_len / (1 << 20); //单位MB/s  
    printf("zip compress file %s result: time used: %lu us, speed is %.3f MB/s\n", inputFile, time1, speed1);

    fclose(fileoutput);
    free(inbuf);
    free(outbuf);
    return 0;
}

int main(int argc, char **argv)
{
    int opt = 0;
    int ret;
    const char *optstring = "s:n:l:d:f:o:h";
    // int multi = 2;
    uLong stream_len = 1024;
    int loop_times = 1;
    int level = 1;
    int perfFlag = -1; //初始值-1表示默认做perf计算，而不是作为压缩解压缩工具。
    char input_filename[128] = {0};
    char output_filename[128] = {0};
    while ((opt = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (opt) {
            case 's':
                stream_len = atoi(optarg);
                break;
            case 'n':
                loop_times = atoi(optarg);
                break;
            case 'l':
                level = atoi(optarg);
                break;
            case 'd':
                perfFlag = atoi(optarg);
                break;
            case 'f':
                strcpy(input_filename, optarg);
                break;
            case 'o':
                strcpy(output_filename, optarg);
                break;
            case 'h':
                usage();
                return 0;
        }
    }

    if (argc <= 1) {
        usage();
        printf("\ndefault input parameter used\n");
    } 

    const char* in_filename  = input_filename[0] == 0 ? NULL : input_filename;
    // const char* out_filename = output_filename[0]== 0 ? NULL : output_filename;
    stream_len *= 1024;


    switch (perfFlag) {
        case -1:
            ret = do_perf(in_filename, stream_len, loop_times, level);
            break;
        case 0:
            ret = do_compress(in_filename, output_filename, level);
            break;
        case 1:
            ret = do_uncompress(in_filename, output_filename, level);
            break;
        default :
            printf("[ERROR]Please select right cmd.\n");
            usage();
    }
    return ret;
}
