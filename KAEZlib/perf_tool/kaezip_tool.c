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

static uLong read_inputFile(const char* fileName, void** input)
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
    *input = malloc(input_size * sizeof(Bytef));
    if (*input == NULL) {
        return 0;
    }
    (void)fread(*input, 1, input_size, sourceFile);
    fclose(sourceFile);

    return input_size;
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

uint8_t *get_decompress_input(size_t input_sz, uLong *pblen)
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

    uLong blen = compressBound(input_sz);
    uint8_t *outbuf = (uint8_t *)malloc(blen * sizeof(uint8_t));
    memset(outbuf, 0, blen);
    int cret = compress2((Bytef *)outbuf, (uLongf *)&blen, (Bytef *)inbuf, (uLong)input_sz, 1);
    if (cret != Z_OK && cret != Z_BUF_ERROR) {
        free(outbuf);
        outbuf = NULL;
    }

    free(inbuf);
    *pblen = blen;
    return outbuf;
}

void do_compress2(int loop_times, int level, unsigned char* output, uLong* output_sz, const unsigned char* inbuf, uLong stream_len)
{
    int ret = 0;
    int output_sz_bak = *output_sz;//因为每次压缩*output_sz值会变化，循环的时候需要初始化成一开始的情况。
    fflush(stdout);
    fflush(stderr);

    struct timeval start, stop;
    gettimeofday(&start, NULL);

    for(int i = 0; i < loop_times; i++)	
    {
        *output_sz = output_sz_bak;
        ret = compress2(output, output_sz, inbuf, stream_len, level);
        if (ret != Z_OK) {
            printf("[KAE_ERR]:compress2 failed, ret is:%d.\n", ret);
            exit(-1);
        }
    }


    gettimeofday(&stop, NULL);
    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    float speed1 = 1000000.0 / time1 * loop_times * stream_len / (1 << 20); //单位MB/s  
    float compressRate =  (float)*output_sz/ (float)stream_len;
    // printf("[%ld]/[%ld]\n", *output_sz, stream_len);
    printf("zip compress perf result: time used: %lu us, compress speed = %.3f MB/s, compress rate = %.3f\n", time1, speed1, compressRate);


    return;
}

void do_uncompress2(int loop_times, unsigned char* decompressedData, uLong* decompressedSize, unsigned char* compressedData, uLong *compressedSize)
{
    int ret = 0;

    fflush(stdout);
    fflush(stderr);

    struct timeval start, stop;
    gettimeofday(&start, NULL);

    for(int i = 0; i < loop_times; i++)	
    {
        ret = uncompress2(decompressedData, decompressedSize, compressedData, compressedSize);
        if (ret != Z_OK) {
            printf("[KAE_ERR]:uncompress2 failed, ret is:%d.\n", ret);
            exit(-1);
        }
    }


    gettimeofday(&stop, NULL);
    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    float speed1 = 1000000.0 / time1 * loop_times * (*compressedSize) / (1 << 20); //单位MB/s  
    printf("zip uncompress perf result: time used: %lu us, uncompress speed = %.3f MB/s\n", time1, speed1);


    return;
}

int do_perf(const char* in_filename, uLong stream_len, int loop_times, int level)
{
    // 获取压缩数据：inbuf stream_len
    void *inbuf = NULL;
    if (in_filename) {
        fprintf(stdout, "compress filename : %s\n", in_filename);
        stream_len = read_inputFile(in_filename, &inbuf);
    } else {
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
                            
    do_compress2(loop_times, level, compressedData, &compressedSize, inbuf, stream_len);
    do_uncompress2(loop_times, decompressedData, &decompressedSize, compressedData, &compressedSize);

    if(decompressedSize != stream_len){
        printf("[KAE_ERR] 压缩前后大小不一致：%ld ==> %ld\n", stream_len, decompressedSize);
        exit(-1);
    }

    free(inbuf);
    free(compressedData);
    free(decompressedData);
    return 0;
}


void usage(void)
{
    printf("usage: \n");
    // printf("  -m: multi process \n");
    printf("  -s: stream length(KB)\n");
    printf("  -n: loop times\n");
    printf("  -l: compress levle, [0-9]\n");
    printf("  -f: input file\n");
    printf("  example: ./kaezip_perf -s 1024 -l 1 -n 1000\n");
    printf("           ./kaezip_perf -f filename -l 1 -n 1000\n");
}


int main(int argc, char **argv)
{
    int o = 0;
    const char *optstring = "dm:s:n:l:f:o:h";
    // int multi = 2;
    uLong stream_len = 1024;
    int loop_times = 1000;
    int level = 8;
    char input_filename[128] = {0};
    char output_filename[128] = {0};
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (o) {
            case 's':
                stream_len = atoi(optarg);
                break;
            case 'n':
                loop_times = atoi(optarg);
                break;
            case 'l':
                level = atoi(optarg);
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

    printf("kaezip perf parameter: stream length: %ld(MB), loop times: %d, level : %d\n", 
         stream_len, loop_times, level);

    const char* in_filename  = input_filename[0] == 0 ? NULL : input_filename;
    // const char* out_filename = output_filename[0]== 0 ? NULL : output_filename;
    stream_len *= 1024;

    return do_perf(in_filename, stream_len, loop_times, level);
   
}
