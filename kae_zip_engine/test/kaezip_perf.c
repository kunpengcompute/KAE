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

uint32_t *get_decompress_input(size_t input_sz, uLong *pblen)
{
    uint32_t *inbuf = (uint32_t *)malloc(input_sz * sizeof(uint32_t));
    if (inbuf == NULL) {
        return NULL;
    }

    memset(inbuf, 0, input_sz);
    srand((unsigned int)time(NULL));
    int i = 0;
    for (i = 0; i < input_sz; i++) {
        inbuf[i] = (uint32_t)rand() % 254 + 1;
    }

    uLong blen = compressBound(input_sz);
    uint32_t *outbuf = (uint32_t *)malloc(blen * sizeof(uint32_t));
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

int do_multi_perf(int multi, int stream_len, int loop_times, int compress, 
    void* output, uLong output_sz, void* inbuf, uLong blen)
{
    int i,j;
    pid_t pid_child = 0;
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    for (i = 0; i < multi; i++) {
        pid_child = fork();
        if (pid_child == 0 || pid_child == -1) {
            break;
        }
    }
    
    if (pid_child == 0) {
        for(j = 0;j < loop_times;j++)
        {
            int ret = -1;
            if (compress) {
                blen = compressBound(stream_len);
                ret = compress2((Bytef *)output, (uLongf *)&blen, (Bytef *)inbuf, (uLong)stream_len, 1);
                if (ret != Z_OK && ret != Z_BUF_ERROR) {
                    printf("compres error, ret = %d\n", ret);
                    return -1;
                }
            } else {
                ret = uncompress((Bytef *)output, &output_sz, (const Bytef *)inbuf, blen);
                if (ret < 0) {
                    printf("uncompres error, ret = %d\n", ret);
                    return -1;
                }
            }
        }
    }
    
    if (pid_child > 0) {
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

    if (pid_child > 0 || multi == 0) {
        if (multi == 0) { multi = 1; }
        gettimeofday(&stop, NULL);
        uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
        float speed1 = 1000000.0 / time1 * loop_times * multi * stream_len / 1000 / 1000 / 1000;
        printf("kaezip %s perf result:\n", compress ? "compress" : "decompress");
        printf("     time used: %lu us, speed = %.3f GB/s\n", time1, speed1);
    }

    return 0;
}

int do_compress_perf(int multi, int stream_len, int loop_times)
{
    int i = 0;
    uint8_t *inbuf = get_compress_input(stream_len);
    if (inbuf == NULL) {
        return -1;
    }
    
    uLong blen = compressBound(stream_len);
    uLong output_sz = blen;
    uint8_t *outbuf = (uint8_t *)malloc(output_sz * sizeof(uint8_t));
    if (outbuf == NULL) {
        return -1;
    }
    memset(outbuf, 0, output_sz);

    int ret = do_multi_perf(multi, stream_len, loop_times, 1, outbuf, output_sz, inbuf, blen);

    free(inbuf); 
    inbuf = NULL;
    free(outbuf); 
    outbuf = NULL;
    return ret;
}

int do_decompress_perf(int multi, int stream_len, int loop_times)
{   
    int i, j;
    uLong blen = 0;
    uint32_t *inbuf = get_decompress_input(stream_len, &blen);
    if (inbuf == NULL) {
        return -1;
    }

    uLong output_sz = stream_len;
    uint32_t *output = malloc(output_sz * sizeof(uint32_t));
    if (output == NULL) {
        return -1;
    }

    int ret = do_multi_perf(multi, stream_len, loop_times, 0, output, output_sz, inbuf, blen);

    free(inbuf); 
    inbuf = NULL;
    free(output);
    output = NULL;
    return ret;
}

void usage(void)
{
    printf("usage: \n");
    printf("  -m: multi process \n");
    printf("  -l: stream length(KB)\n");
    printf("  -n: loop times\n");
    printf("  -d: compress or decompress\n");
    printf("  example: ./kaezip_perf -m 2 -l 1024 -n 1000\n");
    printf("           ./kaezip_perf -d -m 2 -l 1024 -n 1000\n");
}

// [root@localhost test]# ./kaezip_perf
// usage:
//   -m: multi process
//   -l: stream length(KB)
//   -n: loop times
//   -d: compress or decompress
//   example: ./kaezip_perf -m 2 -l 1024 -n 1000
//            ./kaezip_perf -d -m 2 -l 1024 -n 1000

// default input parameter used
// kaezip perf input parameter: multi process 2, stream length: 1024(KB), loop times: 1000
// kaezip compress perf result:
//      time used: 509004 us, speed = 4.024 GB/s
//
// [root@localhost test]# ./kaezip_perf -d
// kaezip perf parameter: multi process 2, stream length: 1024(KB), loop times: 1000
// kaezip decompress perf result:
//      time used: 810318 us, speed = 2.527 GB/s

int main(int argc, char **argv)
{
    int o = 0;
    const char *optstring = "dm:l:n:h";
    int multi = 2;
    int stream_len = 1024;
    int loop_times = 1000;
    int compress = 1;
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (o) {
            case 'm':
                multi = atoi(optarg);
                break;
            case 'l':
                stream_len = atoi(optarg);
                break;
            case 'n':
                loop_times = atoi(optarg);
                break;
            case 'd':
                compress = 0;
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

    printf("kaezip perf parameter: multi process %d, stream length: %d(KB), loop times: %d\n", multi, stream_len, loop_times);

    stream_len = 1000 * stream_len;
    if (compress) {
        return do_compress_perf(multi, stream_len, loop_times);
    } else {
        return do_decompress_perf(multi, stream_len, loop_times);
    }
}
