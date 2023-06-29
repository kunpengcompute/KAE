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

int do_multi_perf(int multi, int stream_len, int loop_times, int compress, 
    void* output, uLong output_sz, void* inbuf, uLong blen)
{
    int i, j, err;
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
        z_stream strm;
        strm.zalloc   = (alloc_func)0;
        strm.zfree    = (free_func)0;
        strm.opaque   = (voidpf)0;
        if (compress) {
            (void)deflateInit2_(&strm, 1, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY, "1.2.11", sizeof(z_stream));
        } else {
            (void)inflateInit2_(&strm, windowBits, "1.2.11", sizeof(z_stream));
        }

        for (j = 0; j < loop_times; j++) {
            int ret = -1;
            strm.next_in  = (z_const Bytef*) inbuf;
            strm.next_out = output;
            if (compress) {
                blen = compressBound(stream_len);
                // ret = compress2((Bytef *)output, (uLongf *)&blen, (Bytef *)inbuf, (uLong)stream_len, 1);
                /***********************************************/
                strm.avail_in  = stream_len;
                strm.avail_out = blen;
                err = deflate(&strm, Z_FINISH);
                ret = (err == Z_STREAM_END ? Z_OK : err);
                deflateReset(&strm);
                /***********************************************/
                if (ret != Z_OK && ret != Z_BUF_ERROR) {
                    printf("compres error, ret = %d\n", ret);
                    return -1;
                }
            } else {
                // ret = uncompress((Bytef *)output, &output_sz, (const Bytef *)inbuf, blen);
                /***********************************************/
                strm.avail_in  = blen;
                strm.avail_out = output_sz;
                err = inflate(&strm, Z_FINISH);
                ret = (err == Z_STREAM_END ? Z_OK : err);
                inflateReset(&strm);
                /***********************************************/
                if (ret < 0) {
                    printf("uncompres error, ret = %d\n", ret);
                    return -1;
                }
            }
        }

        if (compress) {
            (void)deflateEnd(&strm);
        } else {
            (void)inflateEnd(&strm);
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
        float speed1 = 1000000.0 / time1 * loop_times * multi * stream_len / (1 << 30);
        printf("kaezip %s perf result:\n", compress ? "compress" : "decompress");
        printf("     time used: %lu us, speed = %.3f GB/s\n", time1, speed1);
    }

    return 0;
}

int do_perf(const char* fileName, int multi, int loop_times)
{
    void* input = NULL;
    uLong input_size = read_inputFile(fileName, &input);
    if (input_size == 0 || !input) {
        fprintf(stderr, "read %s failed!\n", fileName);
        return -1;
    }

    uLong output_size = compressBound(input_size);
    void* output = malloc(output_size * sizeof(Bytef));
    if (!output) {
        fprintf(stderr, "output malloc failed!\n");
        free(input);
        return -1;
    } else {
        fprintf(stdout, "malloc success, output_size_bound is %luB = %.3lfMB\n\n", 
            output_size, 1.0 * output_size / (1 << 20));
    }

    int ret = do_multi_perf(multi, input_size, loop_times, 1, output, output_size, input, input_size);
    free(input);
    free(output);

    return ret;
}

//  ./test -f ooffice -m 4 -n 1000

int main(int argc, char **argv)
{
    const char *optstring = "f:m:n:";
    char fileName[64] = {0};
    int multi = 4;
    int loop_times = 1000;
    int o = 0;
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (o) {
            case 'f':
                strcpy(fileName, optarg);
                break;
            case 'm':
                multi = atoi(optarg);
                break;
            case 'n':
                loop_times = atoi(optarg);
                break;
            default:
                break;
        }
    }

    if (argc <= 1) {
        printf("\ndefault input parameter used\n");
    } 
    printf("fileName : %s\nmulti_num : %d\nloop_times : %d\n\n", fileName, multi, loop_times);
    (void)do_perf(fileName, multi, loop_times);
    
    return 0;
}
