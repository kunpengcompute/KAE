#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>

int g_kae_device_num;

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

static size_t write_outputFile(const char* outFileName, void* output, uLong output_size)
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

typedef struct {
    uLong stream_len;
    int loop_times;
    int windowBits;
    int level;
    int compress;
    void* output;
    uLong output_sz;
    void* inbuf;
    uLong blen;
    const char* out_filename;
    uLong decomp_len;
    int index;
} Multi_task_stru;

void* do_multi_task(void* args)
{
    Multi_task_stru* task_stru = (Multi_task_stru*)args;
    uLong stream_len = task_stru->stream_len;
    int loop_times = task_stru->loop_times;
    int windowBits = task_stru->windowBits;
    int level = task_stru->level;
    int compress = task_stru->compress;
    void* output = task_stru->output;
    uLong output_sz = task_stru->output_sz;
    void* inbuf = task_stru->inbuf;
    uLong blen = task_stru->blen;
    const char* out_filename = task_stru->out_filename;
    pthread_t tid = pthread_self();

    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet); // 清空cpuSet
    CPU_SET(task_stru->index, &cpuSet);

    // 设置CPU亲和性
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuSet), &cpuSet) == -1) {
        fprintf(stderr, "Failed to set CPU affinity\n");
    }

    z_stream strm = {0};
    if (compress) {
        (void)deflateInit2_(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY, "1.2.11", sizeof(z_stream));
    } else {
        (void)inflateInit2_(&strm, windowBits, "1.2.11", sizeof(z_stream));
    }

    int j, ret, err;
    for (j = 0; j < loop_times; j++) {
        strm.next_in  = (z_const Bytef*) inbuf;
        strm.next_out = output;
        if (compress) {
            blen = compressBound(stream_len);
            strm.avail_in  = stream_len;
            strm.avail_out = blen;
            err = deflate(&strm, Z_FINISH);
            ret = (err == Z_STREAM_END ? Z_OK : err);
            if (j == loop_times - 1) {
                output_sz = strm.total_out;
                double compress_rate = 100.0 * output_sz / stream_len;
                fprintf(stdout, "[tid %lu] compress_size is %luB = %.3lfMB, compress_rate is %.3lf%%\n",
                    tid, output_sz, 1.0 * output_sz / (1 << 20), compress_rate);
                if (out_filename) {
                    write_outputFile(out_filename, output, output_sz);
                }
            }
            deflateReset(&strm);
            /***********************************************/
            if (ret != Z_OK && ret != Z_BUF_ERROR) {
                fprintf(stderr, "compres error, ret = %d\n", ret);
                goto free_init;
            }
        } else {
            strm.avail_in  = blen;
            strm.avail_out = output_sz;
            err = inflate(&strm, Z_FINISH);
            ret = (err == Z_STREAM_END ? Z_OK : err);
            if (j == loop_times - 1) {
                output_sz = strm.total_out;
                task_stru->decomp_len = strm.total_out;
                fprintf(stdout, "[tid %lu] uncompress_size is %luB = %.3lfMB\n",
                    tid, output_sz, 1.0 * output_sz / (1 << 20));

                if (out_filename) {
                    write_outputFile(out_filename, output, output_sz);
                }
            }
            inflateReset(&strm);
            /***********************************************/
            if (ret < 0) {
                printf("uncompres error, ret = %d\n", ret);
                goto free_init;
            }
        }
    }
free_init:
    if (compress) {
        (void)deflateEnd(&strm);
    } else {
        (void)inflateEnd(&strm);
    }
    return NULL;
}

int do_multi_thread_perf(int multi, uLong stream_len, int loop_times, int windowBits, int level, int compress,
    void* output, uLong output_sz, void* inbuf, uLong blen, const char* out_filename)
{
    int err;
    pthread_t ntid[2048];
    struct timeval start, stop;
    Multi_task_stru task_stru = {stream_len, loop_times, windowBits, level, compress, output, output_sz,
        inbuf, blen, out_filename, 0};
    

    int half_device_num = g_kae_device_num / 2;
    int core_id_arr[] = {0, 64};
    core_id_arr[1] = get_nprocs_conf() / 2;

    gettimeofday(&start, NULL);
    for (int i = 0; i < multi; ++i) {
        task_stru.index = (core_id_arr[i%half_device_num] + i/half_device_num) % core_id_arr[1];
        err = pthread_create(&ntid[i], NULL, do_multi_task, &task_stru);
        if (err) {
            fprintf(stderr, "create multi thread perf failed! errno : %d\n", err);
            return -1;
        } else {
            fprintf(stderr, "create thread %lu\n", ntid[i]);
        }
    }

    for (int i = 0; i < multi; ++i) {
        err = pthread_join(ntid[i], NULL);
        if (err) {
            fprintf(stderr, "join multi thread perf failed! errno : %d\n", err);
            return -1;
        }
    }
    gettimeofday(&stop, NULL);

    uLong time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
    stream_len = compress ? stream_len : task_stru.decomp_len;
    float speed1 = 1000000.0 / time1 * loop_times * multi * stream_len / (1 << 30);
    printf("%d multi thread kaezip %s perf result:\n", multi, compress ? "compress" : "decompress");
    printf("     time used: %lu us, speed = %.3f GB/s\n", time1, speed1);
    return 0;
}

int do_multi_process_perf(int multi, uLong stream_len, int loop_times, int windowBits, int level, int compress,
    void* output, uLong output_sz, void* inbuf, uLong blen, const char* out_filename)
{
    int i, j, err;
    int ret = 0;
    pid_t pid_child = 0;
    fflush(stdout);
    fflush(stderr);

    int pipefd[2] = {0};
    pipe(pipefd);

    int half_device_num = g_kae_device_num / 2;
    int core_id_arr[] = {0, 64};
    core_id_arr[1] = get_nprocs_conf() / 2;
    struct timeval start, stop;

    for (i = 0; i < multi; i++) {
        pid_child = fork();
        if (pid_child == 0 || pid_child == -1) {
            // 绑核操作
            cpu_set_t cpuSet;
            CPU_ZERO(&cpuSet); // 清空cpuSet
            // int core_id = i + (80 * (i % 2));
            CPU_SET(core_id, &cpuSet);    //  只使用1个die

            // 设置CPU亲和性
            if (pthread_setaffinity_np(pthread_self(), sizeof(cpuSet), &cpuSet) == -1) {
                fprintf(stderr, "Failed to set CPU affinity\n");
                return -1;
            }
            break;
        }
    }
    gettimeofday(&start, NULL);
    if (pid_child == 0) {
        z_stream strm;
        strm.zalloc   = (alloc_func)0;
        strm.zfree    = (free_func)0;
        strm.opaque   = (voidpf)0;
        if (compress) {
            (void)deflateInit2_(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY, "1.2.11", sizeof(z_stream));
        } else {
            (void)inflateInit2_(&strm, windowBits, "1.2.11", sizeof(z_stream));
        }
        for (j = 0; j < loop_times; j++) {
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
                if (j == loop_times - 1) {
                    output_sz = strm.total_out;
                    double compress_rate = 100.0 * output_sz / stream_len;
                    if (out_filename) {
                        write_outputFile(out_filename, output, output_sz);
                    }
                }
                deflateReset(&strm);
                /***********************************************/
                if (ret != Z_OK && ret != Z_BUF_ERROR) {
                    fprintf(stderr, "compress error, ret = %d\n", ret);
                    goto free_init;
                }
            } 
            else {
                // ret = uncompress((Bytef *)output, &output_sz, (const Bytef *)inbuf, blen);
                /***********************************************/
                strm.avail_in  = blen;
                strm.avail_out = output_sz;
                err = inflate(&strm, Z_FINISH);
                
                ret = (err == Z_STREAM_END ? Z_OK : err);
                if (j == loop_times - 1) {
                    output_sz = strm.total_out;

                    close(pipefd[0]);
                    char buffer[32] = {0};
                    sprintf(buffer, "%lu", output_sz);
                    write(pipefd[1], buffer, strlen(buffer) + 1);

                    if (out_filename) {
                        write_outputFile(out_filename, output, output_sz);
                    }
                }
                inflateReset(&strm);
                /***********************************************/
                if (ret < 0) {
                    printf("uncompres error, ret = %d\n", ret);
                    goto free_init;
                }
            }
        }
free_init:
        if (compress) {
            (void)deflateEnd(&strm);
        } else {
            (void)inflateEnd(&strm);
        }
    }

    if (pid_child > 0) {
        ret = -1;
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

        close(pipefd[1]);
        char buffer[32] = {0};
        read(pipefd[0], buffer, 32);
        char *endptr;
        output_sz = strtoul(buffer, &endptr, 10);

        stream_len = compress ? stream_len : output_sz;
        float speed1 = 1000000.0 / time1 * loop_times * multi * stream_len / (1 << 30);
        printf("%d multi process kaezip %s perf result:\n", multi, compress ? "compress" : "decompress");
        printf("     time used: %lu us, speed = %.3f GB/s\n", time1, speed1);
    }

    return ret;
}

int do_compress_perf(const char* in_filename, const char* out_filename,
    int multi, uLong stream_len, int loop_times, int windowBits, int level, int use_thread)
{
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
    fprintf(stdout, "input_size is %luB\n", stream_len);

    uLong blen = compressBound(stream_len);
    uLong output_sz = blen;
    void *outbuf = malloc(output_sz * sizeof(uint8_t));
    if (outbuf == NULL) {
        return -1;
    }
    memset(outbuf, 0, output_sz);

    fprintf(stderr, "system cpu num is %ld\n", sysconf( _SC_NPROCESSORS_CONF));
    fprintf(stderr, "system enable cpu num is %ld\n\n", sysconf(_SC_NPROCESSORS_ONLN));

    int ret;
    if (use_thread) {
        ret = do_multi_thread_perf(multi, stream_len, loop_times, windowBits, level, 1, outbuf, output_sz, inbuf, blen, out_filename);
    } else {
        ret = do_multi_process_perf(multi, stream_len, loop_times, windowBits, level, 1, outbuf, output_sz, inbuf, blen, out_filename);
    }

    free(inbuf);
    free(outbuf);
    return ret;
}

int do_decompress_perf(const char* in_filename, const char* out_filename,
    int multi, int stream_len, int loop_times, int windowBits, int level, int use_thread)
{
    uLong blen = 0;
    void *inbuf = NULL;
    if (in_filename) {
        fprintf(stdout, "uncompress filename : %s\n", in_filename);
        stream_len = read_inputFile(in_filename, &inbuf);
        blen = stream_len;
    } else {
        inbuf = get_decompress_input(stream_len, &blen);
    }
    if (inbuf == NULL) {
        fprintf(stderr, "inbuf is NULL!\n");
        return -1;
    }
    fprintf(stdout, "input_size is %luB\n", blen);

    uLong output_sz = in_filename ? blen * 8 : stream_len;
    void *output = malloc(output_sz * sizeof(uint8_t));
    if (output == NULL) {
        return -1;
    }
    memset(output, 0, output_sz);

    int ret;
    if (use_thread) {
        ret = do_multi_thread_perf(multi, stream_len, loop_times, windowBits, level, 0, output, output_sz, inbuf, blen, out_filename);
    } else {
        ret = do_multi_process_perf(multi, stream_len, loop_times, windowBits, level, 0, output, output_sz, inbuf, blen, out_filename);
    }

    free(inbuf);
    free(output);
    return ret;
}

void usage(void)
{
    printf("usage: \n");
    printf("  -m: multi process \n");
    printf("  -t: multi thread \n");
    printf("  -l: stream length(KB)\n");
    printf("  -w: windowBits\n");
    printf("  -v: compress level(1~9)\n");
    printf("  -f: input  filename(-l useless if this work)\n");
    printf("  -o: output filename\n");
    printf("  -n: loop times\n");
    printf("  -d: compress or decompress\n");
    printf("  example: ./kaezip_perf -m 2 -l 1024 -n 1000\n");
    printf("           ./kaezip_perf -d -m 2 -l 1024 -n 1000\n");
}

int main(int argc, char **argv)
{
    const char *optstring = "dm:t:l:n:w:f:o:v:h";
    int o = 0;
    int multi = 2;
    int use_thread = 0;
    int level = 6;
    uLong stream_len = 1024;
    int loop_times = 1000;
    int compress = 1;
    int windowBits = 15;
    char input_filename[128] = {0};
    char output_filename[128] = {0};
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (o) {
            case 'm':
                multi = atoi(optarg);
                break;
            case 't':
                multi = atoi(optarg);
                use_thread = 1;
                break;
            case 'l':
                stream_len = atoi(optarg);
                break;
	        case 'v':
                level = atoi(optarg);
                break;
            case 'n':
                loop_times = atoi(optarg);
                break;
            case 'w':
                windowBits = atoi(optarg);
                break;
            case 'd':
                compress = 0;
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

    printf("kaezip perf parameter: multi process %d, stream length: %lu(KB), loop times: %d, windowBits : %d, level : %d\n",
        multi, stream_len, loop_times, windowBits, level);

    FILE* fshell = popen("lspci | grep ZIP | wc -l", "r");
    char res_buf[128] = {0};
    fread(res_buf, sizeof(res_buf), 1, fshell);
    g_kae_device_num = atoi(res_buf);
    fprintf(stderr, "g_kae_device_num %d\n", g_kae_device_num);
    pclose(fshell);

    const char* in_filename  = input_filename[0] == 0 ? NULL : input_filename;
    const char* out_filename = output_filename[0]== 0 ? NULL : output_filename;
    stream_len *= 1024;
    if (compress) {
        return do_compress_perf(in_filename, out_filename, multi, stream_len, loop_times, windowBits, level, use_thread);
    } else {
        return do_decompress_perf(in_filename, out_filename, multi, stream_len, loop_times, windowBits, level, use_thread);
    }
}

