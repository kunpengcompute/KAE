#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <openssl/engine.h>
#include "openssl/evp.h"
#include "openssl/conf.h"

#define KAE_PATH "/usr/local/lib/engines-1.1/libkae.so"

int init_engine(ENGINE *e, const char *id)
{
    if (e == NULL) {
        return 1;
    }
    if (strcmp(id, "kae") != 0 || !ENGINE_ctrl_cmd_string(e, "SO_PATH", KAE_PATH, 0)) {
        return 1;
    }
    if (!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
        return 1;
    }
    if (!ENGINE_init(e)) {
        return 1;
    }
    return 0;
}

ENGINE *get_engine(const char *id)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    init_engine(e, id);
    return e;
}

uint8_t *get_digest_input(int input_sz)
{
    uint8_t *inbuf = (uint8_t *)malloc(input_sz * sizeof(uint8_t));
    if (inbuf == NULL) {
        free(inbuf);
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

int do_md5_multi_perf(int multi, ENGINE *impl, int loop_times, uint8_t *inbuf, size_t insize, uint8_t *outbuf, unsigned int outsize)
{
    int i,j;
    pid_t pid_child = 0;
    const EVP_MD *evp_md5 = EVP_md5();
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    for (i = 0; i < multi; i++) {
        pid_child = fork();
        if (pid_child == 0 || pid_child == -1) {
            break;
        }
    }

    if (pid_child == 0) {
        for(j = 0; j < loop_times; j++)
        {
            outsize = insize + 16;
            int cret = EVP_Digest(inbuf, insize, outbuf, &outsize, evp_md5, impl);
            if (!cret) {
                printf("evp_md5 error!");
                return -1;
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
        long unsigned int time1 = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
        float speed1 = 1000000.0 / time1 * loop_times * multi * insize / 1000;
        printf("md5 digest perf result:\n");
        printf("     time used: %lu us, speed = %.3f KB/s\n", time1, speed1);
    }
    return 0;
}

int do_evp_md5_perf(int multi, ENGINE *impl, int stream_len, int loop_times)
{
    uint8_t *inbuf = get_digest_input(stream_len);
    if (inbuf == NULL) {
        return -1;
    }
    
    unsigned int output_sz = stream_len + 16;
    uint8_t *outbuf = (uint8_t *)malloc(output_sz * sizeof(uint8_t));
    if (outbuf == NULL) {
        free(outbuf);
        return -1;
    }
    memset(outbuf, 0, output_sz);

    int ret = do_md5_multi_perf(multi, impl, loop_times, inbuf, stream_len, outbuf, output_sz);
    free(inbuf); 
    inbuf = NULL;
    free(outbuf); 
    outbuf = NULL;
    return ret;
}

void usage(void)
{
    printf("usage: \n");
    printf("  -m: multi process \n");
    printf("  -e: engine id \n");
    printf("  -l: block size(KB)\n");
    printf("  -n: loop times\n");
    printf("  example: ./md5_speed -m 2 -l 1024 -n 1000\n");
}

// [root@localhost test]# ./md5_speed
// usage:
//   -m: multi process
//   -e: engine id
//   -l: stream length(KB)
//   -n: loop times
//   example: ./md5_speed -m 2 -l 1024 -n 1000
// 
// default input parameter used
// md5 perf parameter: multi process 2, engine id: (null), block size: 1024(B), loop times: 1000
// md5 digest perf result:
//      time used: 4008 us, speed = 510978.031 KB/s

int main(int argc, char **argv)
{
    ENGINE_load_builtin_engines();
    int o = 0;
    const char *optstring = "m:e:l:n:h";
    int multi = 2;
    int stream_len = 1024;
    int loop_times = 1000;
    const char *engine_id = NULL;
    ENGINE *impl = NULL;
    int ret = 0;
    while ((o = getopt(argc, argv, optstring)) != -1) {
        if(optstring == NULL) continue;
        switch (o) {
            case 'm':
                multi = atoi(optarg);
                break;
            case 'e':
                engine_id = optarg;
                impl = get_engine(engine_id);
                break;
            case 'l':
                stream_len = atoi(optarg);
                break;
            case 'n':
                loop_times = atoi(optarg);
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
    printf("md5 perf parameter: multi process %d, engine id: %s, block size: %d(B), loop times: %d\n", multi, engine_id, stream_len, loop_times);
    ret = do_evp_md5_perf(multi, impl, stream_len, loop_times);

    if (impl)
    {
        ENGINE_free(impl);
    }
    return ret;
}

