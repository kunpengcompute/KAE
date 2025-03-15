#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <unistd.h>  // 包含 sleep 函数的头文件

#define CHUNKIN 512
#define CHUNKOUT 1024

int main(int argc, char *argv[]) 
{
    int ret, flush;
    unsigned have;
    z_stream stream;
    unsigned char in[CHUNKIN];
    unsigned char out[CHUNKOUT];
    FILE *destfile = fopen("flink.zlib", "wb");

    for (int i = 0; i < CHUNKIN; i++) {
        in[i] = '1';
    }

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    ret = deflateInit2_(&stream, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY, "1.2.11", sizeof(z_stream));
    
    // 1.
    stream.avail_in = 7;
    stream.next_in = in;
    stream.avail_out = CHUNKOUT;
    stream.next_out = out;
    ret = deflate(&stream, Z_NO_FLUSH);
    have = CHUNKOUT - stream.avail_out;
    fwrite(out, sizeof(char), have, destfile);

    // last block
    stream.avail_in = 10;
    stream.next_in = in;
    stream.avail_out = CHUNKOUT;
    stream.next_out = out;
    ret = deflate(&stream, Z_FINISH);
    printf("ret: %d\n", ret);
    have = CHUNKOUT - stream.avail_out;
    fwrite(out, sizeof(char), have, destfile);

    // deflateEnd
    fclose(destfile);
    (void)deflateEnd(&stream);

    printf("deflateEnd\n");

    return Z_OK;
}

/**
gcc deflate.c -o deflate -lz -g -L/usr/local/kaezip/lib -I /usr/local/kaezip/include/ -Wl,-rpath=/usr/local/kaezip/lib
*/