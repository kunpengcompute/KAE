#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <string.h>
#include <assert.h>

#define LEVEL 6
#define CHUNK 1001

int compressFile(const char *srcfile, unsigned long *srclen, const char *destfile, unsigned long *destlen);
int decompressFile(const char *srcfile, unsigned long *srclen, const char *destfile, unsigned long *destlen);

int main(int argc, char *argv[]) 
{
    unsigned long s1, s2;
    int ret;
    if (argc != 4) {
        printf("usage %s -[c|d] srcfile destfile\n", argv[0]);
        printf("-c\tcompress the srcfile, and save compressed file as destFile.\n");
        printf("-d\tdecompress the srcfile, and save decompressed file as destFile.\n");
        return 0;
    }

    /* compress */
    if (strcmp(argv[1], "-c") == 0) {
        ret = compressFile(argv[2], &s1, argv[3], &s2);
        if (ret == Z_OK) {
            printf("Compression complete, Before:%ld Bytes(s)\tAfter:%ld Bytes(s)\t Ratio:%0.2f%%\n", s1, s2, 1.0f * s2 / s1 * 100);
            return 0;
        }
        else {
            printf("Compression failed, error code=%d\n", ret);
            return ret;
        }
    }

    /* decompress */
    if (strcmp(argv[1], "-d") == 0) {
        ret = decompressFile(argv[2], &s1, argv[3], &s2);
        if (ret == Z_OK) {
            printf("Deompression complete, Before:%ld Bytes(s)\tAfter:%ld Bytes(s)\t Ratio:%0.2f%%\n", s1, s2, 1.0f * s2 / s1 * 100);
            return 0;
        }
        else {
            printf("Deompression failed, error code=%d\n", ret);
            return ret;
        }
    }

    return 0;
}

// compress a file
int compressFile(const char *src, unsigned long *srclen, const char *dest, unsigned long *destlen)
{
    int ret, flush;
    unsigned have;
    z_stream stream;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    *srclen = 0;
    *destlen = 0;

    /* allocate deflate state */
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    ret = deflateInit(&stream, LEVEL);
    if (ret != Z_OK) {
        printf("z_stream init failed.\n");
        return ret;
    }

    /* open srcfile & destfile */
    FILE *srcfile = fopen(src, "rb");
    if (srcfile == NULL) {
        printf("open input file failed.\n");
        return -1;
    }
    FILE *destfile = fopen(dest, "wb");
    if (destfile == NULL) {
        printf("open output file failed.\n");
        return -1;
    }

    /* Compress Data from Srcfile to Destfile */
    do {
        // read chunk data from srcfile
        // stream.avail_in: 待压缩的数据的字节大小
        stream.avail_in = fread(in, sizeof(char), CHUNK, srcfile);
        *srclen += stream.avail_in;
        if (ferror(srcfile)) {
            (void)deflateEnd(&stream);
            return Z_ERRNO;
        }
        // 设置刷新方式
        /**
          1. Z_NO_FLUSH：普通压缩操作，压缩器将尽可能多地将输入数据压缩到输出缓冲区中，但不保证输出缓冲区被填满。
          2. Z_SYNC_FLUSH：同步刷新操作，压缩器将立即将尽可能多的输入数据压缩到输出缓冲区中，并且保证输出缓冲区被填满。
          3. Z_FULL_FLUSH：完全刷新操作，类似于 Z_SYNC_FLUSH，但同时清空压缩器的内部状态，使得压缩后的数据可以独立解压缩。
          4. Z_FINISH：结束操作，表示输入数据已经全部传递给压缩器，压缩器在压缩完成后返回。
        */
        flush = feof(srcfile) ? Z_FINISH : Z_NO_FLUSH;
        stream.next_in = in;
        
        /* 将输入数据传递给deflate */
        do {
            // 输出缓冲区的大小
            stream.avail_out = CHUNK;
            stream.next_out = out;
            ret = deflate(&stream, flush);
            assert(ret != Z_STREAM_ERROR);
            // 调用deflate后，avail_out会变为剩下的还没有使用的最大空间数
            have = CHUNK - stream.avail_out;
            // fwrite 返回实际写入的数据个数
            if (fwrite(out, sizeof(char), have, destfile) != have || ferror(destfile)) {
                (void)deflateEnd(&stream);
                return Z_ERRNO;
            }
            *destlen += have;
        } while (stream.avail_out == 0);
        assert (stream.avail_in == 0);
    } while (flush != Z_FINISH);
    assert (ret == Z_STREAM_END);

    // printf("total_in: %lu", stream.total_in);
    // printf("total_out: %lu", stream.total_out);
    (void)deflateEnd(&stream);
    return Z_OK;
}

//decompress a file
int decompressFile(const char *src, unsigned long *srclen, const char *dest, unsigned long *destlen)
{
    int ret;
    unsigned have;
    z_stream stream;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    *srclen = 0;
    *destlen = 0;

    /* allocate deflate state */
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;
    ret = inflateInit(&stream);
    if (ret != Z_OK) {
        return ret; 
    }

    /* open srcfile & destfile */
    FILE *srcfile = fopen(src, "rb");
    if (srcfile == NULL) {
        printf("open input file failed.\n");
        return -1;
    }
    FILE *destfile = fopen(dest, "wb");
    if (destfile == NULL) {
        printf("open output file failed.\n");
        return -1;
    }

    /* Decompress */
    do {
        stream.avail_in = fread(in, sizeof(char), CHUNK, srcfile);
        *srclen += stream.avail_in;
        if (ferror(srcfile)) {
            (void)deflateEnd(&stream);
            return Z_ERRNO;
        }
        if (stream.avail_in == 0) {
            break;
        }
        stream.next_in = in;
        do {
            stream.avail_out = CHUNK;
            stream.next_out = out;
            ret = inflate(&stream, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&stream);
                return ret;
            }
            have = CHUNK - stream.avail_out;
            if (fwrite(out, sizeof(char), have, destfile) != have || ferror(destfile)) {
                (void)deflateEnd(&stream);
                return Z_ERRNO;
            }
            *destlen += have;
        } while (stream.avail_out == 0);
        assert (stream.avail_in == 0);
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&stream);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}