/* zpipe.c: example of proper use of zlib's inflate() and deflate()
   Not copyrighted -- provided to the public domain
   Version 1.4  11 December 2005  Mark Adler */

/* Version history:
   1.0  30 Oct 2004  First version
   1.1   8 Nov 2004  Add void casting for unused return values
                     Use switch statement for inflate() return values
   1.2   9 Nov 2004  Add assertions to document zlib guarantees
   1.3   6 Apr 2005  Remove incorrect assertion in inf()
   1.4  11 Dec 2005  Add hack to avoid MSDOS end-of-line conversions
                     Avoid some compiler warnings for input and output buffers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "zlib.h"
//#include "zconf.h"
#include <pthread.h>

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#include <fcntl.h>
#include <io.h>
#define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#define SET_BINARY_MODE(file)
#endif

#define CHUNK 16384

struct buff_info {
    char *buff;
    int buff_size;
};
/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files. */
int def(char *source, int buff_size)
{
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    int b_size = buff_size;

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit(&strm, 6);
    if (ret != Z_OK) {
        return ret;
    }

    /* compress until end of file */
    do {
        // strm.avail_in = fread(in, 1, CHUNK, source);
        if (b_size > CHUNK) {
            strm.avail_in = CHUNK;
            memcpy(in, source, CHUNK);
            b_size -= CHUNK;
            flush = Z_NO_FLUSH;
        } else {
            strm.avail_in = b_size;
            memcpy(in, source, b_size);
            b_size = 0;
            flush = Z_FINISH;
        }

        // flush = Z_PARTIAL_FLUSH;
        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);   /* no bad return value */
            assert(ret != Z_STREAM_ERROR); /* state not clobbered */
            have = CHUNK - strm.avail_out;
            // if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
            // (void)deflateEnd(&strm);
            // return Z_ERRNO;
            // }
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0); /* all input will be used */

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END); /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
}

/* Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
int inf(char *source, int buff_size)
{
    int ret;
    unsigned have = 0;
    unsigned h_size = 0;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    int b_size = buff_size;
    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        return ret;
    }
    // char filename[10] = rand() + 'a';
    // prinf("filename is %s\n", filename );
    // FILE *dest = fopen(filename,"wb+");
    /* decompress until deflate stream ends or end of file */
    do {
        if (b_size > CHUNK) {
            strm.avail_in = CHUNK;
            memcpy(in, source, CHUNK);
            b_size -= CHUNK;
        } else {
            strm.avail_in = b_size;
            memcpy(in, source, b_size);
            b_size = 0;
        }
        // if (ferror(source)) {
        // (void)inflateEnd(&strm);
        // return Z_ERRNO;
        // }
        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_PARTIAL_FLUSH);
            // printf("inflate ret is %d\n", ret);
            assert(ret != Z_STREAM_ERROR); /* state not clobbered */
            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR; /* and fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    (void)inflateEnd(&strm);
                    return ret;
            }
            have = (CHUNK - strm.avail_out);
            h_size += have;
            // printf("have size is %d\n", have);
            // have = CHUNK - strm.avail_out;
            // if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
            // (void)inflateEnd(&strm);
            // return Z_ERRNO;
            // }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    // printf("in size is %d\n", buff_size);
    // printf("out size is %d\n", h_size);
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

void *inf_t(void *b_info)
{
    int i = 0;
    for (i; i < 3; i++) {
        inf(((struct buff_info *)b_info)->buff, ((struct buff_info *)b_info)->buff_size);
    }

    sleep(10);
    for (i = 0; i < 3; i++) {
        inf(((struct buff_info *)b_info)->buff, ((struct buff_info *)b_info)->buff_size);
    }
    sleep(10);
    for (i = 0; i < 3; i++) {
        inf(((struct buff_info *)b_info)->buff, ((struct buff_info *)b_info)->buff_size);
    }

}

void *def_t(void *b_info)
{
    int i = 0;
    for (i; i < 3; i++) {
        def(((struct buff_info *)b_info)->buff, ((struct buff_info *)b_info)->buff_size);
    }

    sleep(10);
    for (i = 0; i < 3; i++) {
        def(((struct buff_info *)b_info)->buff, ((struct buff_info *)b_info)->buff_size);
    }
    sleep(10);
    for (i = 0; i < 3; i++) {
        def(((struct buff_info *)b_info)->buff, ((struct buff_info *)b_info)->buff_size);
    }

}

#define THREAD_NUM 300
int inf_thread(char *in_buff, int buff_size)
{
    int error = -1;
    int i = 0;
    pthread_t tidp;
    struct buff_info b_info;
    b_info.buff = in_buff;
    b_info.buff_size = buff_size;
    for (i; i < THREAD_NUM; i++) {
        error = pthread_create(&tidp, NULL, (void *)inf_t, (void *)&b_info);
        printf("inf pthread is created\n");
        if (error != 0) {
            printf("inf pthread is not created\n");
            return -1;
        }
    }

    sleep(50);
/*
    for (i = 0; i < THREAD_NUM; i++) {
        error = pthread_create(&tidp, NULL, (void *)inf_t, (void *)&b_info);
        printf("pthread is created  ");
        if (error != 0) {
            printf("pthread is not created  ");
            return -1;
        }
    }
    sleep(50);
*/
    return 0;
}
int def_thread(char *in_buff, int buff_size)
{
    int error = -1;
    int i = 0;
    pthread_t tidp;
    struct buff_info b_info;
    b_info.buff = in_buff;
    b_info.buff_size = buff_size;
    for (i; i < THREAD_NUM; i++) {
        error = pthread_create(&tidp, NULL, (void *)def_t, (void *)&b_info);
        printf("def pthread is created\n");
        if (error != 0) {
            printf("def pthread is not created\n");
            return -1;
        }
    }

    sleep(50);
/*
    for (i = 0; i < THREAD_NUM; i++) {
        error = pthread_create(&tidp, NULL, (void *)def_t, (void *)&b_info);
        printf("pthread is created  ");
        if (error != 0) {
            printf("pthread is not created  ");
            return -1;
        }
    }
    sleep(50);
*/
    return 0;
}

/* report a zlib or i/o error */
void zerr(int ret)
{
    fputs("zpipe: ", stderr);
    switch (ret) {
        case Z_ERRNO:
            if (ferror(stdin)) {
                fputs("error reading stdin\n", stderr);
            }
            if (ferror(stdout)) {
                fputs("error writing stdout\n", stderr);
            }
            break;
        case Z_STREAM_ERROR:
            fputs("invalid compression level\n", stderr);
            break;
        case Z_DATA_ERROR:
            fputs("invalid or incomplete deflate data\n", stderr);
            break;
        case Z_MEM_ERROR:
            fputs("out of memory\n", stderr);
            break;
        case Z_VERSION_ERROR:
            fputs("zlib version mismatch!\n", stderr);
    }
}
#define BUFF_SIZE (1024 * 1024 * 1024)

/* compress or decompress from stdin to stdout */
int main(int argc, char **argv)
{
    int ret;
    char *in_buffer = NULL;
    in_buffer = malloc(BUFF_SIZE*sizeof(char));
    if(NULL == in_buffer)
    {
        printf("malloc failed");
        return -1;
    }
    memset(in_buffer, 0, BUFF_SIZE*sizeof(char));
    int in_buffer_size = 0;
    /* avoid end-of-line conversions */
    SET_BINARY_MODE(stdin);
    SET_BINARY_MODE(stdout);

    /* do compression if no arguments */

    if (argc == 1) {
        in_buffer_size = fread(in_buffer, 1, CHUNK, stdin);
        printf("in_buffer_size is %d\n", in_buffer_size);
        ret = def_thread(in_buffer, in_buffer_size);
        if (ret != Z_OK) {
            zerr(ret);
        }

        return ret;
    }
    /* do decompression if -d specified */
    else if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        in_buffer_size = fread(in_buffer, 1, CHUNK, stdin);
        printf("in_buffer_size is %d\n", in_buffer_size);
        ret = inf_thread(in_buffer, in_buffer_size);
        if (ret != Z_OK) {
            zerr(ret);
        }
        return ret;
    }

    /* otherwise, report usage */
    else {
        fputs("zpipe usage: zpipe [-d] < source > dest\n", stderr);
        return 1;
    }
    free(in_buffer);
    in_buffer = NULL;
}
