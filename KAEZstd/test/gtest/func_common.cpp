#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <zstd.h>      // presumes zstd library is installed

#include "func_common.h"
#include "common.h"

enum CompressFunc {
    ZSTD_COMPRESS_STREAM2,
    ZSTD_COMPRESS,
};

// 功能：生成随机压缩输入
static uint8_t *CompressInputGet(size_t inputSize)
{
    uint8_t *inbuf = (uint8_t *)malloc_orDie(inputSize * sizeof(uint8_t));

    srand((unsigned int)time(NULL));

    for (int i = 0; i < inputSize; i++) {
        inbuf[i] = (uint8_t)rand() % 254 + 1;
    }

    return inbuf;
}

static Resources CompressCreateResources(uint8_t *inbuf, int streamLen, int cLevel, int nbThreads)
{
    Resources ress;
    ress.buffInSize = streamLen;
    ress.buffOutSize = ZSTD_compressBound(streamLen);
    ress.buffIn = inbuf;
    ress.buffOut = malloc_orDie(ress.buffOutSize);
    ress.cctx = ZSTD_createCCtx();
    CHECK(ress.cctx != NULL, "ZSTD_createCCtx() failed!");

    CHECK_ZSTD( ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_compressionLevel, cLevel) );
    ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_nbWorkers, nbThreads);

    return ress;
}

// 功能：块压缩。一次性将所有输入都输入压缩
// input @streamLen: 待压缩的字节，单位Byte
// input @clevel: 压缩等级
// input @nbThreads: 压缩使用的线程个数
CompressOut DoCompress(int streamLen, int cLevel, int nbThreads)
{
    // 生成随机输入
    uint8_t *inbuf = CompressInputGet(streamLen);

    // 初始化
    Resources const ress = CompressCreateResources(inbuf, streamLen, cLevel, nbThreads);

    /* Compress using the context.
    * If you need more control over parameters, use the advanced API:
    * ZSTD_CCtx_setParameter(), and ZSTD_compress2().
    */
    size_t const cSize = ZSTD_compressCCtx(ress.cctx, ress.buffOut, ress.buffOutSize,
        ress.buffIn, ress.buffInSize, cLevel);
    CHECK_ZSTD(cSize);

    ZSTD_freeCCtx(ress.cctx);

    return CompressOut(inbuf, streamLen, ress.buffOut, cSize);
}

static Resources CompressStream2CreateResources(int cLevel, int nbThreads)
{
    Resources ress;
    ress.buffInSize = ZSTD_CStreamInSize();   /* can always read one full block */
    ress.buffOutSize= ZSTD_CStreamOutSize();  /* can always flush a full block */
    ress.buffIn = malloc_orDie(ress.buffInSize);
    ress.buffOut= malloc_orDie(ress.buffOutSize);
    ress.cctx = ZSTD_createCCtx();
    CHECK(ress.cctx != NULL, "ZSTD_createCCtx() failed!");

    /* Set any compression parameters you want here.
     * They will persist for every compression operation.
     * Here we set the compression level, and enable the checksum.
     */
    CHECK_ZSTD( ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_compressionLevel, cLevel) );
    CHECK_ZSTD( ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_checksumFlag, 1) );
    ZSTD_CCtx_setParameter(ress.cctx, ZSTD_c_nbWorkers, nbThreads);
    return ress;
}

static size_t ReadFromInput(void *buffer, size_t sizeToRead, uint8_t *src, int totalBytesLeft)
{
    int cpySize = (sizeToRead <= totalBytesLeft ? sizeToRead : totalBytesLeft);
    memcpy(buffer, src, cpySize);
    return cpySize;
}

static CompressOut DoCompressStream2Internal(Resources ress, uint8_t *inbuf, int streamLen)
{
    size_t const toRead = ress.buffInSize;
    size_t read;
    uint8_t *src = inbuf;
    void *cBuff = malloc_orDie(streamLen * 2); // 解压缓冲区长度为两倍，防止解压后比原大小还要大
    uint8_t *dst = (uint8_t *)cBuff;
    int totalBytesLeft = streamLen; // 待压缩字节数
    int totalOutputSize = 0; // 压缩后的总字节数
    while ( (read = ReadFromInput(ress.buffIn, toRead, src, totalBytesLeft)) ) {
        totalBytesLeft -= read;
        src += read;
        /* This loop is the same as streaming_compression.c.
         * See that file for detailed comments.
         */
        int const lastChunk = (read < toRead);
        ZSTD_EndDirective const mode = lastChunk ? ZSTD_e_end : ZSTD_e_continue;

        ZSTD_inBuffer input = { ress.buffIn, read, 0 };
        int finished;
        do {
            ZSTD_outBuffer output = { ress.buffOut, ress.buffOutSize, 0 };
            size_t const remaining = ZSTD_compressStream2(ress.cctx, &output, &input, mode);
            CHECK_ZSTD(remaining);
            totalOutputSize += output.pos;
            if (totalOutputSize > streamLen * 2) {
                fprintf(stderr, "compress output size larger than twice the input size\n");
                exit(1);
            }
            memcpy(dst, ress.buffOut, output.pos);
            dst += output.pos;
            finished = lastChunk ? (remaining == 0) : (input.pos == input.size);
        } while (!finished);
        CHECK(input.pos == input.size,
              "Impossible: zstd only returns 0 when the input is completely consumed!");
    }

    return CompressOut(inbuf, streamLen, cBuff, totalOutputSize);
}

// 功能：流压缩。分多次压缩
CompressOut DoCompressStream2(int streamLen, int cLevel, int nbThreads)
{
    // 生成随机输入
    uint8_t *inbuf = CompressInputGet(streamLen);

    Resources const ress = CompressStream2CreateResources(cLevel, nbThreads);

    CompressOut const compressOut = DoCompressStream2Internal(ress, inbuf, streamLen);
    CHECK_ZSTD(compressOut.cSize);

    ZSTD_freeCCtx(ress.cctx);
    free(ress.buffIn);
    free(ress.buffOut);

    return compressOut;
}

// 功能：块解压缩。一次性读入所有字节解压
DecompressOut Decompress(CompressOut compressOut)
{
    void *const cBuff = compressOut.cBuff;
    size_t cSize = compressOut.cSize;

    unsigned long long const rSize = ZSTD_getFrameContentSize(cBuff, cSize);
    CHECK(rSize != ZSTD_CONTENTSIZE_ERROR, "not compressed by zstd!");
    CHECK(rSize != ZSTD_CONTENTSIZE_UNKNOWN, "original size unknown!");

    void* const rBuff = malloc_orDie((size_t)rSize);

    /* Decompress.
     * If you are doing many decompressions, you may want to reuse the context
     * and use ZSTD_decompressDCtx(). If you want to set advanced parameters,
     * use ZSTD_DCtx_setParameter().
     */
    size_t const dSize = ZSTD_decompress(rBuff, rSize, cBuff, cSize);
    CHECK_ZSTD(dSize);
    /* When zstd knows the content size, it will error if it doesn't match. */
    CHECK(dSize == rSize, "Impossible because zstd will check this condition!");

    return DecompressOut(rBuff, dSize);
}

// 功能：流解压缩。分多次解压
DecompressOut DecompressStream(CompressOut compressOut)
{
    size_t const buffInSize = ZSTD_DStreamInSize();
    void*  const buffIn  = malloc_orDie(buffInSize);

    size_t const buffOutSize = ZSTD_DStreamOutSize();  /* Guarantee to successfully flush at least one complete compressed block in all circumstances. */
    void*  const buffOut = malloc_orDie(buffOutSize);

    ZSTD_DCtx* const dctx = ZSTD_createDCtx();
    CHECK(dctx != NULL, "ZSTD_createDCtx() failed!");

    /* This loop assumes that the input file is one or more concatenated zstd
     * streams. This example won't work if there is trailing non-zstd data at
     * the end, but streaming decompression in general handles this case.
     * ZSTD_decompressStream() returns 0 exactly when the frame is completed,
     * and doesn't consume input after the frame.
     */
    void *dBuff = malloc_orDie(compressOut.oSize); // 解压后缓冲区，大小应该同原始数据大小一样
    uint8_t *dst = (uint8_t *)dBuff;
    uint8_t *src = (uint8_t *)compressOut.cBuff; // 待解压缓冲区
    size_t totalBytesLeft = compressOut.cSize; // 待解压字节数
    size_t totalOutputSize = 0; // 解压后的总字节数
    size_t const toRead = buffInSize;
    size_t read;
    size_t lastRet = 0;
    int isEmpty = 1;
    while ( (read = ReadFromInput(buffIn, toRead, src, totalBytesLeft)) ) {
        totalBytesLeft -= read;
        src += read;

        isEmpty = 0;
        ZSTD_inBuffer input = { buffIn, read, 0 };
        /* Given a valid frame, zstd won't consume the last byte of the frame
         * until it has flushed all of the decompressed data of the frame.
         * Therefore, instead of checking if the return code is 0, we can
         * decompress just check if input.pos < input.size.
         */
        while (input.pos < input.size) {
            ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
            /* The return code is zero if the frame is complete, but there may
             * be multiple frames concatenated together. Zstd will automatically
             * reset the context when a frame is complete. Still, calling
             * ZSTD_DCtx_reset() can be useful to reset the context to a clean
             * state, for instance if the last decompression call returned an
             * error.
             */
            size_t const ret = ZSTD_decompressStream(dctx, &output , &input);
            CHECK_ZSTD(ret);
            totalOutputSize += output.pos;
            if (totalOutputSize > compressOut.oSize) {
                fprintf(stderr, "decompress ouput size out of range\n");
                exit(1);
            }
            memcpy(dst, buffOut, output.pos);
            dst += output.pos;
            lastRet = ret;
        }
    }

    if (totalOutputSize != compressOut.oSize) {
        fprintf(stderr, "decompress output size wrong\n");
        exit(1);
    }

    if (isEmpty) {
        fprintf(stderr, "input is empty\n");
        exit(1);
    }

    if (lastRet != 0) {
        /* The last return value from ZSTD_decompressStream did not end on a
         * frame, but we reached the end of the file! We assume this is an
         * error, and the input was truncated.
         */
        fprintf(stderr, "EOF before end of stream: %zu\n", lastRet);
        exit(1);
    }

    ZSTD_freeDCtx(dctx);
    free(buffIn);
    free(buffOut);

    return DecompressOut(dBuff, totalOutputSize);
}