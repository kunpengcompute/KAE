#ifndef FUNC_COMMON_H
#define FUNC_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <zstd.h>      // presumes zstd library is installed

#include "common.h"

typedef struct {
    void* buffIn;
    void* buffOut;
    size_t buffInSize;
    size_t buffOutSize;
    ZSTD_CCtx* cctx;
} Resources;

struct CompressOut {
    void *oBuff; // 待压缩的缓冲区，original buff
    size_t oSize; // 待压缩的字节数
    void *cBuff; // 压缩后的缓冲区，compressed buff
    size_t const cSize; // 压缩后的字节数

    CompressOut(void *oBuff, size_t oSize, void *cBuff, size_t cSize)
        : oBuff(oBuff), oSize(oSize), cBuff(cBuff), cSize(cSize) {}
};

struct DecompressOut {
    void *dBuff; // 解压后的缓冲区，decompressed buff
    size_t const dSize; // 解压后的字节数

    DecompressOut(void *buff, size_t size) : dBuff(buff), dSize(size) {}
};

CompressOut DoCompress(int streamLen, int cLevel, int nbThreads);
CompressOut DoCompressStream2(int streamLen, int cLevel, int nbThreads);
DecompressOut Decompress(CompressOut compressOut);
DecompressOut DecompressStream(CompressOut compressOut);

#endif /* FUNC_COMMON_H */