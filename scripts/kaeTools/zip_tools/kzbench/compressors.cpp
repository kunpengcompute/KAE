#include "compressors.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h> // memcpy
#ifdef ENABLE_QAT
#include "qatzip.h"
#include "qatseqprod.h"
#endif

#ifndef MAX
    #define MAX(a,b) ((a)>(b))?(a):(b)
#endif
#ifndef MIN
	#define MIN(a,b) ((a)<(b)?(a):(b))
#endif


int64_t lzbench_memcpy(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t , size_t, char* )
{
    memcpy(outbuf, inbuf, insize);
    return insize;
}

int64_t lzbench_return_0(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t , size_t, char* )
{
    return 0;
}

#ifndef BENCH_REMOVE_LZ4
#include "lz4.h"
#include "lz4hc.h"
#include "lz4frame.h"

int64_t lzbench_lz4_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
	return LZ4_compress_default(inbuf, outbuf, insize, outsize);
}

int64_t lzbench_lz4fast_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
	return LZ4_compress_fast(inbuf, outbuf, insize, outsize, level);
}

int64_t lzbench_lz4hc_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
	return LZ4_compress_HC(inbuf, outbuf, insize, outsize, level);
}

int64_t lzbench_lz4_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
	return LZ4_decompress_safe(inbuf, outbuf, insize, outsize);
}

int64_t lzbench_lz4frame_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
    return LZ4F_compressFrame(outbuf, LZ4F_compressFrameBound((size_t)insize, NULL), inbuf, insize, NULL);
}

static LZ4F_decompressionContext_t g_dCtx;

int64_t lzbench_lz4frame_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
    LZ4F_createDecompressionContext(&g_dCtx, LZ4F_VERSION);
    LZ4F_decompress(g_dCtx, outbuf, &outsize, inbuf, &insize, NULL);
    LZ4F_freeDecompressionContext(g_dCtx);
    return outsize;
}
#endif


#ifndef BENCH_REMOVE_SNAPPY
#include "snappy.h"

int64_t lzbench_snappy_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
	snappy::RawCompress(inbuf, insize, outbuf, &outsize);
	return outsize;
}

int64_t lzbench_snappy_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
	snappy::RawUncompress(inbuf, insize, outbuf);
	return outsize;
}

#endif


#ifndef BENCH_REMOVE_ZLIB
#include "zlib.h"

int64_t lzbench_zlib_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
	uLongf zcomplen = insize;
	int err = compress2((uint8_t*)outbuf, &zcomplen, (uint8_t*)inbuf, insize, level);
	if (err != Z_OK)
		return 0;
	return zcomplen;
}

int64_t lzbench_zlib_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
	uLongf zdecomplen = outsize;
	int err = uncompress((uint8_t*)outbuf, &zdecomplen, (uint8_t*)inbuf, insize); 
	if (err != Z_OK)
		return 0;
	return outsize;
}

#endif

#ifndef BENCH_REMOVE_ZSTD
#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

typedef struct {
    ZSTD_CCtx* cctx;
    ZSTD_DCtx* dctx;
    ZSTD_CDict* cdict;
    ZSTD_parameters zparams;
    ZSTD_customMem cmem;
} zstd_params_s;

char* lzbench_zstd_init(size_t insize, size_t level, size_t windowLog)
{
    zstd_params_s* zstd_params = (zstd_params_s*) malloc(sizeof(zstd_params_s));
    if (!zstd_params) return NULL;
    zstd_params->cctx = ZSTD_createCCtx();
    zstd_params->dctx = ZSTD_createDCtx();
#if 1
    zstd_params->cdict = NULL;
#else
    zstd_params->zparams = ZSTD_getParams(level, insize, 0);
    zstd_params->cmem = { NULL, NULL, NULL };
    if (windowLog && zstd_params->zparams.cParams.windowLog > windowLog) {
        zstd_params->zparams.cParams.windowLog = windowLog;
        zstd_params->zparams.cParams.chainLog = windowLog + ((zstd_params->zparams.cParams.strategy == ZSTD_btlazy2) | (zstd_params->zparams.cParams.strategy == ZSTD_btopt) | (zstd_params->zparams.cParams.strategy == ZSTD_btopt2));
    }
    zstd_params->cdict = ZSTD_createCDict_advanced(NULL, 0, zstd_params->zparams, zstd_params->cmem);
#endif

    return (char*) zstd_params;
}

void lzbench_zstd_deinit(char* workmem)
{
    zstd_params_s* zstd_params = (zstd_params_s*) workmem;
    if (!zstd_params) return;
    if (zstd_params->cctx) ZSTD_freeCCtx(zstd_params->cctx);
    if (zstd_params->dctx) ZSTD_freeDCtx(zstd_params->dctx);
    if (zstd_params->cdict) ZSTD_freeCDict(zstd_params->cdict);
    free(workmem);
}

int64_t lzbench_zstd_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t windowLog, char* workmem)
{
    size_t res;

    zstd_params_s* zstd_params = (zstd_params_s*) workmem;
    if (!zstd_params || !zstd_params->cctx) return 0;

#if 1
    zstd_params->zparams = ZSTD_getParams(level, insize, 0);
    ZSTD_CCtx_setParameter(zstd_params->cctx, ZSTD_c_compressionLevel, level);
    zstd_params->zparams.fParams.contentSizeFlag = 1;

    if (windowLog && zstd_params->zparams.cParams.windowLog > windowLog) {
        zstd_params->zparams.cParams.windowLog = windowLog;
        zstd_params->zparams.cParams.chainLog = windowLog + ((zstd_params->zparams.cParams.strategy == ZSTD_btlazy2) || (zstd_params->zparams.cParams.strategy == ZSTD_btopt) || (zstd_params->zparams.cParams.strategy == ZSTD_btultra));
    }
    // res = ZSTD_compress_advanced(zstd_params->cctx, outbuf, outsize, inbuf, insize, NULL, 0, zstd_params->zparams);
   res = ZSTD_compressCCtx(zstd_params->cctx, outbuf, outsize, inbuf, insize, level);
#else
    if (!zstd_params->cdict) return 0;
    res = ZSTD_compress_usingCDict(zstd_params->cctx, outbuf, outsize, inbuf, insize, zstd_params->cdict);
#endif
    if (ZSTD_isError(res)) return res;

    return res;
}

int64_t lzbench_zstd_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char* workmem)
{
    zstd_params_s* zstd_params = (zstd_params_s*) workmem;
    if (!zstd_params || !zstd_params->dctx) return 0;

    return ZSTD_decompressDCtx(zstd_params->dctx, outbuf, outsize, inbuf, insize);
}

char* lzbench_zstd_LDM_init(size_t insize, size_t level, size_t windowLog)
{
    zstd_params_s* zstd_params = (zstd_params_s*) lzbench_zstd_init(insize, level, windowLog);
    if (!zstd_params) return NULL;
    ZSTD_CCtx_setParameter(zstd_params->cctx, ZSTD_c_enableLongDistanceMatching, 1);
    return (char*) zstd_params;
}

int64_t lzbench_zstd_LDM_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t windowLog, char* workmem)
{
    zstd_params_s* zstd_params = (zstd_params_s*) workmem;
    if (!zstd_params || !zstd_params->cctx) return 0;
    ZSTD_CCtx_setParameter(zstd_params->cctx, ZSTD_c_enableLongDistanceMatching, 1);
    return lzbench_zstd_compress(inbuf, insize, outbuf, outsize, level, windowLog, (char*) zstd_params);
}

size_t ZstdStreamCompressBuff(ZSTD_CStream *cStream, uint8_t* dst, uint32_t dstSize,
                              uint8_t *src, size_t srcSize, size_t buffInSize, size_t buffOutSize)
{
    size_t ret;
    uint32_t lastChunk = 0;
    void *buffIn = malloc(buffInSize);
    void *buffOut = malloc(buffOutSize);

    uint32_t cSize = 0;
    uint32_t srcPos = 0;
    uint32_t leftSize = srcSize;
    uint32_t readCount = 0;

    while (!lastChunk) {
        readCount = (buffInSize <= leftSize) ? buffInSize : leftSize;
        lastChunk = readCount < buffInSize;

        memcpy(buffIn, src + srcPos, readCount);
        srcPos += readCount;
        leftSize -= readCount;

        ZSTD_inBuffer input = { buffIn, readCount, 0 };
        ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
        while (input.pos != input.size) {
            ret = ZSTD_compressStream(cStream, &output, &input);

            memcpy(dst + cSize, buffOut, output.pos);
            cSize += output.pos;
            output.pos = 0;
        }
    }

    ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
    do {
        leftSize = ZSTD_endStream(cStream, &output);
        memcpy(dst + cSize, buffOut, output.pos);
        cSize += output.pos;
        output.pos = 0;
    } while (leftSize != 0);

    free(buffIn);
    free(buffOut);

    return cSize;
}

int64_t lzbench_zstd_stream_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
    ZSTD_CStream *zstdCStream = ZSTD_createCStream();
    if (level != 0) {
        ZSTD_initCStream(zstdCStream, level); //JD mm场景没有次接口调用逻辑,按level作为默认等级场景
    }
    uint32_t cSize = ZstdStreamCompressBuff(zstdCStream, (uint8_t *)outbuf, outsize, (uint8_t *)inbuf, insize, 1024, 1024);
    ZSTD_freeCStream(zstdCStream);
    return (int64_t) cSize;
}

uint32_t ZstdStreamDecompressBuff(ZSTD_DStream *dStream, uint8_t *src, size_t srcSize, uint8_t *dst, size_t cSize,
                                size_t buffInSize, size_t buffOutSize)
{
    size_t ret;
    void *dBuffIn = malloc(buffInSize);
    void *dBuffOut = malloc(buffOutSize);

    uint32_t lastChunk = 0, dSize = 0, dstPos = 0, leftSize = cSize;

    while (!lastChunk) {
        size_t readCount = (buffInSize <= leftSize) ? buffInSize : leftSize;

        lastChunk = readCount < buffInSize;

        memcpy(dBuffIn, dst + dstPos, readCount);
        dstPos += readCount;

        size_t cSize = 1;

        ZSTD_inBuffer dInput = { dBuffIn, readCount, 0 };
        ZSTD_outBuffer dOutput = { dBuffOut, buffOutSize, 0 };
        size_t size = 1;
        while (dInput.pos != dInput.size) {
            size = ZSTD_decompressStream(dStream, &dOutput, &dInput);

            if (dOutput.pos != 0) {
                memcpy(src + dSize, dBuffOut, dOutput.pos);
            }

            dSize += dOutput.pos;
            dOutput.pos = 0;
        }

        if (size == 0) {
            break;
        }


        leftSize -= readCount;
    }

    free(dBuffOut);
    free(dBuffIn);
    return dSize;
}

int64_t lzbench_zstd_stream_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{

    ZSTD_DStream *zstdDStream = ZSTD_createDStream();
    ZSTD_initDStream(zstdDStream);

    uint32_t dSize = ZstdStreamDecompressBuff(zstdDStream, (uint8_t *)outbuf, outsize, (uint8_t *)inbuf, insize, 1024, 1024);
    ZSTD_freeDStream(zstdDStream);
    return dSize;
}

int64_t lzbench_zstd_simple_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
    return ZSTD_compress(outbuf, outsize, inbuf, insize, level);
}

int64_t lzbench_zstd_simple_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
    return  ZSTD_decompress(outbuf, outsize, inbuf, insize);
}

#endif


#ifdef ENABLE_QAT
int64_t lzbench_qat_zip_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
    // 初始化QAT压缩上下文
    QzSession_T sess = {0};
    int rc = QZ_OK;
    rc = qzInit(&sess, 1);
    QzSessionParamsDeflate_T params;
    qzGetDefaultsDeflate(&params);
    params.common_params.hw_buff_sz =  128 * 1024;
    params.common_params.comp_lvl = level;
    params.common_params.direction = QZ_DIR_COMPRESS;
    params.common_params.comp_algorithm = QZ_DEFLATE;
    params.common_params.sw_backup = QZ_SW_BACKUP_BIT_POSITION;

    rc = qzSetupSessionDeflate(&sess, &params);

    unsigned int src_len = (unsigned int)insize;
    unsigned int dest_len = (unsigned int)outsize;
    // printf("size before compress： %u ", src_len);
    rc = qzCompress(&sess, (unsigned char *)inbuf, &src_len, (unsigned char *)outbuf, &dest_len, 1);
    // printf("size after compress： %u", dest_len);
    outsize = (size_t)dest_len;
    return dest_len;
}

int64_t lzbench_qat_zip_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
    // 初始化QAT压缩上下文
    QzSession_T sess = {0};
    int rc = QZ_OK;
    rc = qzInit(&sess, 1);
    QzSessionParamsDeflate_T params;
    qzGetDefaultsDeflate(&params);
    params.common_params.hw_buff_sz =  128 * 1024;
    params.common_params.direction = QZ_DIR_DECOMPRESS;
    params.common_params.comp_algorithm = QZ_DEFLATE;
    params.common_params.sw_backup = QZ_SW_BACKUP_BIT_POSITION;
    
    rc = qzSetupSessionDeflate(&sess, &params);
    unsigned int src_len = (unsigned int)insize;
    unsigned int dest_len = (unsigned int)outsize;
    // printf("size before decompress：%d", src_len);
    rc = qzDecompress(&sess, (unsigned char *)inbuf, &src_len, (unsigned char *)outbuf, &dest_len);
    // printf("size after decompress: %d", dest_len);
    return outsize;
}
int64_t lzbench_qat_lz4_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
    // 初始化QAT压缩上下文
    QzSession_T sess = {0};
    int rc = QZ_OK;
    rc = qzInit(&sess, 1);
    QzSessionParamsLZ4_T params;
    qzGetDefaultsLZ4(&params);
    // params.data_fmt = LZ4S_BK; //   QZ_DEFLATE_4B 、 QZIP_LZ4_FH 、 QZ_DEFLATE_RAW 、 QZIP_LZ4S_BK
    params.common_params.hw_buff_sz =  128 * 1024;
    params.common_params.comp_lvl = level;
    params.common_params.direction = QZ_DIR_COMPRESS;
    params.common_params.comp_algorithm = QZ_LZ4;
    params.common_params.sw_backup = QZ_SW_BACKUP_BIT_POSITION;
    
    rc = qzSetupSessionLZ4(&sess, &params);
    unsigned int src_len = (unsigned int)insize;
    unsigned int dest_len = (unsigned int)outsize;
    // printf("size before lz4 compress： %u ", src_len);
    rc = qzCompress(&sess, (unsigned char *)inbuf, &src_len, (unsigned char *)outbuf, &dest_len, 1);
    // printf("size after lze compress： %u", dest_len);
    outsize = (size_t)dest_len;
    return outsize;
}

int64_t lzbench_qat_lz4_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
        // 初始化QAT压缩上下文
    QzSession_T sess = {0};
    int rc = QZ_OK;
    rc = qzInit(&sess, 1);
    QzSessionParamsLZ4_T params;
    qzGetDefaultsLZ4(&params);
    // params.data_fmt = LZ4S_BK; //   QZ_DEFLATE_4B
    params.common_params.hw_buff_sz =  128 * 1024;
    params.common_params.direction = QZ_DIR_DECOMPRESS;
    params.common_params.comp_algorithm = QZ_LZ4;
    params.common_params.sw_backup = QZ_SW_BACKUP_BIT_POSITION;
    
    rc = qzSetupSessionLZ4(&sess, &params);
    unsigned int src_len = (unsigned int)insize;
    unsigned int dest_len = (unsigned int)outsize;
    rc = qzDecompress(&sess, (unsigned char *)inbuf, &src_len, (unsigned char *)outbuf, &dest_len);
    outsize = (size_t)dest_len;
    return outsize;
}

int64_t lzbench_qat_gzip_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{
    // 初始化QAT压缩上下文
    QzSession_T sess = {0};
    int rc = QZ_OK;
    rc = qzInit(&sess, 1);
    QzSessionParams_T params;
    qzGetDefaults(&params);
    params.data_fmt = QZ_DEFLATE_GZIP; // set gzip format
    params.hw_buff_sz =  128 * 1024;
    params.comp_lvl = level;
    params.direction = QZ_DIR_COMPRESS;
    params.comp_algorithm = QZ_DEFLATE;
    params.sw_backup = QZ_SW_BACKUP_BIT_POSITION;
    
    rc = qzSetupSession(&sess, &params);
    unsigned int src_len = (unsigned int)insize;
    unsigned int dest_len = (unsigned int)outsize;
    // printf("size before gzip compress： %u ", src_len);
    rc = qzCompress(&sess, (unsigned char *)inbuf, &src_len, (unsigned char *)outbuf, &dest_len, 1);
    // printf("size after gzip compress： %u", dest_len);
    outsize = (size_t)dest_len;
    return outsize;
}

int64_t lzbench_qat_gzip_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{
    // 初始化QAT压缩上下文
    QzSession_T sess = {0};
    int rc = QZ_OK;
    rc = qzInit(&sess, 1);
    QzSessionParams_T params;
    qzGetDefaults(&params);
    params.data_fmt = QZ_DEFLATE_GZIP;
    params.hw_buff_sz =  128 * 1024;
    params.direction = QZ_DIR_DECOMPRESS;
    params.comp_algorithm = QZ_DEFLATE;
    params.sw_backup = QZ_SW_BACKUP_BIT_POSITION;
    
    rc = qzSetupSession(&sess, &params);
    unsigned int src_len = (unsigned int)insize;
    unsigned int dest_len = (unsigned int)outsize;
    rc = qzDecompress(&sess, (unsigned char *)inbuf, &src_len, (unsigned char *)outbuf, &dest_len);
    outsize = (size_t)dest_len;
    return outsize;
}

ZSTD_CCtx* getZc(){
    static ZSTD_CCtx* zc = NULL;  // 在函数作用域内的静态变量，单例模式
    if(zc == NULL) {
        zc = ZSTD_createCCtx();
        /* Start QAT device, start QAT device at any
        time before compression job started */
        QZSTD_startQatDevice();
        /* Create sequence producer state for QAT sequence producer */
        void *sequenceProducerState = QZSTD_createSeqProdState();
        /* register qatSequenceProducer */
        ZSTD_registerSequenceProducer(
            zc,
            sequenceProducerState,
            qatSequenceProducer
        );
        /* Enable sequence producer fallback */
        ZSTD_CCtx_setParameter(zc, ZSTD_c_enableSeqProducerFallback, 1);

    }
    return zc;
}

int64_t lzbench_qat_zstd_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t, char*)
{

    ZSTD_CCtx* zc =getZc(); // 获取初始化上下文

    ZSTD_compress2(zc, outbuf, outsize, inbuf, insize);

    // /* Free sequence producer state */
    // QZSTD_freeSeqProdState(sequenceProducerState);
    // /* Please call QZSTD_stopQatDevice before
    // QAT is no longer used or the process exits */
    // QZSTD_stopQatDevice();

    return outsize;
}

int64_t lzbench_qat_zstd_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t, size_t, char*)
{

    ZSTD_DCtx *const zdc = ZSTD_createDCtx();
    ZSTD_decompressDCtx(zdc, outbuf, outsize, inbuf, insize);

    return outsize;
}
#endif
