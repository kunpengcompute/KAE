#ifndef KZBENCH_COMPRESSORS_H
#define KZBENCH_COMPRESSORS_H

#include <stddef.h>
#include <stdint.h>

int64_t lzbench_memcpy(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_return_0(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);

int64_t lzbench_lz4_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_lz4fast_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_lz4hc_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_lz4_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_lz4frame_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_lz4frame_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);

int64_t lzbench_snappy_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_snappy_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);

int64_t lzbench_zlib_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_zlib_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);

char* lzbench_zstd_init(size_t insize, size_t level, size_t windowLog);
void lzbench_zstd_deinit(char* workmem);
int64_t lzbench_zstd_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t windowLog, char* workmem);
int64_t lzbench_zstd_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t windowLog, char* workmem);
char* lzbench_zstd_LDM_init(size_t insize, size_t level, size_t windowLog);
int64_t lzbench_zstd_LDM_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t windowLog, char* workmem);
int64_t lzbench_zstd_stream_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_zstd_stream_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_zstd_simple_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_zstd_simple_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);

#ifdef ENABLE_QAT
int64_t lzbench_qat_zip_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_qat_zip_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_qat_lz4_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_qat_lz4_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_qat_gzip_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_qat_gzip_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_qat_zstd_compress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
int64_t lzbench_qat_zstd_decompress(char *inbuf, size_t insize, char *outbuf, size_t outsize, size_t level, size_t param2, char* workmem);
#endif

#endif

