/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2024. All rights reserved.
 * Description: contain kaelz4 api defines
 * Author: DSA
 * Create: 2024-7-6
 */

#ifndef KAELZ4_H
#define KAELZ4_H

#include <stdint.h>
#include <stddef.h>

typedef   uint8_t BYTE;
typedef   uint8_t U8;
typedef  uint16_t U16;
typedef  uint32_t U32;
typedef  uint64_t U64;

/**
* HW_LZ77_ZSTD: U32 offBase   U16 litLength   U16 mlBase
* WCRYPTO_LZ77_ONLY: U32 litLength   (U16 offBase - 1)   U16 mlBase
*/
typedef struct seqDef_s {
    U32 litLength;   /* offBase == Offset + ZSTD_REP_NUM, or repcode 1,2,3 */
    U16 offBase;
    U16 mlBase;    /* mlBase == matchLength - MINMATCH */
} seqDef;

/* Controls whether seqStore has a single "long" litLength or matchLength. See seqStore_t. */
typedef enum {
    LZ4_llt_none = 0,             /* no longLengthType */
    LZ4_llt_literalLength = 1,    /* represents a long literal */
    LZ4_llt_matchLength = 2       /* represents a long match */
} LZ4_longLengthType_e;

typedef struct {
    seqDef* sequencesStart;
    seqDef* sequences;
    BYTE* litStart;
    BYTE* lit;
    BYTE* llCode;
    BYTE* mlCode;
    BYTE* ofCode;
    size_t maxNbSeq;
    size_t maxNbLit;
    LZ4_longLengthType_e longLengthType;
    U32 longLengthPos;
} seqStore_t;

typedef struct {
    unsigned char kaeInited;
    unsigned int kaeFrameMode;
    uintptr_t kaeConfig;
    seqStore_t seqStore;
    int compressionLevel;
    int kaeLevel;
    int seqnum;
} LZ4_CCtx;

#define TUPLE_STATUS_COMPRESS 2
#define TUPLE_STATUS_RLEBLOCK 1
#define TUPLE_STATUS_NOCOMPRESS 0

#define KAE_LZ4_SUCC 0
#define KAE_LZ4_INVAL_PARA 1
#define KAE_LZ4_INIT_FAIL 2
#define KAE_LZ4_COMP_FAIL 3
#define KAE_LZ4_RELEASE_FAIL 4
#define KAE_LZ4_ALLOC_FAIL 5
#define KAE_LZ4_SET_FAIL 6
#define KAE_LZ4_HW_TIMEOUT_FAIL 7

#define KAE_LZ77_SEQ_DATA_SIZE_PER_64K (128UL * 1024UL)

#define VERSION_STRUCT_LEN 100
typedef struct {
    char productName[VERSION_STRUCT_LEN];
    char productVersion[VERSION_STRUCT_LEN];
    char componentName[VERSION_STRUCT_LEN];
    char componentVersion[VERSION_STRUCT_LEN];
} KAELz4Version;

extern int kaelz4_get_version(KAELz4Version* ver);
extern int kaelz4_init(LZ4_CCtx* zc, int is_sgl);
extern void kaelz4_reset(LZ4_CCtx* zc);
extern void kaelz4_release(LZ4_CCtx* zc);
extern void kaelz4_setstatus(LZ4_CCtx* zc, unsigned int status);
extern int kaelz4_compress(LZ4_CCtx* zc, const void* src, size_t srcSize);

struct kaelz4_result {
    int status;
    unsigned int rsvd;
    void *user_data;
    size_t src_size;
    size_t dst_len;
    uint32_t *ibuf_crc;
    uint32_t *obuf_crc;
};

struct kaelz4_buffer {
    size_t buf_len;
    void *data;
};

struct kaelz4_buffer_list {
    unsigned int buf_num;
    unsigned int rsvd;
    struct kaelz4_buffer *buf;
    void *usr_data;
};

typedef void (*lz4_async_callback)(struct kaelz4_result *result);
typedef int (*sw_compress_fn)(const char* src, char* dst, int srcSize, int dstCapacity);
typedef size_t (*sw_compress_frame_fn)(void* dstBuffer, size_t dstCapacity, const void* srcBuffer, size_t srcSize,
                                       const void* preferences_ptr);
typedef int (*sw_decompress_fn)(const char* source, char* dest, int compressedSize, int maxDecompressedSize);
typedef void *(*iova_map_fn)(void *usr, void *vaddr, size_t sz);
int KAELZ4_compress_async(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                          lz4_async_callback callback, struct kaelz4_result *result);
int KAELZ4F_compressFrame_async(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                                lz4_async_callback callback, struct kaelz4_result *result, const void *preferences_ptr);
void KAELZ4_teardown_async_compress(void);
void *KAELZ4_create_async_compress_session(iova_map_fn usr_map);
void KAELZ4_destroy_async_compress_session(void *sess);
int KAELZ4_compress_async_in_session(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                                     lz4_async_callback callback, struct kaelz4_result *result);
void KAELZ4_compress_async_polling_in_session(void *sess, int budget);
int KAELZ4_compress_frame_async_in_session(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                                           lz4_async_callback callback, struct kaelz4_result *result,
                                           const void *preferences_ptr);
int KAELZ4_async_compress_init(iova_map_fn usr_map, sw_compress_fn sw_compress, sw_compress_frame_fn sw_compress_frame,
                               sw_decompress_fn sw_decompress);
int KAELZ4_decompress_async(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                            lz4_async_callback callback, struct kaelz4_result *result);
int KAELZ4F_decompressFrame_async(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                                  lz4_async_callback callback, struct kaelz4_result *result, const void *options_ptr);
size_t KAELZ4_compress_get_tuple_buf_len(size_t src_len);
int KAELZ4_compress_lz77_async_in_session(void *sess, const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                                          lz4_async_callback callback, struct kaelz4_result *result);
int KAELZ4_rebuild_lz77_to_block(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *tuple_buf, struct kaelz4_buffer_list *dst,
                                 struct kaelz4_result *result);
int KAELZ4_rebuild_lz77_to_frame(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *tuple_buf, struct kaelz4_buffer_list *dst,
                                 struct kaelz4_result *result, const void *preferences_ptr);
#endif