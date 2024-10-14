/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2024. All rights reserved.
 * Description: contain kaelz4 api defines
 * Author: DSA
 * Create: 2024-7-6
 */

#ifndef KAELZ4_H
#define KAELZ4_H

#include "lz4.h"

typedef   uint8_t BYTE;
typedef   uint8_t U8;
typedef  uint16_t U16;
typedef  uint32_t U32;
typedef  uint64_t U64;

typedef struct seqDef_s {
    U32 offBase;   /* offBase == Offset + ZSTD_REP_NUM, or repcode 1,2,3 */
    U16 litLength;
    U16 mlBase;    /* mlBase == matchLength - MINMATCH */
} seqDef;

/* Controls whether seqStore has a single "long" litLength or matchLength. See seqStore_t. */
typedef enum {
    ZSTD_llt_none = 0,             /* no longLengthType */
    ZSTD_llt_literalLength = 1,    /* represents a long literal */
    ZSTD_llt_matchLength = 2       /* represents a long match */
} ZSTD_longLengthType_e;

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
    ZSTD_longLengthType_e longLengthType;
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

#define VERSION_STRUCT_LEN 100
typedef struct {
    char productName[VERSION_STRUCT_LEN];
    char productVersion[VERSION_STRUCT_LEN];
    char componentName[VERSION_STRUCT_LEN];
    char componentVersion[VERSION_STRUCT_LEN];
} KAELz4Version;

extern int kaelz4_get_version(KAELz4Version* ver);
extern int kaelz4_init(LZ4_CCtx* zc);
extern void kaelz4_reset(LZ4_CCtx* zc);
extern void kaelz4_release(LZ4_CCtx* zc);
extern void kaelz4_setstatus(LZ4_CCtx* zc, unsigned int status);
extern int kaelz4_compress(LZ4_CCtx* zc, const void* src, size_t srcSize);

#endif