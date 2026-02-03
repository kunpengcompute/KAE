/*
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KAESNAPPY_H
#define KAESNAPPY_H

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
    SNAPPY_llt_none = 0,             /* no longLengthType */
    SNAPPY_llt_literalLength = 1,    /* represents a long literal */
    SNAPPY_llt_matchLength = 2       /* represents a long match */
} SNAPPY_longLengthType_e;

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
    SNAPPY_longLengthType_e longLengthType;
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
} SNAPPY_CCtx;

#define TUPLE_STATUS_COMPRESS 2
#define TUPLE_STATUS_RLEBLOCK 1
#define TUPLE_STATUS_NOCOMPRESS 0

#define KAE_SNAPPY_SUCC 0
#define KAE_SNAPPY_INVAL_PARA 1
#define KAE_SNAPPY_INIT_FAIL 2
#define KAE_SNAPPY_COMP_FAIL 3
#define KAE_SNAPPY_RELEASE_FAIL 4
#define KAE_SNAPPY_ALLOC_FAIL 5
#define KAE_SNAPPY_SET_FAIL 6
#define KAE_SNAPPY_HW_TIMEOUT_FAIL 7

#define VERSION_STRUCT_LEN 100
typedef struct {
    char productName[VERSION_STRUCT_LEN];
    char productVersion[VERSION_STRUCT_LEN];
    char componentName[VERSION_STRUCT_LEN];
    char componentVersion[VERSION_STRUCT_LEN];
} KAESnappyVersion;

extern int kaesnappy_get_version(KAESnappyVersion* ver);
extern int kaesnappy_init(SNAPPY_CCtx* zc);
extern void kaesnappy_release(SNAPPY_CCtx* zc);
extern int kaesnappy_compress(SNAPPY_CCtx* zc, const void* src, size_t srcSize);

struct kaesnappy_result {
    int status;
    unsigned int flag;
    void *user_data;
    size_t src_size;
    size_t dst_len;
    uint32_t *ibuf_crc;
    uint32_t *obuf_crc;
};

#endif