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

#ifndef KAESNAPPY_COMP_H
#define KAESNAPPY_COMP_H

#include "kaesnappy_common.h"
#include <stdint.h>
#include <arm_acle.h>
#include <arm_neon.h>


#define TOKEN_NUM_CONTROL 0 // 用于控制生成压缩块中三元组数目，来保证解压速度（对齐实际match length需+3）
#define ML_BITS  4
#define ML_MASK  ((1U<<ML_BITS)-1)
#define RUN_BITS (8-ML_BITS)
#define RUN_MASK ((1U<<RUN_BITS)-1)
#define MFLIMIT       12
#define KAE_SNAPPY_REBUILD_FAIL -257
#define KAE_SNAPPY_SW_RETURN_0_FAIL -256

#define HARDWARE_BLOCK_SIZE (64 * 1024) // 硬件支持的最大压缩块大小

#if !defined(SNAPPY_memcpy)
#  if defined(__GNUC__) && (__GNUC__ >= 4)
#    define SNAPPY_memcpy(dst, src, size) __builtin_memcpy(dst, src, size)
#  else
#    define SNAPPY_memcpy(dst, src, size) memcpy(dst, src, size)
#  endif
#endif

#if defined(__x86_64__)
  typedef U64    reg_t;   /* 64-bits in x32 mode */
#else
  typedef size_t reg_t;   /* 32-bits in x32 mode */
#endif

typedef union { U16 u16; U32 u32; reg_t uArch; } __attribute__((packed)) SNAPPY_unalign;

int  kaesnappy_compress_v1(SNAPPY_CCtx* zc, const void* src, size_t srcSize);

// part1.frame模式的header & footer描述
#define KAESNAPPY_MAGIC_NUMBER    0x184D2204U
#define KAESNAPPY_MAGIC_SKIPPABLE 0x184D2A50U

#define KAESNAPPY_VERSION                  0x1        // version必须为01
#define KAESNAPPY_BLOCK_INDEPENDENCE_FLAG  0x1        // block间独立不依赖
#define KAESNAPPY_BLOCK_CHECKSUM_FLAG      (1 << 4)        // 各block不带checksum
#define KAESNAPPY_CONTENT_SIZE_FLAG        (1 << 3)        // 携带原始数据长度
#define KAESNAPPY_CONTENT_CHECKSUM_FLAG    (1 << 2)        // frame携带checksum
#define KAESNAPPY_DICTIONARY_ID_FLAG       0x0        // 不使用字典dict
#define KAESNAPPY_MAX_BLK_SIZE  0x4                   // 各block大小64KB
#define KAESNAPPY_ENDMARK       0x0                   // frame结束标志

#define KAESNAPPY_MAGIC_SIZE    4                     // magic number长度
#define KAESNAPPY_FRAMEDESCRIPTOR_SIZE     11         // frame descriptor长度
#define KAESNAPPY_HEADER_SIZE   (KAESNAPPY_MAGIC_SIZE + KAESNAPPY_FRAMEDESCRIPTOR_SIZE) // frame header长度

#define KAESNAPPY_BLOCK_HEADER_SIZE  4                // block header长度(4字节)
#define KAESNAPPY_STOREDBLOCK_FLAG   0x80000000U      // 长度为0的未压缩块，是有效的
#define KAESNAPPY_STORED_HEADER_SIZE 4

#define KAESNAPPY_CHECKSUM_SIZE 4                     // checksum长度
#define KAESNAPPY_ENDMARK_SIZE  4                     // endmark长度
#define KAESNAPPY_FOOTER_SIZE   (KAESNAPPY_CHECKSUM_SIZE + KAESNAPPY_ENDMARK_SIZE) // frame footer长度

// part2.首尾数据结构
// frame header
typedef struct KAESNAPPYH_S {
    uint32_t magic_number;
    uint8_t  flag_descriptor;
    uint8_t  block_descriptor;
    uint64_t content_size;
    uint8_t  header_checksum;
} KAESNAPPYH_T;

// frame footer
typedef struct KAESNAPPYF_S {
    uint32_t end_mark;
    uint32_t content_checksum;
} KAESNAPPYF_T;

// part4.功能函数
inline unsigned long KAESNAPPYHeaderSz(void)
{
    return KAESNAPPY_HEADER_SIZE;
}

inline unsigned long KAESNAPPYFooterSz(void)
{
    return KAESNAPPY_FOOTER_SIZE;
}

inline unsigned long KAESNAPPYBlockHeaderSz(void)
{
    return KAESNAPPY_BLOCK_HEADER_SIZE;
}

#endif
