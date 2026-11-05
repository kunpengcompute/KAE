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

#ifndef MANAGE_H
#define MANAGE_H
#include <lz4.h>
#include <lz4frame.h>

typedef struct {
    const char *name;
    // 同步接口
    int (*init)();
    int (*bound)(int src_len);
    // 我们约定：由框架统一读取待处理的数据以及大小。统一申请待存储的空间以及大小。
    // 压缩解压算法需要输出正确的处理后产物，输出正确的 dst_len。
    // 统一返回 0 表示算法OK
    // 返回其他表示压缩解压异常
    int (*compress)(const unsigned char *src, unsigned int *src_len,
                   unsigned char *dst, unsigned int *dst_len);
    int (*decompress)(const unsigned char *src, unsigned int *src_len,
                     unsigned char *dst, unsigned int *dst_len);
    void (*cleanup)();

    // 异步接口
    int (*async_compress)(const unsigned char *src, unsigned char *dst,
                          lz4_async_callback cb, struct kaelz4_result *result);

    int (*async_decompress)(const unsigned char* src, unsigned char *dst,
                           lz4_async_callback cb, struct kaelz4_result *result);
} compression_algorithm_t;

// 注册算法
void register_algorithm(compression_algorithm_t *algorithm);

// 根据名称查找算法
compression_algorithm_t *get_algorithm(const char *name);

int vaild_algorithm(const char *name);

// 初始化所有算法（自动注册）
void initialize_algorithms(void);

void register_lz4_algorithm(void);
void register_lz4_frame_algorithm(void);
void register_lz4async_block_algorithm(void);
void register_lz4async_frame_algorithm(void);
#endif
