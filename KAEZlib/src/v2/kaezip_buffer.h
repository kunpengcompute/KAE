/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: zlib-v2 real buffer function header file
 * @Author: LiuYongYang
 * @Date: 2023-11-03
*/

#ifndef KAEZIP_BUFFER_H
#define KAEZIP_BUFFER_H

#define INPUT_CHUNK_V2  (1024 * 1024)
#define OUTPUT_CHUNK_V2 (INPUT_CHUNK_V2 << 3)

typedef struct kz_zlib_outbuffer {
    unsigned char *out;
    unsigned int produced;  //  how many bytes (un)compress produced
    unsigned int remained;  //  how many bytes (un)compress remained if no more avail_out space
} *outbuffer_ptr;

int  kz_outbuffer_init(z_streamp strm);
void kz_outbuffer_reset(z_streamp strm);
void kz_outbuffer_free(z_streamp strm);

#endif