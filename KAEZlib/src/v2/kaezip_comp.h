/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: uadk-v2 real compress/uncompress header file
 * @Author: LiuYongYang
 * @Date: 2023-05-09
*/
#ifndef KAEZIP_COMP_H
#define KAEZIP_COMP_H

#define INPUT_CHUNK_V2  (512 * 1024)
#define OUTPUT_CHUNK_V2 (INPUT_CHUNK_V2 << 3)

typedef struct kaezip_exdata_s {
    unsigned int  remain;               // 因avail_out不足需要借用的长度
    unsigned char output_buffer[OUTPUT_CHUNK_V2];   // 输出buffer
    unsigned int  last_comp_in_len;     // 最后一次压缩的输入长度
    unsigned int  last_comp_out_len;    // 最后一次压缩的输出长度
    unsigned long chunk_total_in;       // 上次一整块总共消耗的输入长度
    unsigned long chunk_total_out;      // 上次一整块总共消耗的输出长度
} kaezip_exdata;

int wd_deflate_v2(z_streamp strm, int flush);
int wd_inflate_v2(z_streamp strm, int flush);

#endif
