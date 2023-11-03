/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: uadk-v2 real compress/uncompress header file
 * @Author: LiuYongYang
 * @Date: 2023-05-09
*/
#ifndef KAEZIP_COMP_H
#define KAEZIP_COMP_H

int kz_deflate_v2(z_streamp strm, int flush);
int kz_inflate_v2(z_streamp strm, int flush);

#endif
