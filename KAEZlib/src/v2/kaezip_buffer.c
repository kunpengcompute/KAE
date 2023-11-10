/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: zlib-v2 real buffer function
 * @Author: LiuYongYang
 * @Date: 2023-11-03
*/

#include <string.h>
#include <stdlib.h>
#include "wd.h"
#include "wd_zlibwrapper.h"
#include "kaezip_buffer.h"
#include "kaezip_log.h"

int  kz_outbuffer_init(z_streamp strm)
{
    outbuffer_ptr out_buffer = (outbuffer_ptr)malloc(sizeof(struct kz_zlib_outbuffer));
    if (!out_buffer) {
        US_ERR("kz_outbuffer_init: failed to malloc outbuffer struct");
        return Z_BUF_ERROR;
    }
    out_buffer->out = (unsigned char *)malloc(OUTPUT_CHUNK_V2);
    if (!out_buffer->out) {
        US_ERR("kz_outbuffer_init: failed to malloc outbuffer array");
        return Z_BUF_ERROR;
    }

    out_buffer->produced = out_buffer->remained = 0;
    //  use strm->adler store out_buffer's address
    strm->adler = (unsigned long long)out_buffer;
    US_DEBUG("kz_outbuffer_init: out_buffer address is %p", out_buffer);
    return Z_OK;
}

void kz_outbuffer_reset(z_streamp strm)
{
    outbuffer_ptr out_buffer = (outbuffer_ptr)strm->adler;
    US_DEBUG("kz_outbuffer_reset: out_buffer address is %p", out_buffer);
    if (out_buffer) {
        unsigned char* buffer = out_buffer->out;
        if (buffer) {
            //  memset(buffer, 0x1, OUTPUT_CHUNK_V2);
        }
        out_buffer->produced = out_buffer->remained = 0;
    }
}

void kz_outbuffer_free(z_streamp strm)
{
    outbuffer_ptr out_buffer = (outbuffer_ptr)strm->adler;
    US_DEBUG("kz_outbuffer_free: out_buffer address is %p", out_buffer);
    if (out_buffer) {
        unsigned char* buffer = out_buffer->out;
        if (buffer) {
            free(buffer);
            out_buffer->out = NULL;
        }
        free(out_buffer);
        strm->adler = 0;
    }
}
