/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: uadk-v2 real compress/uncompress
 * @Author: LiuYongYang
 * @Date: 2023-05-09
*/

#include "wd.h"
#include "wd_comp.h"
#include "wd_zlibwrapper.h"
#include "kaezip_comp.h"

static int wd_zlib_do_request_v2(z_streamp strm, int flush, enum wd_comp_op_type type)
{
	handle_t h_sess = strm->reserved;
	struct wd_comp_req req = {0};
	int src_len = strm->avail_in;
	int dst_len = strm->avail_out;
	int ret;

	if (unlikely(flush != Z_SYNC_FLUSH && flush != Z_NO_FLUSH && flush != Z_FINISH)) {
		WD_ERR("invalid: flush is %d!\n", flush);
		return Z_STREAM_ERROR;
	}

	req.src = (void *)strm->next_in;
	req.src_len = strm->avail_in;
	req.dst = (void *)strm->next_out;
	req.dst_len = strm->avail_out;
	req.op_type = type;
	req.data_fmt = WD_FLAT_BUF;
	req.last = (flush == Z_FINISH) ? 1 : 0;

	ret = wd_do_comp_sync2(h_sess, &req);
	if (unlikely(ret)) {
		WD_ERR("failed to do compress(%d)!\n", ret);
		return Z_STREAM_ERROR;
	}

	strm->avail_in = src_len - req.src_len;
	strm->avail_out = dst_len - req.dst_len;
	strm->total_in += req.src_len;
	strm->total_out += req.dst_len;

	if (flush == Z_FINISH && req.src_len == src_len)
		ret = Z_STREAM_END;

	return ret;
}

int wd_deflate_v2(z_streamp strm, int flush)
{
    return wd_zlib_do_request_v2(strm, flush, WD_DIR_COMPRESS);
}

int wd_inflate_v2(z_streamp strm, int flush)
{
    return wd_zlib_do_request_v2(strm, flush, WD_DIR_DECOMPRESS);
}
