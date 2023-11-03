/**
 * @CopyRight: Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * @Description: uadk-v2 real compress/uncompress
 * @Author: LiuYongYang
 * @Date: 2023-05-09
*/

#include "zlib.h"
#include "wd.h"
#include "wd_comp.h"
#include "kaezip_comp.h"
#include "kaezip_buffer.h"
#include "kaezip_log.h"

static int kz_check_params(struct wd_comp_req *req)
{
	if (unlikely(!req)) {
		US_ERR("invalid: req is NULL!\n");
		return -WD_EINVAL;
	}
	if (unlikely(!req->src || !req->dst)) {
		US_ERR("invalid: src or dst is NULL!\n");
		return -WD_EINVAL;
	}
	if (unlikely(!req->dst_len)) {
		US_ERR("invalid: dst_len is 0!\n");
		return -WD_EINVAL;
	}
	return WD_SUCCESS;
}

static int kz_zlib_do_comp_implement(handle_t h_sess, struct wd_comp_req *req,
	__u64 *used_in, __u64 *used_out, outbuffer_ptr out_buffer)
{
	int ret = kz_check_params(req);
	if (unlikely(ret)) {
		return ret;
	}
	__u32 total_avail_in  = req->src_len;
	__u32 total_avail_out = req->dst_len;

	struct wd_comp_req strm_req;
	memcpy(&strm_req, req, sizeof(struct wd_comp_req));

	*used_in = *used_out = 0;
	strm_req.dst = out_buffer->out;

	// 该接口至多压缩/解压缩(u32_max)个字节，若超过, 则重复调用
	// 因此需根据req->last判断是否为最后一个大块
	int is_real_last = req->last;
	strm_req.last = 0;
	do {
		strm_req.src_len = total_avail_in > INPUT_CHUNK_V2 ? INPUT_CHUNK_V2 : total_avail_in;
		strm_req.dst_len = OUTPUT_CHUNK_V2;
		__u32 orig_src_len = strm_req.src_len;
		__u32 orig_dst_len = OUTPUT_CHUNK_V2;

		if (strm_req.op_type == WD_DIR_COMPRESS) {
			if (is_real_last && total_avail_in <= INPUT_CHUNK_V2) {
				strm_req.last = 1;
			}
		}

		ret = wd_do_comp_strm(h_sess, &strm_req);
		if (strm_req.status == WD_IN_EPARA || unlikely(ret < 0)) {
			US_ERR("wd_do_comp_strm, invalid or incomplete data! ret = %d, status = %d\n", ret, strm_req.status);
			US_DEBUG("src_len : %u/%u, dst_len : %u/%u\n\n", orig_src_len, strm_req.src_len,
				orig_dst_len, strm_req.dst_len);
			return Z_STREAM_ERROR;
		}
		if (strm_req.dst_len > total_avail_out) {
			out_buffer->produced = strm_req.dst_len;
			out_buffer->remained = strm_req.dst_len - total_avail_out;
			strm_req.dst_len = total_avail_out;
			US_WARN("no more avail out space! remained is %u\n", out_buffer->remained);
			US_DEBUG("src_len : %u/%u, dst_len : %u/%u\n\n", orig_src_len, strm_req.src_len,
				orig_dst_len, strm_req.dst_len);
		}

		*used_out += strm_req.dst_len;
		memcpy(req->dst, strm_req.dst, strm_req.dst_len);
		req->dst += strm_req.dst_len;
		total_avail_out -= strm_req.dst_len;

		*used_in += strm_req.src_len;
		strm_req.src += strm_req.src_len;
		total_avail_in -= strm_req.src_len;
	} while ((total_avail_in != 0) && (total_avail_out != 0));

	req->status = strm_req.status;
	return 0;
}

static int kz_deflate_check_strm_avail(z_streamp strm, int flush, unsigned int remained)
{
	//z stream finished and outbuf == 0, but there is still some data that needs to be taken
    if (strm->avail_out == 0 && flush == Z_FINISH && remained != 0) {
        US_WARN("kz deflate warning, no enough output buff, remained %d", remained);
        return Z_STREAM_ERROR;
    }
    //z stream not finished but inbuf == 0 and no data remained, so we consider that it has reached the end of data
    if (strm->avail_in == 0 && flush != Z_FINISH && remained == 0) {
        US_WARN("kz deflate warning, no more input buff, remained %d", remained);
        return Z_STREAM_ERROR;
    }

    return Z_OK;
}

static int kz_get_remain_data(z_streamp strm, int flush)
{
	outbuffer_ptr out_buffer = (outbuffer_ptr)strm->adler;
	int remain_data_pos = out_buffer->produced - out_buffer->remained;
	unsigned int consumed = 0;

	US_DEBUG("before kaezip_get_remain_data: consumed is %u, avail_out is %u, remained is %u",
		consumed, strm->avail_out, out_buffer->remained);
	if (strm->avail_out < out_buffer->remained) {
		consumed = strm->avail_out;
		strm->avail_out = 0;
		out_buffer->remained -= consumed;
	} else {
		consumed = out_buffer->remained;
		strm->avail_out -= out_buffer->remained;
		out_buffer->remained = 0;
	}
	US_DEBUG("after  kaezip_get_remain_data: consumed is %u, avail_out is %u, remained is %u",
		consumed, strm->avail_out, out_buffer->remained);
	
	memcpy(strm->next_out, out_buffer->out + remain_data_pos, consumed);
	strm->next_out  += consumed;
	strm->total_out += consumed;

	return flush == Z_FINISH ? Z_STREAM_END : Z_OK;
}

static int kz_zlib_do_request_v2(z_streamp strm, int flush, enum wd_comp_op_type type)
{
	if (unlikely(flush != Z_SYNC_FLUSH && flush != Z_NO_FLUSH && flush != Z_FINISH)) {
		US_ERR("invalid: flush is %d!\n", flush);
		return Z_STREAM_ERROR;
	}
	outbuffer_ptr out_buffer = (outbuffer_ptr)strm->adler;
	if (!out_buffer) {
		US_ERR("out_buffer is NULL");
		return Z_BUF_ERROR;
	}

	unsigned int remain_data = out_buffer->remained;
	if (type == WD_DIR_COMPRESS && unlikely(kz_deflate_check_strm_avail(strm, flush, remain_data))) {
		return Z_STREAM_ERROR;
	}
	if (remain_data != 0) {
		return kz_get_remain_data(strm, flush);
	}

	handle_t h_sess = strm->reserved;
	struct wd_comp_req req = {0};

	__u32 src_len = strm->avail_in;
	__u32 dst_len = strm->avail_out;
	US_DEBUG("avail_in is %u, avail_out is %u\n", src_len, dst_len);
	if (src_len == 0) {
		US_DEBUG("kaezip do comp success, for input_len == 0, comp type : %s",
			type == WD_DIR_COMPRESS ? "deflate" : "inflate");
		return flush == Z_FINISH ? Z_STREAM_END : Z_OK;
	}

	req.src = (void*)(strm->next_in);
	req.src_len = src_len;
	req.dst = (void*)(strm->next_out);
	req.dst_len = dst_len;
	req.op_type = type;
	req.data_fmt = WD_FLAT_BUF;
	req.last = (flush == Z_FINISH) ? 1 : 0;

	__u64 used_in;
	__u64 used_out;
	kz_outbuffer_reset(strm);
	int ret = kz_zlib_do_comp_implement(h_sess, &req, &used_in, &used_out, out_buffer);
	if (unlikely(ret)) {
		US_ERR("failed to do un/compress(%d)!\n", ret);
		return ret;
	}

	strm->next_in  += used_in;
	strm->next_out += used_out;
	strm->avail_in  = src_len - used_in;
	strm->avail_out = dst_len - used_out;
	strm->total_in  += used_in;
	strm->total_out += used_out;
	US_DEBUG("strm->total_in is %lu, strm->total_out is %lu\n\n", strm->total_in, strm->total_out);
	if ((flush == Z_FINISH && used_in == src_len) || (req.status == 1)) {
		ret = Z_STREAM_END;
	}
	return ret;
}

int kz_deflate_v2(z_streamp strm, int flush)
{
    return kz_zlib_do_request_v2(strm, flush, WD_DIR_COMPRESS);
}

int kz_inflate_v2(z_streamp strm, int flush)
{
    return kz_zlib_do_request_v2(strm, flush, WD_DIR_DECOMPRESS);
}
