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
#include "kaezip_log.h"

static z_stream g_init_strm = {0};

static void __attribute((constructor)) wd_do_init_onlyone(void)
{
	wd_deflateInit_(&g_init_strm, 1, NULL, 0);
}

static void __attribute((destructor)) wd_do_uninit_onlyone(void)
{
	wd_deflateEnd(&g_init_strm);
}

static int wd_check_params(struct wd_comp_req *req)
{
	if (unlikely(!req)) {
		US_ERR("invalid: req is NULL!\n");
		return -WD_EINVAL;
	}
	if (unlikely(!req->src || !req->dst)) {
		US_ERR("invalid: src or dst is NULL!\n");
		return -WD_EINVAL;
	}
	if (unlikely(!req->src_len)) {
		return Z_STREAM_END;
	}
	if (unlikely(!req->dst_len)) {
		US_ERR("invalid: dst_len is 0!\n");
		return -WD_EINVAL;
	}
	return WD_SUCCESS;
}

static int wd_zlib_do_comp_implement(handle_t h_sess, struct wd_comp_req *req, __u32 *borrowd_dst_len,
	__u64 *used_in, __u64 *used_out)
{
	int ret = wd_check_params(req);
	if (unlikely(ret)) {
		return ret;
	}
	__u32 total_avail_in  = req->src_len;
	__u32 total_avail_out = req->dst_len;

	struct wd_comp_req strm_req;
	memcpy(&strm_req, req, sizeof(struct wd_comp_req));
	req->src_len = 0;
	req->dst_len = 0;
	*used_in = *used_out = 0;
	void *tmp_dst_buffer = malloc(OUTPUT_CHUNK_V2);
	if (!tmp_dst_buffer) {
		return -WD_EINVAL;
	}
	strm_req.dst = tmp_dst_buffer;

	// 该接口至多压缩/解压缩(u32_max)个字节，若超过, 则重复调用
	// 因此需根据req->last判断是否为最后一个大块
	int is_real_last = req->last;
	strm_req.last = 0;
	do {
		strm_req.src_len = total_avail_in > INPUT_CHUNK_V2 ? INPUT_CHUNK_V2 : total_avail_in;
		strm_req.dst_len = OUTPUT_CHUNK_V2;
		__u32 orig_src_len = strm_req.src_len;
		__u32 orig_dst_len = OUTPUT_CHUNK_V2 / 2;

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
			free(tmp_dst_buffer);
			return ret;
		}
		if (strm_req.dst_len > total_avail_out) {
			*borrowd_dst_len = strm_req.dst_len - total_avail_out;
			total_avail_out = strm_req.dst_len;
			US_ERR("no more avail out space! borrowed dst len is %u\n", *borrowd_dst_len);
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

	free(tmp_dst_buffer);
	req->status = strm_req.status;
	return 0;
}

static int wd_zlib_do_request_v2(z_streamp strm, int flush, enum wd_comp_op_type type)
{
	if (unlikely(flush != Z_SYNC_FLUSH && flush != Z_NO_FLUSH && flush != Z_FINISH)) {
		US_ERR("invalid: flush is %d!\n", flush);
		return Z_STREAM_ERROR;
	}
	handle_t h_sess = strm->reserved;
	struct wd_comp_req req = {0};

	__u32 borrowed_dst_len = strm->adler;
	__u32 src_len = strm->avail_in;
	__u32 dst_len = strm->avail_out > borrowed_dst_len ? strm->avail_out - borrowed_dst_len : 0;
	US_DEBUG("borrowed dst len is %u, avail_in is %u, avail_out is %u\n",
		borrowed_dst_len, src_len, dst_len);

	req.src = (void*)(strm->next_in + strm->total_in);
	req.src_len = src_len;
	req.dst = (void*)(strm->next_out + strm->total_out);
	req.dst_len = dst_len;
	req.op_type = type;
	req.data_fmt = WD_FLAT_BUF;
	req.last = (flush == Z_FINISH) ? 1 : 0;

	borrowed_dst_len = 0;
	__u64 used_in;
	__u64 used_out;
	int ret = wd_zlib_do_comp_implement(h_sess, &req, &borrowed_dst_len, &used_in, &used_out);
	if (unlikely(ret)) {
		US_ERR("failed to do un/compress(%d)!\n", ret);
		return ret;
	}

	strm->adler = borrowed_dst_len;
	strm->avail_in  = src_len - used_in;
	strm->avail_out = (strm->adler == 0) ? dst_len - used_out : 0;
	strm->total_in  += used_in;
	strm->total_out += used_out;
	US_DEBUG("strm->total_in is %llu, strm->total_out is %llu\n\n", strm->total_in, strm->total_out);
	if ((flush == Z_FINISH && used_in == src_len) || (req.status == 1)) {
		ret = Z_STREAM_END;
	}
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
