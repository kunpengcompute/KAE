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
	wd_deflate_init(&g_init_strm, 1, 12);
}

static void __attribute((destructor)) wd_do_uninit_onlyone(void)
{
	wd_deflate_end(&g_init_strm);
}

static int wd_checkAndSet_remainData(z_streamp strm, int flush)
{
	kaezip_exdata *kz_exdata = (kaezip_exdata*)strm->opaque;
	if (!kz_exdata) {
		US_ERR("kaezip_exdata is NULL!\n");
	}

	unsigned int remain_len = kz_exdata->remain;
	US_DEBUG("remain data has %u Bytes\n", remain_len);
	if (remain_len != 0) {
		if (strm->avail_out < remain_len) {
			US_ERR("buffer error! no more avail_out!\n");
			return 0;
		}
		memcpy(strm->avail_out + strm->total_out, kz_exdata->output_buffer, kz_exdata->last_comp_out_len);
		strm->avail_out -= remain_len;
		strm->total_out += kz_exdata->last_comp_out_len;
	} else if (strm->avail_in == 0 && flush != Z_FINISH) {
		US_ERR("buffer error! no more avail_in!\n");
		return 0;
	}
	return 1;
}

static int wd_zlib_do_implement(handle_t h_sess, struct wd_comp_req *req, kaezip_exdata *kz_exdata)
{
	if (unlikely(!req || !kz_exdata)) {
		US_ERR("req or kz_exdata NULL!\n");
		return Z_ERRNO;
	}
	unsigned int total_avail_in  = req->src_len;
	unsigned int total_avail_out = req->dst_len;

	struct wd_comp_req strm_req;
	memcpy(&strm_req, req, sizeof(struct wd_comp_req));
	strm_req.dst = kz_exdata->output_buffer;
	strm_req.last = 0;
	do {
		strm_req.src_len = (total_avail_in > INPUT_CHUNK_V2 ? INPUT_CHUNK_V2 : total_avail_in);
		strm_req.dst_len = OUTPUT_CHUNK_V2;
		unsigned int orig_src_len = strm_req.src_len;
		unsigned int orig_dst_len = strm_req.dst_len;
		if (strm_req.op_type == WD_DIR_COMPRESS && req->last && total_avail_in <= INPUT_CHUNK_V2) {
			strm_req.last = 1;
		}

		int ret = wd_do_comp_strm(h_sess, &strm_req);
		if (unlikely(ret < 0 || strm_req.status == WD_IN_EPARA )) {
			US_ERR("wd_do_comp_strm, invaild or incomplete data! ret = %d, status = %d\n", ret, strm_req.status);
			US_DEBUG("src_len : %u/%u, dst_len : %u/%u\n", 
				orig_src_len, strm_req.src_len, orig_dst_len, strm_req.dst_len);
			return ret;
		}
		if (strm_req.dst_len > total_avail_out) {
			US_WARN("no more avail out space! need more %u Bytes!\n", kz_exdata->remain);
			US_DEBUG("src_len : %u/%u, dst_len : %u/%u\n", 
				orig_src_len, strm_req.src_len, orig_dst_len, strm_req.dst_len);
			kz_exdata->remain = strm_req.dst_len - total_avail_out;
			kz_exdata->last_comp_in_len  = strm_req.src_len;
			kz_exdata->last_comp_out_len = strm_req.dst_len;
			kz_exdata->chunk_total_in   += strm_req.src_len;
			break;
		}

		kz_exdata->chunk_total_out += strm_req.dst_len;
		memcpy(req->dst, strm_req.dst, strm_req.dst_len);
		req->dst += strm_req.dst_len;
		total_avail_out -= strm_req.dst_len;

		kz_exdata->chunk_total_in += strm_req.src_len;
		strm_req.src += strm_req.src_len;
		total_avail_in -= strm_req.src_len;
	} while ((total_avail_in != 0) && (total_avail_out != 0));

	req->status = strm_req.status;
	return Z_OK;
}

static int wd_zlib_do_request_v2(z_streamp strm, int flush, enum wd_comp_op_type type)
{
	if (unlikely(!strm)) {
		US_ERR("strm NULL!\n");
		return Z_STREAM_ERROR;
	}
	if (!wd_checkAndSet_remainData(strm, flush)) {
		return Z_BUF_ERROR;
	}

	flush = (flush == Z_NO_FLUSH ? Z_SYNC_FLUSH : flush);
	if (unlikely(flush != Z_SYNC_FLUSH && flush != Z_FINISH)) {
		US_ERR("invalid : flush is %d\n", flush);
		return Z_STREAM_ERROR;
	}

	unsigned int src_len = strm->avail_in;
	unsigned int dst_len = strm->avail_out;
	struct wd_comp_req req = {0};
	req.src      = (void*)(strm->next_in + strm->total_in);
	req.src_len  = src_len;
	req.dst      = (void*)(strm->next_out + strm->total_out);
	req.src_len  = dst_len;
	req.op_type  = type;
	req.data_fmt = WD_FLAT_BUF;
	req.last     = (flush == Z_FINISH ? 1 : 0);
	US_DEBUG("before %s, strm->avail_in = %u, strm->avail_out = %u, strm->total_in = %llu, strm->total_out = %llu, is_last_chunk = %u\n",
		type ? "decompress" : "compress", strm->avail_in, strm->avail_out, strm->total_in, strm->total_out, req.last);
	
	/********************************/
	kaezip_exdata *kz_exdata = (kaezip_exdata*)strm->opaque;
	memset(kz_exdata, 0, sizeof(kaezip_exdata));
	handle_t h_sess = strm->reserved;
	int ret = wd_zlib_do_implement(h_sess, &req, kz_exdata);
	if (unlikely(ret)) {
		US_ERR("failed to do %s, ret is %d\n", type ? "decompress" : "compress", ret);
		return Z_STREAM_ERROR;
	}
	/********************************/

	strm->avail_in   = src_len - kz_exdata->chunk_total_in;
	strm->avail_out  = (kz_exdata->remain == 0) ? dst_len - kz_exdata->chunk_total_out : 0;
	strm->total_in  += kz_exdata->chunk_total_in;
	strm->total_out += kz_exdata->chunk_total_out;
	US_DEBUG("after %s, strm->avail_in = %u, strm->avail_out = %u, strm->total_in = %llu, strm->total_out = %llu, is_last_chunk = %u\n",
		type ? "decompress" : "compress", strm->avail_in, strm->avail_out, strm->total_in, strm->total_out, req.last);
	
	if (type == WD_DIR_COMPRESS && flush == Z_FINISH && 
		kz_exdata->chunk_total_in == src_len && kz_exdata->remain == 0) {
		ret = Z_STREAM_END;
	} else if (type == WD_DIR_DECOMPRESS && req.status == WD_STREAM_END && kz_exdata->remain == 0) {
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
