//
// Created by hWX748325 on 2021-07-19.
//

#include <openssl/pem.h>
#include "uadk_common.h"

#define SM2_MODE_SIZE 3
#define SM2_KEY_SIZE 3
#define MAX_OUT_SIZE 128

typedef const EVP_MD *(*EVP_md_method)(void);

typedef enum {
	GENKEY,
	SIGN,
	VERIFY,
	ENCRYPT,
	DECRYPT
} SM2_MODE;

struct sm2_async_param {
	EVP_MD_CTX *mctx;
	EVP_PKEY_CTX *pctx;
	EC_KEY *key;
	SM2_MODE mode;
	unsigned char *output;
	size_t *out_size;
	unsigned char *input;
	size_t *in_size;
};

struct sm2_key_data {
	SM2_MODE mode;
	bool async;
	EC_KEY *key;
};

struct sm2_raw_data {
	unsigned char *input;
	unsigned char *id;
	unsigned char *output;
	size_t in_size;
	size_t id_size;
	size_t out_size;
	unsigned int thread_num;
	acc_check_type check_type;
	bool async;
	int count;
	int result;
	int loop_time;
};

struct sm2_setup_data {
	size_t input_size;
	size_t id_size;
	size_t output_size;
	bool async;
	unsigned int thread_num;
	acc_source_mode src_mode;
	acc_check_type check_type;
	bool perf_flag;
	int count;
	int loop_time;
};

struct get_evp_md_funcs {
	char alg_name[MAX_ALG_LEN];
	EVP_md_method method;
};

static EC_KEY *key = NULL;
static const EVP_MD *type = NULL;
static EVP_PKEY *pkey = NULL;
static char hash_alg[20] = {0};
static char mode_name[20] = {0};
static char id_need[20] = {0};
static SM2_MODE mode = 0;

static struct get_evp_md_funcs get_evps[] = {
		{"sm3", EVP_sm3},
		{"md5", EVP_md5},
		{"sha1", EVP_sha1},
		{"sha256", EVP_sha256},
		{"sha224", EVP_sha224},
		{"md4", EVP_md4},
		{"sha384", EVP_sha384},
		{"sha512", EVP_sha512}
};

static int sm2_jobfunc(void *arg)
{
	ASYNC_JOB *currjob;
	struct sm2_async_param *async_param = (struct sm2_async_param *)arg;
	int ret = 0;

	currjob = ASYNC_get_current_job();
	if (!currjob) {
		LOG(ERR, "Error: not executing within a job \n");
		return ret;
	}
	if (async_param->mode == SIGN) {
		if (type != NULL)
			ret = EVP_DigestSign(async_param->mctx, async_param->output, async_param->out_size,
								 async_param->input, *async_param->in_size);
		else
			ret = EVP_PKEY_sign(async_param->pctx, async_param->output, async_param->out_size,
								async_param->input, *async_param->in_size);
	} else if (async_param->mode == VERIFY) {
		if (type != NULL)
			ret = EVP_DigestVerify(async_param->mctx, async_param->input, *async_param->in_size,
								   async_param->output, *async_param->out_size);
		else
			ret = EVP_PKEY_verify(async_param->pctx, async_param->input, *async_param->in_size,
								  async_param->output, *async_param->out_size);
	} else if (async_param->mode == ENCRYPT) {
		ret = EVP_PKEY_encrypt(async_param->pctx, async_param->output, async_param->out_size,
							   async_param->input, *async_param->in_size);
	} else if (async_param->mode == DECRYPT) {
		ret = EVP_PKEY_decrypt(async_param->pctx, async_param->output, async_param->out_size,
							   async_param->input, *async_param->in_size);
	} else if (async_param->mode == GENKEY) {
		ret = EC_KEY_generate_key(async_param->key);
	}
	return ret;
}

static int sm2_async(void *arg)
{
	LOG(INF, "Info: run sm2 %s async \n", mode_name);
	ASYNC_JOB *job = NULL;
	ASYNC_WAIT_CTX *waitctx = NULL;
	size_t numfds = 0;
	OSSL_ASYNC_FD waitfd = 0;
	fd_set waitfdset;
	int ret = 0;

	waitctx = ASYNC_WAIT_CTX_new();
	if (waitctx == NULL) {
		LOG(ERR, "Error: create ASYNC_WAIT_CTX failed \n");
		return ret;
	}
	for (;;) {
		switch (ASYNC_start_job(&job, waitctx, &ret, sm2_jobfunc, arg, sizeof(struct sm2_async_param))) {
			case ASYNC_ERR:
				LOG(ERR, "Error: start sm2 async job err \n");
				goto exit_pause;
			case ASYNC_NO_JOBS:
				LOG(ERR, "Error: can't get sm2 async job from job pool \n");
				goto exit_pause;
			case ASYNC_PAUSE:
				LOG(INF, "Info: job was paused \n");
				break;
			case ASYNC_FINISH:
				LOG(INF, "Info: job finished with return value %d \n", ret);
				goto exit_pause;
		}
		/* wait for the job to be woken */
		LOG(DBG, "Debug: waitting for the job to be woken up \n");
		if (!ASYNC_WAIT_CTX_get_all_fds(waitctx, NULL, &numfds) || numfds > 1) {
			LOG(ERR, "Error: unexpected number of fds \n");
			ret = DOF;
			goto exit_pause;
		}
		ASYNC_WAIT_CTX_get_all_fds(waitctx, &waitfd, &numfds);
		FD_ZERO(&waitfdset);
		FD_SET(waitfd, &waitfdset);
		select(waitfd + 1, &waitfdset, NULL, NULL, NULL);
	}
exit_pause:
	ASYNC_WAIT_CTX_free(waitctx);
	LOG(DBG, "Debug: finish sm2 %s async \n", mode_name);
	return ret;
}

static EC_KEY *get_ec_key(struct sm2_key_data *data)
{
	EC_KEY *lkey = NULL;
	EC_GROUP *group = NULL;
	struct sm2_async_param async_param;
	int ret = 0;

	lkey = EC_KEY_new();
	if (!lkey) {
		LOG(ERR, "Error: new EC_KEY failed. \n");
		goto group_free;
	}
	group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!group) {
		LOG(ERR, "Error: new group via curve failed. \n");
		EC_KEY_free(lkey);
		lkey = NULL;
		goto group_free;
	}
	ret = EC_KEY_set_group(lkey, group);
	if (ret != 1) {
		LOG(ERR, "Error: key associate with curve group failed. \n");
		EC_KEY_free(lkey);
		lkey = NULL;
		goto group_free;
	}
	if (data->mode == GENKEY && data->async) {
		async_param.key = lkey;
		async_param.mode = GENKEY;
		ret = sm2_async(&async_param);
	} else {
		ret = EC_KEY_generate_key(lkey);
	}
	if (ret != 1) {
		LOG(ERR, "Error: generate EC_key failed. \n");
		EC_KEY_free(lkey);
		lkey = NULL;
		goto group_free;
	}
	if (data->mode == GENKEY && log_lvl == DBG) {
		BIGNUM *bn_pri_key = NULL;
		const EC_POINT *point = NULL;
		unsigned char *pub_key = NULL, *pri_key = NULL;
		size_t pri_size = 0, pub_size = 0;
		bn_pri_key = (BIGNUM *)EC_KEY_get0_private_key((const EC_KEY *)lkey);
		if (!bn_pri_key) {
			LOG(ERR, "Error: get private key from ec_key failed \n");
			EC_KEY_free(lkey);
			lkey = NULL;
			goto group_free;
		}
		point = EC_KEY_get0_public_key(lkey);
		if (!point) {
			LOG(ERR, "Error: get ec point failed. \n");
			EC_KEY_free(lkey);
			lkey = NULL;
			goto group_free;
		}
		pri_key = malloc((unsigned long)BN_num_bytes(bn_pri_key));
		pri_size = (size_t)BN_bn2bin(bn_pri_key, (void *)pri_key);
		print_hex_bytes("pri_key", (char *)pri_key, pri_size, log_lvl);
		pub_size = (size_t)EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED, &pub_key, NULL);
		print_hex_bytes("pub_key", (char *)pub_key, pub_size, log_lvl);
		if (pri_key)
			free(pri_key);
		if (pub_key)
			OPENSSL_free(pub_key);
	}
group_free:
	if (group)
		EC_GROUP_free(group);
	data->key = lkey;
	return lkey;
}

static EVP_PKEY *get_evp_pkey(void)
{
	EVP_PKEY *lpkey = NULL;
	BIO *bio_pri = BIO_new(BIO_s_mem());
	unsigned char *bio_pri_key = NULL;
	int bio_pri_len = 0;
	BIO *bio_pri_buff = NULL;

	PEM_write_bio_ECPrivateKey(bio_pri, key, NULL, NULL, 0, NULL, NULL);
	bio_pri_len = BIO_pending(bio_pri);
	bio_pri_key = malloc((unsigned long)bio_pri_len);
	BIO_read(bio_pri, bio_pri_key, bio_pri_len);
	bio_pri_buff = BIO_new_mem_buf(bio_pri_key, -1);
	if (bio_pri_buff == NULL) {
		LOG(ERR, "Error: BIO_new_mem_buf failed, \n");
		goto pkey_free;
	}
	lpkey = PEM_read_bio_PrivateKey(bio_pri_buff, NULL, NULL, NULL);
pkey_free:
	if (bio_pri_key)
		free(bio_pri_key);
	if (bio_pri)
		BIO_free(bio_pri);
	if (bio_pri_buff)
		BIO_free(bio_pri_buff);
	return lpkey;
}

static int openssl_sm2_sign(struct sm2_raw_data *data)
{
	LOG(DBG, "Debug: run sm2 sign \n");
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *mctx = EVP_MD_CTX_new();
	struct sm2_async_param async_param;
	size_t out_size = data->out_size;
	struct timeval begin_tval;
	struct timeval end_tval;
	double time_used = 0;
	int ret = AGF;
	int cnt = 0;

	gettimeofday(&begin_tval, NULL);
	while (1) {
		data->out_size = out_size;
		pctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (pctx == NULL) {
			LOG(ERR, "Error: new EVP_PKEY_CTX failed \n");
			ret = DOF;
			goto free_evp_sign;
		}
		if (strcmp(id_need, "no_id") != 0) {
			EVP_PKEY_CTX_set1_id(pctx, (const uint8_t *)data->id, data->id_size);
		}
		EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
		async_param.mctx = mctx;
		async_param.pctx = pctx;
		async_param.mode = SIGN;
		async_param.output = data->output;
		async_param.out_size = &data->out_size;
		async_param.input = data->input;
		async_param.in_size = &data->in_size;

		if (type != NULL) {
			ret = EVP_DigestSignInit(mctx, NULL, type, NULL, pkey);
			if (ret != 1) {
				LOG(ERR, "Error: sm2 digest sign init failed with %s, ret = %d \n", hash_alg, ret);
				ret = DOF;
				goto free_evp_sign;
			}
			if (data->async)
				ret = sm2_async((void *)&async_param);
			else
				ret = EVP_DigestSign(mctx, data->output, &data->out_size, data->input, data->in_size);

			if (ret != 1) {
				LOG(ERR, "Error: 2 sm2 digest sign failed with %s, ret = %d \n", hash_alg, ret);
				ret = DOF;
				goto free_evp_sign;
			}
		} else {
			ret = EVP_PKEY_sign_init(pctx);
			if (ret != 1) {
				LOG(ERR, "Error: sm2 sign init failed, ret = %d \n", ret);
				ret = DOF;
				goto free_evp_sign;
			}
			if (data->async)
				ret = sm2_async((void *)&async_param);
			else
				ret = EVP_PKEY_sign(pctx, data->output, &data->out_size, data->input, data->in_size);

			if (ret != 1) {
				LOG(ERR, "Error: 2 sm2 sign failed, ret = %d \n", ret);
				ret = DOF;
				goto free_evp_sign;
			}
		}
		cnt++;
		if (data->loop_time == 0 && cnt == data->count) {
			break;
		} else if (data->loop_time != 0) {
			gettimeofday(&end_tval, NULL);
			time_used = (double)((end_tval.tv_sec - begin_tval.tv_sec) * S_TO_US_TIME +
								 end_tval.tv_usec - begin_tval.tv_usec);
			if (time_used >= data->loop_time * S_TO_US_TIME)
				break;
		}
	}
	ret = 0;
free_evp_sign:
	print_hex_bytes("sign_input", (char *)data->input, data->in_size, log_lvl);
	print_hex_bytes("sign_id", (char *)data->id, data->id_size, log_lvl);
	print_hex_bytes("sign_output", (char *)data->output, data->out_size, log_lvl);
	if (mctx)
		EVP_MD_CTX_free(mctx);
	if (pctx)
		EVP_PKEY_CTX_free(pctx);
	data->result = ret;
	return ret;
}

static int openssl_sm2_verify(struct sm2_raw_data *data)
{
	LOG(DBG, "Debug: run sm2 verify \n");
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *mctx = EVP_MD_CTX_new();
	struct sm2_async_param async_param;
	struct timeval begin_tval;
	struct timeval end_tval;
	double time_used = 0;
	int ret = AGF;
	int cnt = 0;

	gettimeofday(&begin_tval, NULL);
	while (1) {
		pctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (pctx == NULL) {
			LOG(ERR, "Error: new EVP_PKEY_CTX failed \n");
			ret = DOF;
			goto free_evp_verify;
		}
		if (strcmp(id_need, "no_id") != 0) {
			EVP_PKEY_CTX_set1_id(pctx, (const uint8_t *)data->id, data->id_size);
		}
		EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
		async_param.mctx = mctx;
		async_param.pctx = pctx;
		async_param.mode = VERIFY;
		async_param.output = data->output;
		async_param.out_size = &data->out_size;
		async_param.input = data->input;
		async_param.in_size = &data->in_size;

		if (type != NULL) {
			ret = EVP_DigestVerifyInit(mctx, NULL, type, NULL, pkey);
			if (ret != 1) {
				LOG(ERR, "Error: sm2 digest verify init failed with %s, ret = %d \n", hash_alg, ret);
				ret = DOF;
				goto free_evp_verify;
			}
			if (data->async)
				ret = sm2_async((void *)&async_param);
			else
				ret = EVP_DigestVerify(mctx, data->input, data->in_size, data->output, data->out_size);
			if (ret != 1) {
				LOG(ERR, "Error: sm2 digest verify failed with %s, ret = %d \n", hash_alg, ret);
				ret = DOF;
				goto free_evp_verify;
			}
		} else {
			ret = EVP_PKEY_verify_init(pctx);
			if (ret != 1) {
				LOG(ERR, "Error: sm2 verify init failed, ret = %d \n", ret);
				ret = DOF;
				goto free_evp_verify;
			}
			if (data->async)
				ret = sm2_async((void *)&async_param);
			else
				ret = EVP_PKEY_verify(pctx, data->input, data->in_size, data->output, data->out_size);
			if (ret != 1) {
				LOG(ERR, "Error: sm2 verify failed, ret = %d \n", ret);
				ret = DOF;
				goto free_evp_verify;
			}
		}
		cnt++;
		if (data->loop_time == 0 && cnt == data->count) {
			break;
		} else if (data->loop_time != 0) {
			gettimeofday(&end_tval, NULL);
			time_used = (double)((end_tval.tv_sec - begin_tval.tv_sec) * S_TO_US_TIME +
								 end_tval.tv_usec - begin_tval.tv_usec);
			if (time_used >= data->loop_time * S_TO_US_TIME)
				break;
		}
	}
	ret = 0;
free_evp_verify:
	print_hex_bytes("verify_input", (char *)data->input, data->in_size, log_lvl);
	print_hex_bytes("verify_id", (char *)data->id, data->id_size, log_lvl);
	print_hex_bytes("verify_output", (char *)data->output, data->out_size, log_lvl);
	if (pctx != NULL)
		EVP_PKEY_CTX_free(pctx);
	if (mctx != NULL)
		EVP_MD_CTX_free(mctx);
	data->result = ret;
	return ret;
}

static int openssl_sm2_encrypt(struct sm2_raw_data *data)
{
	LOG(DBG, "Debug: run sm2 encrypt \n");
	EVP_PKEY_CTX *pctx = NULL;
	struct sm2_async_param async_param;
	struct timeval begin_tval;
	struct timeval end_tval;
	double time_used = 0;
	int ret = AGF;
	int cnt = 0;

	gettimeofday(&begin_tval, NULL);
	while (1) {
		pctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (pctx == NULL) {
			LOG(ERR, "Error: new EVP_PKEY_CTX failed \n");
			ret = DOF;
			goto free_evp_encrypt;
		}
		async_param.mctx = NULL;
		async_param.pctx = pctx;
		async_param.mode = ENCRYPT;
		async_param.output = data->output;
		async_param.out_size = &data->out_size;
		async_param.input = data->input;
		async_param.in_size = &data->in_size;
		ret = EVP_PKEY_encrypt_init(pctx);
		if (ret != 1) {
			LOG(ERR, "Error: sm2 EVP_PKEY_encrypt init failed \n");
			ret = DOF;
			goto free_evp_encrypt;
		}
		ret = EVP_PKEY_CTX_ctrl(pctx, -1, -1, EVP_PKEY_CTRL_MD, -1, (void *)type);
		if (ret <= 0) {
			LOG(ERR, "Error: sm2 EVP_PKEY_CTX_ctr control pctx failed \n");
			ret = DOF;
			goto free_evp_encrypt;
		}
		if (data->async)
			ret = sm2_async((void *)&async_param);
		else
			ret = EVP_PKEY_encrypt(pctx, data->output, &data->out_size, (const unsigned char *)data->input,
								   data->in_size);
		if (ret != 1) {
			LOG(ERR, "Error: sm2 EVP_PKEY_encrypt failed \n");
			ret = DOF;
			goto free_evp_encrypt;
		}
		cnt++;
		if (data->loop_time == 0 && cnt == data->count) {
			break;
		} else if (data->loop_time != 0) {
			gettimeofday(&end_tval, NULL);
			time_used = (double)((end_tval.tv_sec - begin_tval.tv_sec) * S_TO_US_TIME +
								 end_tval.tv_usec - begin_tval.tv_usec);
			if (time_used >= data->loop_time * S_TO_US_TIME)
				break;
		}
	}
	ret = 0;
free_evp_encrypt:
	print_hex_bytes("encrypt_input", (char *)data->input, data->in_size, log_lvl);
	print_hex_bytes("encrypt_output", (char *)data->output, data->out_size, log_lvl);
	if (pctx != NULL)
		EVP_PKEY_CTX_free(pctx);
	data->result = ret;
	return ret;
}

static int openssl_sm2_decrypt(struct sm2_raw_data *data)
{
	LOG(DBG, "Debug: run sm2 decrypt \n");
	EVP_PKEY_CTX *pctx = NULL;
	struct sm2_async_param async_param;
	struct timeval begin_tval;
	struct timeval end_tval;
	double time_used = 0;
	int ret = AGF;
	int cnt = 0;

	gettimeofday(&begin_tval, NULL);
	while (1) {
		pctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (pctx == NULL) {
			LOG(ERR, "Error: new EVP_PKEY_CTX failed \n");
			ret = DOF;
			goto free_evp_decrypt;
		}
		async_param.mctx = NULL;
		async_param.pctx = pctx;
		async_param.mode = DECRYPT;
		async_param.output = data->output;
		async_param.out_size = &data->out_size;
		async_param.input = data->input;
		async_param.in_size = &data->in_size;
		ret = EVP_PKEY_decrypt_init(pctx);
		if (ret != 1) {
			LOG(ERR, "Error: sm2 EVP_PKEY_decrypt_init failed \n");
			ret = DOF;
			goto free_evp_decrypt;
		}
		if (type != NULL)
			ret = EVP_PKEY_CTX_ctrl_str(pctx, "digest", hash_alg);
		if (ret <= 0) {
			LOG(ERR, "Error: sm2 EVP_PKEY_CTX_ctrl_str control pctx failed, ret = %d \n", ret);
			ret = DOF;
			goto free_evp_decrypt;
		}
		if (data->async)
			ret = sm2_async((void *)&async_param);
		else
			ret = EVP_PKEY_decrypt(pctx, data->output, &data->out_size, (const unsigned char *)data->input,
								   data->in_size);
		if (ret != 1) {
			LOG(ERR, "Error: sm2 EVP_PKEY_decrypt failed. \n");
			ret = DOF;
			goto free_evp_decrypt;
		}
		cnt++;
		if (data->loop_time == 0 && cnt == data->count) {
			break;
		} else if (data->loop_time != 0) {
			gettimeofday(&end_tval, NULL);
			time_used = (double)((end_tval.tv_sec - begin_tval.tv_sec) * S_TO_US_TIME +
								 end_tval.tv_usec - begin_tval.tv_usec);
			if (time_used >= data->loop_time * S_TO_US_TIME)
				break;
		}
	}
	ret = 0;
free_evp_decrypt:
	print_hex_bytes("decrypt_input", (char *)data->input, data->in_size, log_lvl);
	print_hex_bytes("decrypt_output", (char *)data->output, data->out_size, log_lvl);
	if (pctx != NULL)
		EVP_PKEY_CTX_free(pctx);
	data->result = ret;
	return ret;
}

static int sm2_engine_register(void)
{
	LOG(DBG, "Debug: sm2 engine register \n");
	ENGINE *e = NULL;
	e = ENGINE_by_id("uadk_engine");
	if (!e) {
		LOG(ERR, "Error: not find uadk engine \n");
		return 1;
	}
	ENGINE_init(e);
	ENGINE_register_EC(e);
	ENGINE_register_pkey_meths(e);
	ENGINE_free(e);
	return 0;
}

static int sm2_engine_unregister(void)
{
	LOG(DBG, "Debug: sm2 engine unregister \n");
	ENGINE *e = NULL;
	e = ENGINE_by_id("uadk_engine");
	if (!e) {
		LOG(ERR, "Error: not find uadk engine \n");
		return 1;
	}
	ENGINE_init(e);
	ENGINE_unregister_EC(e);
	ENGINE_unregister_pkey_meths(e);
	ENGINE_free(e);
	return 0;
}

static int hisi_sm2_data_process(struct sm2_raw_data *raw_data)
{
	int ret = AGF;
	unsigned char *e_output = NULL, *o_output = NULL;
	size_t e_output_size = 0;
	struct sm2_raw_data *sm2_data = NULL;

	sm2_data = malloc(sizeof(struct sm2_raw_data));
	if (!sm2_data) {
		LOG(ERR, "Error: malloc sm2_data fail.");
		return RSF;
	}
	memcpy(sm2_data, raw_data, sizeof(struct sm2_raw_data));
	sm2_data->input = malloc(sm2_data->in_size);
	if (!sm2_data->input) {
		LOG(ERR, "Error: sm2_data->input malloc fail!");
		ret = RSF;
		goto free_resources_single;
	}
	RAND_priv_bytes((void *)sm2_data->input, sm2_data->in_size);
	sm2_data->id = malloc(sm2_data->id_size);
	if (!sm2_data->id) {
		LOG(ERR, "Error: sm2_data->id malloc fail!");
		ret = RSF;
		goto free_resources_single;
	}
	RAND_priv_bytes((void *)sm2_data->id, sm2_data->id_size);
	if (mode == SIGN || mode == VERIFY) {
		e_output = malloc(MAX_OUT_SIZE);
		if (!e_output) {
			LOG(ERR, "Error: e_output malloc fail!");
			ret = RSF;
			goto free_resources_single;
		}
		memset(e_output, 0, MAX_OUT_SIZE);
	} else {
		e_output = malloc(sm2_data->out_size + MAX_OUT_SIZE);
		if (!e_output) {
			LOG(ERR, "Error: e_output malloc fail!");
			ret = RSF;
			goto free_resources_single;
		}
		memset(e_output, 0, sm2_data->out_size + MAX_OUT_SIZE);
	}
	o_output = malloc(sm2_data->out_size + MAX_OUT_SIZE);
	if (!o_output) {
		LOG(ERR, "Error: o_output malloc fail!");
		ret = RSF;
		goto free_resources_single;
	}
	memset(o_output, 0, sm2_data->out_size + MAX_OUT_SIZE);
	sm2_data->output = e_output;

	if (mode == SIGN || mode == VERIFY)
		ret = openssl_sm2_sign(sm2_data);
	else
		ret = openssl_sm2_encrypt(sm2_data);
	if (ret)
		goto free_resources_single;
	else {
		if (mode == SIGN || mode == VERIFY)
			LOG(INF, "Info: do sm2_sign success. \n");
		else
			LOG(INF, "Info: do sm2_encrypt success. \n");
	}

	if (mode == SIGN || mode == ENCRYPT) {
		ret = sm2_engine_unregister();
		if (ret)
			goto free_resources_single;
	}

	e_output_size = sm2_data->out_size;
	if (sm2_data->check_type == CHECK_OPENSSL || mode == VERIFY || mode == DECRYPT) {
		LOG(DBG, "Debug: verify or decrypt the result before \n");
		struct sm2_raw_data data;
		memset(&data, 0, sizeof(struct sm2_raw_data));
		data.id = sm2_data->id;
		data.id_size = sm2_data->id_size;
		data.thread_num = sm2_data->thread_num;
		data.check_type = sm2_data->check_type;
		data.async = sm2_data->async;
		data.count = sm2_data->count;

		if (mode == SIGN || mode == VERIFY) {
			data.output = sm2_data->input;
			data.out_size = sm2_data->in_size;
		} else {
			data.output = o_output;
			data.out_size = sm2_data->out_size;
		}
		data.input = sm2_data->output;
		data.in_size = e_output_size;
		if (mode == SIGN || mode == VERIFY)
			ret = openssl_sm2_verify(&data);
		else
			ret = openssl_sm2_decrypt(&data);
		if (ret)
			goto free_resources_single;
		else {
			if (mode == SIGN || mode == VERIFY)
				LOG(INF, "Info: do sm2_verify success. \n");
		}
		if (mode == ENCRYPT || mode == DECRYPT) {
			if (sm2_data->in_size != data.out_size) {
				LOG(ERR, "Error: do sm2_decrypt failed: input_size: %ld, out_size: %ld \n", data.in_size,
					data.out_size);
				ret = DIF;
				goto free_resources_single;
			}
			ret = compare_bytes((char *)sm2_data->input, (char *)data.output, sm2_data->in_size, log_lvl);
			if (ret == 0)
				LOG(INF, "Info: do sm2_decrypt success \n");
			else
				LOG(ERR, "Error: do sm2_decrypt failed \n");
		}
	}
	ret = 0;
free_resources_single:
	raw_data->result = ret;
	if (sm2_data->id)
		free(sm2_data->id);
	if (sm2_data->input)
		free(sm2_data->input);
	if (sm2_data)
		free(sm2_data);
	if (e_output)
		free(e_output);
	if (o_output)
		free(o_output);
	return ret;
}

static int uadk_sm2_pool_setup(struct sm2_setup_data *data)
{
	unsigned int thread_num = data->thread_num;
	struct sm2_raw_data raw_data[thread_num];
	struct sm2_key_data key_data;
	wayca_sc_threadpool_t threadpool = 0;
	int success_thread_num = 0;
	int running_task_num = 0;
	int succ_thread_num = 0;
	int work_thread_num = 0;
	int wait_task_num = 0;
	int ret = AGF;
	int ok_cnt = 0;
	int i = 0;

	// register uadk engine;
	ret = sm2_engine_register();
	if (ret)
		return ret;

	for (i = 0; i < KP_ARRAY_SIZE(get_evps); i++) {
		if (!strcmp(hash_alg, get_evps[i].alg_name)) {
			type = get_evps[i].method();
			break;
		}
	}

	memset(&key_data, 0, sizeof(struct sm2_key_data));
	key_data.mode = mode;
	key_data.async = data->async;
	key_data.key = NULL;
	key = get_ec_key(&key_data);
	if (!key)
		return DOF;

	pkey = get_evp_pkey();
	if (pkey == NULL) {
		LOG(ERR, "Error: failed to generate EVP_PKEY \n");
		ret = DOF;
		goto free_resources;
	}
	ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
	if (ret != 1) {
		LOG(ERR, "Error: set alias type to EVP_PKEY_SM2 failed \n");
		ret = DOF;
		goto free_resources;
	}

	// 创建线程池
	succ_thread_num = wayca_sc_threadpool_create(&threadpool, NULL, MAX_THREAD_POOL_NUM);
	if (succ_thread_num <= 0) {
		LOG(ERR, "Failed to wayca_sc_threadpool_create, thread_num:%d.", succ_thread_num);
		ret = AGF;
		goto free_resources_multiple;
	}

	work_thread_num = wayca_sc_threadpool_thread_num(threadpool);
	if (work_thread_num <= 0) {
		LOG(ERR, "Failed to check wayca_sc_threadpool_thread_num: %d", work_thread_num);
		ret = AGF;
		goto free_resources_multiple;
	}
	LOG(NTC, "Notice: work_thread_num:%d", work_thread_num);

	if (mode == GENKEY) {
		struct sm2_key_data test_key_data[thread_num];
		// 提交线程池任务
		for (i = 0; i < thread_num; i++) {
			memset(&test_key_data[i], 0, sizeof(struct sm2_key_data));
			test_key_data[i].mode = mode;
			test_key_data[i].async = data->async;
			test_key_data[i].key = NULL;
			ret = wayca_sc_threadpool_queue(threadpool, (void *)get_ec_key, (void *)&test_key_data[i]);
			if (ret) {
				LOG(ERR, "Failed to wayca_sc_threadpool_queue:%d, ret_code:%d.", i, ret);
				ret = AGF;
				goto free_resources_multiple;
			}
		}
		wait_task_num = wayca_sc_threadpool_task_num(threadpool);
		if (wait_task_num < 0) {
			LOG(ERR, "Failed to check wayca_sc_threadpool_task_num: %d", wait_task_num);
			ret = AGF;
			goto free_resources_multiple;
		}
		LOG(NTC, "Notice: wait_task_num:%d", wait_task_num);
		running_task_num = wayca_sc_threadpool_running_num(threadpool);
		if (running_task_num < 0) {
			LOG(ERR, "Failed to check wayca_sc_threadpool_running_num: %d", running_task_num);
			ret = AGF;
			goto free_resources_multiple;
		}
		LOG(NTC, "Notice: running_task_num:%d", running_task_num);

		while (1) {
			while (wayca_sc_threadpool_running_num(threadpool) != 0)
				usleep(WAIT_US);
			ok_cnt = 0;
			for (i = 0; i < thread_num; i++) {
				if (raw_data[i].result != INIT_ERR_CODE) {
					ok_cnt++;
				}
			}
			if (ok_cnt == thread_num)
				break;
		}
		ret = 0;
		return ret;
	} else {
		// 提交线程池任务
		for (i = 0; i < thread_num; i++) {
			memset(&raw_data[i], 0, sizeof(struct sm2_raw_data));
			raw_data[i].in_size = data->input_size;
			raw_data[i].id_size = data->id_size;
			raw_data[i].out_size = data->output_size;
			raw_data[i].thread_num = data->thread_num;
			raw_data[i].check_type = data->check_type;
			raw_data[i].async = data->async;
			raw_data[i].count = data->count;
			raw_data[i].loop_time = data->loop_time;
			raw_data[i].result = INIT_ERR_CODE;
			ret = wayca_sc_threadpool_queue(threadpool, (void *)hisi_sm2_data_process, (void *)&raw_data[i]);
			if (ret) {
				LOG(ERR, "Failed to wayca_sc_threadpool_queue:%d, ret_code:%d.", i, ret);
				ret = AGF;
				goto free_resources_multiple;
			}
		}
		wait_task_num = wayca_sc_threadpool_task_num(threadpool);
		if (wait_task_num < 0) {
			LOG(ERR, "Failed to check wayca_sc_threadpool_task_num: %d", wait_task_num);
			ret = AGF;
			goto free_resources_multiple;
		}
		LOG(NTC, "Notice: wait_task_num:%d", wait_task_num);
		running_task_num = wayca_sc_threadpool_running_num(threadpool);
		if (running_task_num < 0) {
			LOG(ERR, "Failed to check wayca_sc_threadpool_running_num: %d", running_task_num);
			ret = AGF;
			goto free_resources_multiple;
		}
		LOG(NTC, "Notice: running_task_num:%d", running_task_num);

		while (1) {
			while (wayca_sc_threadpool_running_num(threadpool) != 0)
				usleep(WAIT_US);
			ok_cnt = 0;
			for (i = 0; i < thread_num; i++) {
				if (raw_data[i].result != INIT_ERR_CODE) {
					ok_cnt++;
				}
			}
			if (ok_cnt == thread_num)
				break;
		}

		// collect each thread result
		for (i = 0; i < thread_num; i++) {
			if (raw_data[i].result) {
				LOG(ERR, "Failed to do sm2, result: %d.", raw_data[i].result);
				ret = DOF;
				goto free_resources_multiple;
			}
			success_thread_num++;
		}
		LOG(NTC, "Notice: There's a total of %d thread run, %d thread run success!\n", thread_num, success_thread_num);
	}
	ret = 0;
free_resources:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (key)
		EC_KEY_free(key);
free_resources_multiple:
	// 销毁线程池
	ret = wayca_sc_threadpool_destroy(threadpool);
	if (ret) {
		LOG(ERR, "Failed to wayca_sc_threadpool_destroy, ret_code:%d.", ret);
		return -EINVAL;
	}
	return ret;
}

static int uadk_sm2_thread_setup(struct sm2_setup_data *data)
{
	int success_thread_num = 0;
	int ret = AGF;
	int i = 0;
	struct sm2_key_data key_data;
	// register uadk engine;
	ret = sm2_engine_register();
	if (ret)
		return ret;

	for (i = 0; i < KP_ARRAY_SIZE(get_evps); i++) {
		if (!strcmp(hash_alg, get_evps[i].alg_name)) {
			type = get_evps[i].method();
			break;
		}
	}

	memset(&key_data, 0, sizeof(struct sm2_key_data));
	key_data.mode = mode;
	key_data.async = data->async;
	key_data.key = NULL;
	key = get_ec_key(&key_data);
	if (!key)
		return DOF;
	if (mode == GENKEY) {
		if (data->thread_num == 0) {
			// test generate key. if single process, key is test ok.
			LOG(INF, "Info: do sm2 generate key success.\n");
			if (key)
				EC_KEY_free(key);
			return 0;
		} else {
			// test generate key, if multiple process, use other param to test.
			struct sm2_key_data test_key_data[data->thread_num];
			pthread_t thread_process[data->thread_num];
			for (i = 0; i < data->thread_num; i++) {
				memset(&test_key_data[i], 0, sizeof(struct sm2_key_data));
				test_key_data[i].mode = mode;
				test_key_data[i].async = data->async;
				test_key_data[i].key = NULL;
				ret = pthread_create(&thread_process[i], NULL, (void *)get_ec_key, (void *)&test_key_data[i]);
				if (ret) {
					LOG(ERR, "Error: create thread[%d] failed, ret = %d \n", i, ret);
					ret = THF;
					goto free_ec_key;
				}
			}
			for (i = 0; i < data->thread_num; i++) {
				ret = pthread_join(thread_process[i], NULL);
				if (ret) {
					LOG(ERR, "Error: join thread[%d] failed, ret = %d \n", i, ret);
					ret = THF;
					goto free_ec_key;
				}
			}
			// check result
			for (i = 0; i < data->thread_num; i++) {
				if (!test_key_data[i].key) {
					LOG(ERR, "Error: thread %d generate key failed. \n", i);
					ret = DOF;
					goto free_ec_key;
				}
				success_thread_num++;
			}
			LOG(NTC, "Notice: There's a total of %d thread run, %d thread run success!\n",
				data->thread_num, success_thread_num);
			ret = 0;
			LOG(INF, "Info: do sm2 generate key multiple threads success. \n");
free_ec_key:
			for (i = 0; i < data->thread_num; i++) {
				if (test_key_data[i].key)
					EC_KEY_free(test_key_data[i].key);
			}
			if (key)
				EC_KEY_free(key);
			return ret;
		}
	}

	pkey = get_evp_pkey();
	if (pkey == NULL) {
		LOG(ERR, "Error: failed to generate EVP_PKEY \n");
		ret = DOF;
		goto free_resources;
	}
	ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
	if (ret != 1) {
		LOG(ERR, "Error: set alias type to EVP_PKEY_SM2 failed \n");
		ret = DOF;
		goto free_resources;
	}

	if (data->thread_num == 0) {
		struct sm2_raw_data raw_data;

		memset(&raw_data, 0, sizeof(struct sm2_raw_data));
		raw_data.in_size = data->input_size;
		raw_data.id_size = data->id_size;
		raw_data.out_size = data->output_size;
		raw_data.thread_num = data->thread_num;
		raw_data.check_type = data->check_type;
		raw_data.async = data->async;
		raw_data.count = data->count;
		raw_data.loop_time = data->loop_time;
		raw_data.result = INIT_ERR_CODE;
		ret = hisi_sm2_data_process(&raw_data);
		if (raw_data.result) {
			ret = DOF;
			goto free_resources_single;
		}
free_resources_single:
		if (raw_data.input)
			free(raw_data.input);
		if (raw_data.id)
			free(raw_data.id);
	} else {
		struct sm2_raw_data raw_data[data->thread_num];
		pthread_t thread_process[data->thread_num];

		for (i = 0; i < data->thread_num; i++) {
			memset(&raw_data[i], 0, sizeof(struct sm2_raw_data));
			raw_data[i].in_size = data->input_size;
			raw_data[i].id_size = data->id_size;
			raw_data[i].out_size = data->output_size;
			raw_data[i].thread_num = data->thread_num;
			raw_data[i].check_type = data->check_type;
			raw_data[i].async = data->async;
			raw_data[i].count = data->count;
			raw_data[i].loop_time = data->loop_time;
			raw_data[i].result = INIT_ERR_CODE;
			ret = pthread_create(&thread_process[i], NULL, (void *)hisi_sm2_data_process, (void *)&raw_data[i]);
			if (ret) {
				LOG(ERR, "Error: create thread[%d] failed, ret = %d \n", i, ret);
				ret = THF;
				goto free_resources_multiple;
			}
		}
		for (i = 0; i < data->thread_num; i++) {
			ret = pthread_join(thread_process[i], NULL);
			if (ret) {
				LOG(ERR, "Error: join thread[%d] failed, ret = %d \n", i, ret);
				ret = THF;
				goto free_resources_multiple;
			}
		}
		// check thread result
		for (i = 0; i < data->thread_num; i++) {
			if (raw_data[i].result) {
				LOG(ERR, "Error: thread %d result is failed. \n", i);
				ret = DOF;
				goto free_resources_multiple;
			}
			success_thread_num++;
		}
		LOG(NTC, "Notice: There's a total of %d thread run, %d thread run success!\n",
			data->thread_num, success_thread_num);
free_resources_multiple:
		for (i = 0; i < data->thread_num; i++) {
			if (raw_data[i].input)
				free(raw_data[i].input);
			if (raw_data[i].id)
				free(raw_data[i].id);
		}
	}
free_resources:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (key)
		EC_KEY_free(key);
	return ret;
}

int uadk_sm2_func(void *param)
{
	int ret = AGF;
	struct uadk_common_param *g_uadk_param = (struct uadk_common_param *)param;
	size_t input_size = 0, id_size = 0, output_size = 0;
	struct sm2_setup_data setup_data;

	if (sscanf(g_uadk_param->comm_param.alg_mode, "%[^-]-%[^-]-%s", mode_name, hash_alg, id_need) > SM2_MODE_SIZE) {
		LOG(ERR, "Error: uadk sm2 alg_mode format invalid \n");
		return AGF;
	}
	if (g_uadk_param->comm_param.src_mode == SRC_RANDOM || g_uadk_param->comm_param.src_mode == SRC_OPENSSL) {
		if (sscanf(g_uadk_param->comm_param.alg_key_size, "%ld-%ld-%ld", &input_size, &id_size, &output_size)
			!= SM2_KEY_SIZE) {
			LOG(ERR, "Error: uadk sm2 alg_size format invalid \n");
			return AGF;
		}
	} else if (g_uadk_param->comm_param.src_mode == SRC_FILE) {
		LOG(ERR, "Error: file mode developing...\n");
		return AGF;
	}

	if (strcmp(mode_name, "sign") == 0)
		mode = SIGN;
	else if (strcmp(mode_name, "verify") == 0)
		mode = VERIFY;
	else if (strcmp(mode_name, "encrypt") == 0)
		mode = ENCRYPT;
	else if (strcmp(mode_name, "decrypt") == 0)
		mode = DECRYPT;
	else if (strcmp(mode_name, "genkey") == 0)
		mode = GENKEY;
	else {
		LOG(ERR, "Error: uadk sm2 mode invalid \n");
		return AGF;
	}

	LOG(NTC, "Notice: src_mode:%s.\n", uadk_src_type(g_uadk_param->comm_param.src_mode));
	LOG(NTC, "Notice: mode_name:%s, hash_alg:%s, id_need:%s.\n", mode_name, hash_alg, id_need);
	LOG(NTC, "Notice: input_size:%ld, id_size:%ld, output_size:%ld.\n", input_size, id_size, output_size);

	setup_data.input_size = input_size;
	if (strcmp(id_need, "no_id") != 0)
		setup_data.id_size = id_size;
	else
		setup_data.id_size = 0;
	setup_data.output_size = output_size;
	setup_data.thread_num = g_uadk_param->comm_param.thread_num;
	setup_data.src_mode = g_uadk_param->comm_param.src_mode;
	setup_data.check_type = g_uadk_param->comm_param.check_type;
	setup_data.async = g_uadk_param->comm_param.async;
	setup_data.perf_flag = g_uadk_param->comm_param.perf_flag;
	setup_data.count = g_uadk_param->comm_param.count;
	setup_data.loop_time = g_uadk_param->comm_param.loop;

	if (setup_data.thread_num > MAX_THREAD_CHANGE_NUM) {
		ret = uadk_sm2_pool_setup(&setup_data);
	} else {
		ret = uadk_sm2_thread_setup(&setup_data);
	}
	return ret;
}
