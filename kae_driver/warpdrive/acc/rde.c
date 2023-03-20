#include "rde.h"

void *ec_alloc(void *usr, size_t size)
{
	return wd_alloc_blk(usr);
}

void ec_free(void *usr, void *va)
{
	wd_free_blk(usr, va);
}

void *ec_map(void *usr, void *va, size_t sz)
{
	return wd_blk_iova_map(usr, va);
}

void ec_unmap(void *usr, void *va, void *dma, size_t sz)
{
	wd_blk_iova_unmap(usr, dma, va);
}

void acc_rde_callback(const void *msg, void *tag)
{
	struct wcrypto_ec_msg *resp_msg = (struct wcrypto_ec_msg *)msg;
	struct wcrypto_ec_tag *wtag =
			(void *)(uintptr_t)resp_msg->usr_data;
	struct acc_ctx *ctx = tag;
	struct acc_inner *inner = ctx->inner;
	int status;

	switch (resp_msg->result) {
	case WD_HW_EACCESS:
		status = ACC_RETRY;
		break;
	case WCRYPTO_EC_DIF_CHK_ERR:
		status = ACC_RDE_DIF_ERR;
		break;
	case WCRYPTO_EC_DATA_VERIFY_ERR:
		status = ACC_RDE_DISK_VERIFY_ERR;
		break;
	case WCRYPTO_EC_IN_EPARA:
		status = ACC_INVALID_PARAM;
		break;
	default:
		status = resp_msg->result;
		break;
	}

	ctx->cb(ctx, wtag->priv, status, 0);
	__sync_sub_and_fetch(&inner->ref_cnt, 1);
}

static void *ec_pool_setup(struct wd_queue *q, struct wd_blkpool_setup *setup)
{
	memset(setup, 0, sizeof(struct wd_blkpool_setup));
	setup->block_size = WCRYPTO_EC_TBl_SIZE * WCRYPTO_EC_CTX_MSG_NUM;
	setup->block_num = RDE_POOL_BLK_NUM;
	setup->align_size = RDE_POOL_ALIGN_SIZE;

	return wd_blkpool_create(q, setup);
}

static int ec_ctx_setup(struct wcrypto_ec_ctx_setup *ctx_setup,
	struct acc_ctx *ctx, void *pool)
{
	memset(ctx_setup, 0, sizeof(struct wcrypto_ec_ctx_setup));

	ctx_setup->data_fmt = ACC_BUF_TYPE_SGL;
	if (ctx->alg_type == ACC_ALG_FLEXEC)
		ctx_setup->ec_type = WCRYPTO_EC_FLEXEC;
	else if (ctx->alg_type == ACC_ALG_MPCC)
		ctx_setup->ec_type = WCRYPTO_EC_MPCC;
	else {
		WD_ERR("invalid alg type.\n");
		return ACC_INVALID_PARAM;
	}
	ctx_setup->cb = acc_rde_callback;
	ctx_setup->br.alloc = ec_alloc;
	ctx_setup->br.free = ec_free;
	ctx_setup->br.iova_map = ec_map;
	ctx_setup->br.iova_unmap = ec_unmap;
	ctx_setup->br.usr = pool;

	return ACC_SUCCESS;
}

int acc_rde_init(struct acc_ctx *ctx)
{
	struct wcrypto_ec_ctx_setup ctx_setup;
	struct wd_blkpool_setup pool_setup;
	struct acc_inner *inner;
	struct wd_queue *q;
	void *pool;
	void *rctx;
	int ret;

	if (!ctx) {
		WD_ERR("ctx error.\n");
		return ACC_INVALID_PARAM;
	}

	inner = calloc(1, sizeof(struct acc_inner));
	if (!inner) {
		ret = -ENOMEM;
		WD_ERR("alloc inner fail, ret = %d.\n", ret);
		return ret;
	}

	q = calloc(1, sizeof(struct wd_queue));
	if (!q) {
		ret = -ENOMEM;
		WD_ERR("alloc q fail, ret = %d.\n", ret);
		goto free_inner;
	}

	q->capa.alg = "ec";
	q->capa.latency = 0;
	q->capa.throughput = 0;
	ret = wd_request_queue(q);
	if (ret) {
		WD_ERR("request q fail, ret = %d.\n", ret);
		goto free_q;
	}

	pool = ec_pool_setup(q, &pool_setup);
	if (pool == NULL) {
		ret = -ENOMEM;
		WD_ERR(" create blkpool fail, ret = %d.\n", ret);
		goto release_q;
	}

	ret = ec_ctx_setup(&ctx_setup, ctx, pool);
	if (ret)
		goto release_blkpool;

	rctx = wcrypto_create_ec_ctx(q, &ctx_setup);
	if (rctx == NULL) {
		WD_ERR(" create ec_ctx fail.\n");
		goto release_blkpool;
	}

	inner->wd_ctx = rctx;
	inner->q = q;
	inner->pool = pool;
	ctx->inner = (void *)inner;

	return ACC_SUCCESS;

release_blkpool:
	wd_blkpool_destroy(pool);
release_q:
	wd_release_queue(q);
free_q:
	free(q);
free_inner:
	free(inner);

	return acc_transform_err_code(ret);
}

int acc_rde_clear(struct acc_ctx *ctx)
{
	struct acc_inner *inner;

	if (!ctx) {
		WD_ERR("ctx error.\n");
		return ACC_INVALID_PARAM;
	}

	inner = ctx->inner;
	if (!inner) {
		WD_ERR("inner error.\n");
		return ACC_INVALID_PARAM;
	}

	wcrypto_del_ec_ctx(inner->wd_ctx);
	wd_blkpool_destroy(inner->pool);
	wd_release_queue(inner->q);
	free(inner->q);
	free(inner);
	ctx->inner = NULL;

	return ACC_SUCCESS;
}

int acc_rde_poll(struct acc_ctx *ctx, int num, int *reminder)
{
	int ret;
	struct acc_inner *inner;

	if (!ctx) {
		WD_ERR("ctx is null.\n");
		return ACC_INVALID_PARAM;
	}

	inner = ctx->inner;
	if (!inner) {
		WD_ERR("inner is null.\n");
		return ACC_INVALID_PARAM;
	}

	ret = wcrypto_ec_poll(inner->q, num);
	if (ret == -WD_HW_EACCESS && inner->ref_cnt == 0)
		ret = ACC_FATAL_INSTANCE;
	else if (ret == -WD_HW_EACCESS && inner->ref_cnt > 0)
		ret = ACC_FATAL_ENGINE;

	if (reminder)
		*reminder = inner->ref_cnt;

	return acc_transform_err_code(ret);
}

static int ec_op_data_setup(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	struct wcrypto_ec_op_data *opdata, uint8_t op_type)
{
	if (!ctx || !ctrl) {
		WD_ERR("ctx or ctrl is null.\n");
		return ACC_INVALID_PARAM;
	}

	memset(opdata, 0, sizeof(struct wcrypto_ec_op_data));
	opdata->in = ctrl->src_data;
	opdata->out = ctrl->dst_data;
	opdata->coef_matrix = ctrl->coe_matrix;
	opdata->alg_blk_size = ctrl->alg_blk_size;
	opdata->block_num = ctrl->input_block;
	opdata->block_size = ctrl->block_size;
	opdata->coef_matrix_len = ctrl->cm_len;
	opdata->coef_matrix_load = ctrl->cm_load;
	opdata->in_disk_num = ctrl->src_num;
	opdata->out_disk_num = ctrl->dst_num;
	opdata->op_type = op_type;
	opdata->priv = (void *)ctrl;

	return ACC_SUCCESS;
}

/**
 *
 * @brief flexec/raid5/raid6 operation synchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Multiple concurrent processing is not supported for the same instance.
 */
int acc_do_flexec(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	int ret;
	struct wcrypto_ec_op_data opdata;
	struct acc_inner *inner;

	ret = ec_op_data_setup(ctx, ctrl, &opdata, op_type);
	if (ret)
		return ret;

	inner = ctx->inner;
	if (!inner) {
		WD_ERR("inner is null.\n");
		return ACC_INVALID_PARAM;
	}

	ret = wcrypto_do_ec(inner->wd_ctx, &opdata, NULL);
	if (!ret && opdata.status) {
		if (opdata.status == WCRYPTO_EC_DIF_CHK_ERR)
			ret = ACC_RDE_DIF_ERR;
		else if (opdata.status == WCRYPTO_EC_DATA_VERIFY_ERR)
			ret = ACC_RDE_DISK_VERIFY_ERR;
		else if (opdata.status == WCRYPTO_EC_IN_EPARA)
			ret = ACC_INVALID_PARAM;
	}

	return acc_transform_err_code(ret);
}

/**
 *
 * @brief flexec/raid5/raid6 operation asynchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Multiple concurrent processing is not supported for the same instance.
 * User should hold on ctrl until callback
 */
int acc_do_flexec_asyn(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	int ret;
	struct wcrypto_ec_op_data opdata;
	struct acc_inner *inner;

	ret = ec_op_data_setup(ctx, ctrl, &opdata, op_type);
	if (ret)
		return ret;

	inner = ctx->inner;
	if (!inner) {
		WD_ERR("inner is null.\n");
		return ACC_INVALID_PARAM;
	}

	ret = wcrypto_do_ec(inner->wd_ctx, &opdata, ctx);
	if (ret == WD_SUCCESS)
		__sync_add_and_fetch(&inner->ref_cnt, 1);

	return acc_transform_err_code(ret);
}

/**
 *
 * @brief mpcc operation synchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Multiple concurrent processing is not supported for the same instance.
 */
int acc_do_mpcc(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	int ret;
	struct wcrypto_ec_op_data opdata;
	struct acc_inner *inner;

	ret = ec_op_data_setup(ctx, ctrl, &opdata, op_type);
	if (ret)
		return ret;

	inner = ctx->inner;
	if (!inner) {
		WD_ERR("inner is null.\n");
		return ACC_INVALID_PARAM;
	}

	ret = wcrypto_do_ec(inner->wd_ctx, &opdata, NULL);
	if (!ret && opdata.status) {
		if (opdata.status == WCRYPTO_EC_DIF_CHK_ERR)
			ret = ACC_RDE_DIF_ERR;
		else if (opdata.status == WCRYPTO_EC_DATA_VERIFY_ERR)
			ret = ACC_RDE_DISK_VERIFY_ERR;
		else if (opdata.status == WCRYPTO_EC_IN_EPARA)
			ret = ACC_INVALID_PARAM;
	}

	return acc_transform_err_code(ret);
}

/**
 *
 * @brief mpcc operation asynchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] ctrl is the parameter data of current io.
 * @param [in] op_type is from ACC_OPT_RAID_E
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Multiple concurrent processing is not supported for the same instance.
 * User should hold on ctrl until callback
 */
int acc_do_mpcc_asyn(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	int ret;
	struct wcrypto_ec_op_data opdata;
	struct acc_inner *inner;

	ret = ec_op_data_setup(ctx, ctrl, &opdata, op_type);
	if (ret)
		return ret;

	inner = ctx->inner;
	if (!inner) {
		WD_ERR("inner is null.\n");
		return ACC_INVALID_PARAM;
	}

	ret = wcrypto_do_ec(inner->wd_ctx, &opdata, ctx);
	if (ret == WD_SUCCESS)
		__sync_add_and_fetch(&inner->ref_cnt, 1);

	return acc_transform_err_code(ret);
}

