#include <errno.h>
#include <dirent.h>
#include "acc_utils.h"
#include "wd_comp.h"
#include "acc.h"
#include "wd_util.h"

#define SYS_DEBUG_HIZIP_DIR	"/sys/kernel/debug/hisi_zip"
#define QM_STATE_RELATIVE_PATH "qm/qm_state"
#define ZIP_QM_REG_PATH_FORMAT SYS_DEBUG_HIZIP_DIR"/%s/"QM_STATE_RELATIVE_PATH
#define LINUX_CRTDIR_SIZE 1
#define LINUX_PRTDIR_SIZE 2
#define PF_NAME_SUFFIX "00.0"
#define ZIP_STATUS_RANGE 69

static int g_zip_status_trans_tb[ZIP_STATUS_RANGE] = {
    0, 1, 2, 3, ACC_INVALID_PARAM, ACC_INVALID_PARAM,
    ACC_ZIP_SRC_DIF_ERR, ACC_ZIP_DST_DIF_ERR, ACC_ZIP_NEGTIVE_COMP_ERR, 9, 10,
    11, 12, 13, 14, 15,
    16, 17, 18, 19, 20,
    21, 22, 23, 24, 25,
    26, 27, 28, 29, 30,
    31, 32, 33, 34, 35,
    36, 37, 38, 39, 40,
    41, 42, 43, 44, 45,
    46, 47, 48, 49, 50,
    51, 52, 53, 54, 55,
    56, 57, 58, 59, 60,
    61, ACC_RETRY, 63, 64, 65,
    66, ACC_INVALID_PARAM, 68
};

static int acc_zip_transform_status(int status)
{
    if (status < 0 || status >= ZIP_STATUS_RANGE)
        return status;
    return g_zip_status_trans_tb[status];
}

static int zip_io_sync(struct acc_ctx *ctx, void *ctrl,
        void *dst, size_t *dst_len, void *src, size_t src_len)
{
    int ret;
    int status;
    struct wcrypto_comp_op_data opdata;
    struct acc_inner *inner;

    if (!ctx || !ctrl || !dst || !src ||
        !dst_len || !src_len) {
        return ACC_INVALID_PARAM;
    }

    memset(&opdata, 0, sizeof(opdata));
    inner = ctx->inner;
    if (!inner || !inner->q) {
        WD_ERR("inner or queue is null.\n");
        return ACC_INVALID_PARAM;
    }
    opdata.in = (__u8*)src;
    opdata.out = (__u8*)dst;
    opdata.in_len = src_len;
    opdata.avail_out = *dst_len;
    opdata.priv = ctrl;

    ret = wcrypto_do_comp(inner->wd_ctx, &opdata, NULL);
    if (ret)
        return acc_transform_err_code(ret);

    *dst_len = opdata.produced;
    status = acc_zip_transform_status(opdata.status);
    return status >= 0 ? ACC_SUCCESS : status;
}

static int zip_io_asyn(struct acc_ctx *ctx, void *ctrl,
        void *dst, size_t dst_len, const void *src, size_t src_len)
{
    int ret;
    struct wcrypto_comp_op_data opdata;
    struct acc_inner *inner;

    if (!ctx || !ctrl || !dst || !src ||
        !dst_len || !src_len) {
        return ACC_INVALID_PARAM;
    }

    inner = ctx->inner;
    if (!inner || !inner->q) {
        WD_ERR("inner or queue is null.\n");
        return ACC_INVALID_PARAM;
    }

    memset(&opdata, 0, sizeof(opdata));
    opdata.in = (__u8*)src;
    opdata.out = (__u8*)dst;
    opdata.in_len = src_len;
    opdata.avail_out = dst_len;
    opdata.priv = ctrl;

    ret = wcrypto_do_comp(inner->wd_ctx, &opdata, ctx);
    if (ret == WD_SUCCESS)
        __sync_add_and_fetch(&inner->ref_cnt, 1);

    return acc_transform_err_code(ret);
}

void *zip_alloc_buf(void *pool, size_t sz)
{
    return NULL;
}

void zip_free_buf(void *pool, void *pbuf)
{
    return;
}

void *zip_wd_dma_map(void *usr, void *va, size_t sz)
{
    return va;
}

void zip_wd_dma_unmap(void *usr, void *va, void *dma, size_t sz)
{
    return;
}

void acc_zip_callback(const void *msg, void *tag)
{
    struct wcrypto_comp_msg *respmsg = (struct wcrypto_comp_msg *)msg;
    struct wcrypto_comp_tag *wtag = (void *)(uintptr_t)respmsg->udata;
    struct acc_ctx *ctx = tag;
    struct acc_inner *inner = ctx->inner;
    int status;

    dbg("[%s], ctx_id =%d comsume=%d, produce=%d\n", __func__,
    	respmsg->tag, respmsg->in_cons, respmsg->produced);

    status = acc_zip_transform_status(respmsg->status);

    ctx->cb(ctx, wtag->priv, status, respmsg->produced);
    __sync_sub_and_fetch(&inner->ref_cnt, 1);
}

static int acc_zip_init_param_check(struct acc_ctx *ctx)
{
    if (!ctx) {
        WD_ERR("ctx error.\n");
        return ACC_INVALID_PARAM;
    }

    if (ctx->alg_type < ACC_ALG_ZLIB || ctx->alg_type > ACC_ALG_GZIP) {
        WD_ERR("alg_type error.  alg_type:%d\n", ctx->alg_type);
        return ACC_INVALID_PARAM;
    }

    if (ctx->op_type < WCRYPTO_DEFLATE || ctx->op_type > WCRYPTO_INFLATE) {
        WD_ERR("op_type error. op_type:%d\n", ctx->op_type);
        return ACC_INVALID_PARAM;
    }

    return ACC_SUCCESS;
}

static void acc_zip_init_fill_param(struct acc_ctx *ctx, struct wd_queue *q,
    struct wcrypto_comp_ctx_setup *ctx_setup)
{
    struct wcrypto_paras *priv;

    if (ctx->alg_type == ACC_ALG_GZIP) {
        ctx_setup->alg_type = WCRYPTO_GZIP;
        q->capa.alg = "gzip";
    } else {
        ctx_setup->alg_type = WCRYPTO_ZLIB;
        q->capa.alg = "zlib";
    }

    ctx_setup->stream_mode = WCRYPTO_COMP_STATELESS;
    ctx_setup->br.alloc = (void *)zip_alloc_buf;
    ctx_setup->br.free = (void *)zip_free_buf;
    ctx_setup->br.iova_map = zip_wd_dma_map;
    ctx_setup->br.iova_unmap = zip_wd_dma_unmap;
    ctx_setup->cb = acc_zip_callback;
    q->capa.latency = 0;
    q->capa.throughput = 0;
    priv = &q->capa.priv;
    priv->direction = ctx->op_type;
}

int acc_zip_init(struct acc_ctx *ctx)
{
    struct wcrypto_comp_ctx_setup ctx_setup;
    struct acc_inner *inner;
    struct wd_queue *q;
    void *zctx;
    int ret;

    ret = acc_zip_init_param_check(ctx);
    if (ret)
        return ret;

    inner = calloc(1, sizeof(struct acc_inner));
    if (!inner) {
        ret = -ENOMEM;
        WD_ERR("alloc inner fail, ret =%d\n", ret);
        return ret;
    }

    q = calloc(1, sizeof(struct wd_queue));
    if (!q) {
        ret = -ENOMEM;
        WD_ERR("alloc q fail, ret =%d\n", ret);
        goto release_inner;
    }

    memset(&ctx_setup, 0, sizeof(ctx_setup));
    acc_zip_init_fill_param(ctx, q, &ctx_setup);

    ret = wd_request_queue(q);
    if (ret) {
        WD_ERR("wd_request_queue fail, ret =%d\n", ret);
        goto hw_q_free;
    }

    zctx = wcrypto_create_comp_ctx(q, &ctx_setup);
    if (zctx == NULL) {
        WD_ERR("wd_create_comp_ctx fail, ret =%d\n", ret);
        goto release_q;
    }

    inner->wd_ctx = zctx;
    inner->q = q;

    ctx->inner = inner;
    return ACC_SUCCESS;

release_q:
    wd_release_queue(q);
hw_q_free:
    free(q);
release_inner:
    free(inner);

    return acc_transform_err_code(ret);
}

int acc_zip_clear(struct acc_ctx *ctx)
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

    wcrypto_del_comp_ctx(inner->wd_ctx);
    wd_release_queue(inner->q);
    free(inner->q);
    free(inner);
    ctx->inner = NULL;

    return ACC_SUCCESS;
}

/**
 *
 * @brief compress data synchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] dst is the destination address.
 * @param [in] dst_len is the destination total length.
 * @param [in] src is the source address.
 * @param [in] src_len is the source total length.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_compress(struct acc_ctx *ctx, void *ctrl,
        void *dst, size_t *dst_len, void *src, size_t src_len)
{
    return zip_io_sync(ctx, ctrl, dst, dst_len, src, src_len);
}

/**
 *
 * @brief decompress data synchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] dst is the destination address.
 * @param [in] dst_len is the destination total length.
 * @param [in] src is the source address.
 * @param [in] src_len is the source total length.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_decompress(struct acc_ctx *ctx, void *ctrl,
        void *dst, size_t *dst_len, void *src, size_t src_len)
{
    return zip_io_sync(ctx, ctrl, dst, dst_len, src, src_len);
}

/**
 *
 * @brief compress data asynchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] dst is the destination address.
 * @param [in] dst_len is the destination total length.
 * @param [in] src is the source address.
 * @param [in] src_len is the source total length.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * 需要配合acc_poll()接口进行回调.
 *
 */
int acc_compress_asyn(struct acc_ctx *ctx, void *ctrl,
        void *dst, size_t dst_len, const void *src, size_t src_len)
{
    return zip_io_asyn(ctx, ctrl, dst, dst_len, src, src_len);
}

/**
 *
 * @brief compress data asynchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] dst is the destination address.
 * @param [in] dst_len is the destination total length.
 * @param [in] src is the source address.
 * @param [in] src_len is the source total length.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * 需要配合acc_poll()接口进行回调.
 *
 */
int acc_decompress_asyn(struct acc_ctx *ctx, void *ctrl,
        void *dst, size_t dst_len, const void *src, size_t src_len)
{
    return zip_io_asyn(ctx, ctrl, dst, dst_len, src, src_len);
}

int acc_zip_poll(struct acc_ctx *ctx, int num, int* remainder)
{
    int ret;
    struct acc_inner *inner;

    if (!ctx) {
        WD_ERR("ctx is null.\n");
        return ACC_INVALID_PARAM;
    }

    inner = ctx->inner;
    if (!inner || !inner->q) {
        WD_ERR("inner or queue is null.\n");
        return ACC_INVALID_PARAM;
    }

    ret = wcrypto_comp_poll(inner->q, num);
    if (remainder)
        *remainder = inner->ref_cnt;

    if (ret == -WD_HW_EACCESS && inner->ref_cnt == 0)
        return ACC_FATAL_INSTANCE;
    else
        return acc_transform_err_code(ret);
}

static int acc_zip_read_dev_idle_state(char *name, int *state)
{
    char attr_file[PATH_STR_SIZE], buf[MAX_ATTR_STR_SIZE];
    int size, fd;

    size = snprintf(attr_file, PATH_STR_SIZE, "%s/%s/%s",
        SYS_DEBUG_HIZIP_DIR, name, QM_STATE_RELATIVE_PATH);
    if (size < 0) {
        ACC_LOG("get %s/%s path fail!\n", name, QM_STATE_RELATIVE_PATH);
        return ACC_UNSUPPORTED;
    }

    fd = open(attr_file, O_RDONLY, 0);
    if (fd < 0) {
        ACC_LOG("open %s fail!\n", attr_file);
        return ACC_UNSUPPORTED;
    }

    size = read(fd, buf, MAX_ATTR_STR_SIZE);
    if (size <= 0) {
        ACC_LOG("read nothing at %s!\n", attr_file);
        close(fd);
        return ACC_UNSUPPORTED;
    }

    close(fd);
    *state = atoi((char *)&buf);

    return ACC_SUCCESS;
}

int acc_zip_get_dev_idle_state(int *state)
{
    char *name;
    struct dirent *device = NULL;
    DIR *sys_dbg_dir = NULL;
    int ret;

    sys_dbg_dir = opendir(SYS_DEBUG_HIZIP_DIR);
    if (!sys_dbg_dir) {
        WD_ERR("debugfs is not enabled on the system!\n");
        return ACC_UNSUPPORTED;
    }

    while (true) {
        device = readdir(sys_dbg_dir);
        if (!device)
            break;

        name = device->d_name;
        if (!strncmp(name, ".", LINUX_CRTDIR_SIZE) ||
            !strncmp(name, "..", LINUX_PRTDIR_SIZE))
            continue;

        if (strstr(name, PF_NAME_SUFFIX) == NULL)
            continue;

        ret = acc_zip_read_dev_idle_state(name, state);
        if (ret)
            goto err_with_dev;
        if (*state == 0)
            break;
    }

    closedir(sys_dbg_dir);

    return ACC_SUCCESS;

err_with_dev:
    if (sys_dbg_dir)
        closedir(sys_dbg_dir);

    return ACC_UNSUPPORTED;
}
