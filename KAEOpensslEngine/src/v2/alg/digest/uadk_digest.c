/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2020-2022 Linaro ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <uadk/wd_cipher.h>
#include <uadk/wd_digest.h>
#include <uadk/wd_sched.h>
#include "v2/uadk.h"
#include "v2/async/uadk_async.h"
#include "v2/utils/uadk_utils.h"
#include "utils/engine_log.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#ifndef EVP_MD_CTX_md_data(ctx)
#define EVP_MD_CTX_md_data(ctx) EVP_MD_CTX_get0_md_data(ctx)
#endif
#endif
#define UADK_DO_SOFT (-0xE0)
#define CTX_SYNC 0
#define CTX_ASYNC 1
#define CTX_NUM 2
#define ENV_ENABLED 1

/* The max BD data length is 16M-512B */
#define BUF_LEN      0xFFFE00

#define SM3_DIGEST_LENGTH	32
#define SHA1_CBLOCK		64
#define SHA224_CBLOCK		64
#define SHA384_CBLOCK		128
#define SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)
#define MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (8 * 1024)
#define SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)
#define MAX_DIGEST_LENGTH	64
#define DIGEST_BLOCK_SIZE (512 * 1024)

/* copied form openssl/include/internal/sm3.h
 * OpenSSL 3.0 has no <openssl/sm3.h>
 */
# define SM3_DIGEST_LENGTH 32
# define SM3_WORD unsigned int
# define SM3_CBLOCK      64
# define SM3_LBLOCK      (SM3_CBLOCK/4)

typedef struct SM3state_st {
    SM3_WORD A, B, C, D, E, F, G, H;
    SM3_WORD Nl, Nh;
    SM3_WORD data[SM3_LBLOCK];
    unsigned int num;
} SM3_CTX;

enum sec_digestz_state {
	SEC_DIGEST_INIT,
	SEC_DIGEST_FIRST_UPDATING,
	SEC_DIGEST_DOING,
	SEC_DIGEST_FINAL
};

struct digest_threshold_table {
    int nid;
    int threshold;
};

struct digest_engine {
    struct wd_ctx_config ctx_cfg;
    struct wd_sched sched;
    int numa_id;
    int pid;
    pthread_spinlock_t lock;
};

static struct digest_engine g_digest_engine;

#if OPENSSL_VERSION_NUMBER < 0x30000000
struct evp_md_ctx_st {
    const EVP_MD *digest;
    /* Functional reference if 'digest' is ENGINE-provided */
    ENGINE *engine;
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count);
};
#else
struct evp_md_ctx_st {
	const EVP_MD *reqdigest;    /* The original requested digest */
    const EVP_MD *digest;
	ENGINE *engine;             /* functional reference if 'digest' is
				     * ENGINE-provided
				     */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count);

    /*
	 * Opaque ctx returned from a providers digest algorithm implementation
	 * OSSL_FUNC_digest_newctx()
	 */
    void *algctx;
    EVP_MD *fetched_digest;
} /* EVP_MD_CTX */;
#endif

struct digest_priv_ctx {
    handle_t sess;
    struct wd_digest_sess_setup setup;
    struct wd_digest_req req;
    unsigned char *data;
    unsigned char out[MAX_DIGEST_LENGTH];
    EVP_MD_CTX *soft_ctx;
    const EVP_MD *soft_md;
    size_t last_update_bufflen;
    uint32_t e_nid;
    uint32_t state;
    uint32_t switch_threshold;
    int switch_flag;
    uint32_t app_datasize;
    bool is_stream_copy;
    size_t total_data_len;
    struct sched_params sched_param;
};

struct digest_info {
    int nid;
    enum wd_digest_mode mode;
    enum wd_digest_type alg;
    __u32 out_len;
};

static int digest_nids[] = {
	NID_md5,
	NID_sm3,
	NID_sha1,
	NID_sha224,
	NID_sha256,
	NID_sha384,
	NID_sha512,
	0,
};

static struct digest_threshold_table digest_pkt_threshold_table[] = {
	{ NID_sm3, SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_md5, MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha1, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha224, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha256, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha384, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha512, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
};

static struct digest_info digest_info_table[] = {
    {NID_md5, WD_DIGEST_NORMAL, WD_DIGEST_MD5, MD5_DIGEST_LENGTH},
    {NID_sm3, WD_DIGEST_NORMAL, WD_DIGEST_SM3, SM3_DIGEST_LENGTH},
    {NID_sha1, WD_DIGEST_NORMAL, WD_DIGEST_SHA1, SHA_DIGEST_LENGTH},
    {NID_sha224, WD_DIGEST_NORMAL, WD_DIGEST_SHA224, SHA224_DIGEST_LENGTH},
    {NID_sha256, WD_DIGEST_NORMAL, WD_DIGEST_SHA256, SHA256_DIGEST_LENGTH},
    {NID_sha384, WD_DIGEST_NORMAL, WD_DIGEST_SHA384, SHA384_DIGEST_LENGTH},
    {NID_sha512, WD_DIGEST_NORMAL, WD_DIGEST_SHA512, SHA512_DIGEST_LENGTH},
};

static EVP_MD *uadk_md5;
static EVP_MD *uadk_sm3;
static EVP_MD *uadk_sha1;
static EVP_MD *uadk_sha224;
static EVP_MD *uadk_sha256;
static EVP_MD *uadk_sha384;
static EVP_MD *uadk_sha512;

static int uadk_e_digests_soft_md(struct digest_priv_ctx *priv)
{
    int app_datasize = 0;

    if (priv->soft_md)
        return 1;

    switch (priv->e_nid) {
        case NID_sm3:
            priv->soft_md = EVP_sm3();
            break;
        case NID_md5:
            priv->soft_md = EVP_md5();
            break;
        case NID_sha1:
            priv->soft_md = EVP_sha1();
            break;
        case NID_sha224:
            priv->soft_md = EVP_sha224();
            break;
        case NID_sha256:
            priv->soft_md = EVP_sha256();
            break;
        case NID_sha384:
            priv->soft_md = EVP_sha384();
            break;
        case NID_sha512:
            priv->soft_md = EVP_sha512();
            break;
        default:
            break;
    }

    if (unlikely(priv->soft_md == NULL))
        return 0;

    app_datasize = EVP_MD_meth_get_app_datasize(priv->soft_md);
    if (app_datasize == 0) {
        /* OpenSSL 3.0 has no app_datasize, need set manually
		 * check crypto/evp/legacy_md5.c: md5_md as example
		 */
        switch (priv->e_nid) {
            case NID_sm3:
                app_datasize = sizeof(EVP_MD *) + sizeof(SM3_CTX);
                break;
            case NID_md5:
                app_datasize = sizeof(EVP_MD *) + sizeof(MD5_CTX);
                break;
            case NID_sha1:
                app_datasize = sizeof(EVP_MD *) + sizeof(SHA_CTX);
                break;
            case NID_sha224:
                app_datasize = sizeof(EVP_MD *) + sizeof(SHA256_CTX);
                break;
            case NID_sha256:
                app_datasize = sizeof(EVP_MD *) + sizeof(SHA256_CTX);
                break;
            case NID_sha384:
                app_datasize = sizeof(EVP_MD *) + sizeof(SHA512_CTX);
                break;
            case NID_sha512:
                app_datasize = sizeof(EVP_MD *) + sizeof(SHA512_CTX);
                break;
            default:
                break;
        }
    }

    if (priv->soft_ctx == NULL) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        if (ctx == NULL)
            return 0;

        ctx->md_data = OPENSSL_malloc(app_datasize);
        if (ctx->md_data == NULL)
            return 0;

        priv->soft_ctx = ctx;
        priv->app_datasize = app_datasize;
    }
    return 1;
}

static uint32_t sec_digest_get_sw_threshold(int n_id)
{
    int threshold_table_size = ARRAY_SIZE(digest_pkt_threshold_table);
    int i = 0;

    do {
        if (digest_pkt_threshold_table[i].nid == n_id)
            return digest_pkt_threshold_table[i].threshold;
    } while (++i < threshold_table_size);

    fprintf(stderr, "nid %d not found in digest threshold table", n_id);
    return 0;
}

static int digest_soft_init(struct digest_priv_ctx *priv)
{
    if (uadk_e_digests_soft_md(priv) == 0)
        return 0;

    return EVP_MD_meth_get_init(priv->soft_md)(priv->soft_ctx);
}

static int digest_soft_update(struct digest_priv_ctx *priv, const void *data, size_t len)
{
    return EVP_MD_meth_get_update(priv->soft_md)(priv->soft_ctx, data, len);
}

static int digest_soft_final(struct digest_priv_ctx *priv, unsigned char *digest)
{
    return EVP_MD_meth_get_final(priv->soft_md)(priv->soft_ctx, digest);
}

static void digest_soft_cleanup(struct digest_priv_ctx *md_ctx)
{
    EVP_MD_CTX *ctx = md_ctx->soft_ctx;

    if (ctx != NULL) {
        if (ctx->md_data) {
            OPENSSL_free(ctx->md_data);
            ctx->md_data = NULL;
        }
        EVP_MD_CTX_free(ctx);
        md_ctx->soft_ctx = NULL;
        md_ctx->app_datasize = 0;
    }
}

static int uadk_e_digest_soft_work(struct digest_priv_ctx *md_ctx, int len,
				   unsigned char *digest)
{
    (void)digest_soft_init(md_ctx);

    if (len != 0)
        (void)digest_soft_update(md_ctx, md_ctx->data, len);

    (void)digest_soft_final(md_ctx, digest);

    digest_soft_cleanup(md_ctx);

    return 1;
}

static int uadk_engine_digests(ENGINE *e, const EVP_MD **digest,
			       const int **nids, int nid)
{
    int ok = 1;

    if (!digest) {
        *nids = digest_nids;
        return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
    }

    switch (nid) {
        case NID_md5:
            *digest = uadk_md5;
            break;
        case NID_sm3:
            *digest = uadk_sm3;
            break;
        case NID_sha1:
            *digest = uadk_sha1;
            break;
        case NID_sha224:
            *digest = uadk_sha224;
            break;
        case NID_sha256:
            *digest = uadk_sha256;
            break;
        case NID_sha384:
            *digest = uadk_sha384;
            break;
        case NID_sha512:
            *digest = uadk_sha512;
            break;
        default:
            ok = 0;
            *digest = NULL;
            break;
    }

    return ok;
}

static handle_t sched_single_init(handle_t h_sched_ctx, void *sched_param)
{
    return (handle_t)0;
}

static __u32 sched_single_pick_next_ctx(handle_t sched_ctx,
		void *sched_key, const int sched_mode)
{
    if (sched_mode)
        return CTX_ASYNC;
    else
        return CTX_SYNC;
}

static int sched_single_poll_policy(handle_t h_sched_ctx,
				    __u32 expect, __u32 *count)
{
    return 0;
}

static int uadk_e_digest_poll(void *ctx)
{
    __u64 rx_cnt = 0;
    __u32 recv = 0;
    int expt = 1;
    int ret = 0;

    do {
        ret = wd_digest_poll_ctx(CTX_ASYNC, expt, &recv);
        if (!ret && recv == expt)
            return 0;
        else if (ret == -EAGAIN)
            rx_cnt++;
        else
            return -1;
    } while (rx_cnt < ENGINE_RECV_MAX_CNT);

    fprintf(stderr, "failed to recv msg: timeout!\n");

    return -ETIMEDOUT;
}

static int uadk_e_digest_env_poll(void *ctx)
{
    __u64 rx_cnt = 0;
    __u32 recv = 0;
    /* Poll one packet currently */
    int expt = 1;
    int ret;

    do {
        ret = wd_digest_poll(expt, &recv);
        if (ret < 0 || recv == expt)
            return ret;
        rx_cnt++;
    } while (rx_cnt < ENGINE_ENV_RECV_MAX_CNT);

    fprintf(stderr, "failed to poll msg: timeout!\n");

    return -ETIMEDOUT;
}

static int uadk_e_wd_digest_env_init(struct uacce_dev *dev)
{
    int ret;

    ret = uadk_e_set_env("WD_DIGEST_CTX_NUM", dev->numa_id);
    if (ret)
        return ret;

    ret = wd_digest_env_init(NULL);
    if (ret)
        return ret;

    async_register_poll_fn(ASYNC_TASK_DIGEST, uadk_e_digest_env_poll);

    return 0;
}

static int uadk_e_wd_digest_init(struct uacce_dev *dev)
{
    __u32 i, j;
    int ret;

    g_digest_engine.numa_id = dev->numa_id;

    ret = uadk_e_is_env_enabled("digest");
    if (ret == ENV_ENABLED)
        return uadk_e_wd_digest_env_init(dev);

    memset(&g_digest_engine.ctx_cfg, 0, sizeof(struct wd_ctx_config));
    g_digest_engine.ctx_cfg.ctx_num = CTX_NUM;
    g_digest_engine.ctx_cfg.ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
    if (!g_digest_engine.ctx_cfg.ctxs)
        return -ENOMEM;

    for (i = 0; i < CTX_NUM; i++) {
        g_digest_engine.ctx_cfg.ctxs[i].ctx = wd_request_ctx(dev);
        if (!g_digest_engine.ctx_cfg.ctxs[i].ctx) {
            ret = -ENOMEM;
            goto err_freectx;
        }

        g_digest_engine.ctx_cfg.ctxs[i].op_type = CTX_TYPE_ENCRYPT;
		g_digest_engine.ctx_cfg.ctxs[i].ctx_mode =
			(i == 0) ? CTX_MODE_SYNC : CTX_MODE_ASYNC;
    }

    g_digest_engine.sched.name = "sched_single";
    g_digest_engine.sched.pick_next_ctx = sched_single_pick_next_ctx;
    g_digest_engine.sched.poll_policy = sched_single_poll_policy;
    g_digest_engine.sched.sched_init = sched_single_init;

    ret = wd_digest_init(&g_digest_engine.ctx_cfg, &g_digest_engine.sched);
    if (ret)
        goto err_freectx;

    async_register_poll_fn(ASYNC_TASK_DIGEST, uadk_e_digest_poll);

    return 0;

err_freectx:
    for (j = 0; j < i; j++)
        wd_release_ctx(g_digest_engine.ctx_cfg.ctxs[j].ctx);

    free(g_digest_engine.ctx_cfg.ctxs);

    return ret;
}

static int uadk_e_init_digest(void)
{
    struct uacce_dev *dev;
    int ret;

    if (g_digest_engine.pid != getpid()) {
        pthread_spin_lock(&g_digest_engine.lock);
        if (g_digest_engine.pid == getpid()) {
            pthread_spin_unlock(&g_digest_engine.lock);
            return 1;
        }

        dev = wd_get_accel_dev("digest");
        if (!dev) {
            pthread_spin_unlock(&g_digest_engine.lock);
            fprintf(stderr, "failed to get device for digest.\n");
            return 0;
        }

        ret = uadk_e_wd_digest_init(dev);
        if (ret)
            goto err_unlock;

        g_digest_engine.pid = getpid();
        pthread_spin_unlock(&g_digest_engine.lock);
        free(dev);
    }

    return 1;

err_unlock:
    pthread_spin_unlock(&g_digest_engine.lock);
    free(dev);
    fprintf(stderr, "failed to init digest(%d).\n", ret);

    return 0;
}

static void digest_priv_ctx_setup(struct digest_priv_ctx *priv,
			enum wd_digest_type alg, enum wd_digest_mode mode,
                                  __u32 out_len)
{
    priv->setup.alg = alg;
    priv->setup.mode = mode;
    priv->req.out_buf_bytes = MAX_DIGEST_LENGTH;
    priv->req.out_bytes = out_len;
}

static void digest_priv_ctx_reset(struct digest_priv_ctx *priv)
{
    /* Ensure that private variable values are initialized */
    priv->state = SEC_DIGEST_INIT;
    priv->last_update_bufflen = 0;
    priv->switch_threshold = 0;
    priv->switch_flag = 0;
    priv->total_data_len = 0;
    priv->app_datasize = 0;
    priv->is_stream_copy = false;
}

static int uadk_e_digest_ctrl(EVP_MD_CTX *ctx, int cmd, int numa_node, void *p2)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);

    if (unlikely(!priv)) {
        fprintf(stderr, "digest priv ctx is NULL!\n");
        return 0;
    }
    priv->sched_param.numa_id = numa_node;
    priv->setup.sched_param = (void *)&(priv->sched_param);
    return 1;
}

static int uadk_e_digest_init(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
    __u32 digest_counts = ARRAY_SIZE(digest_info_table);
    __u32 i;
    int ret;

    if (unlikely(!priv)) {
        fprintf(stderr, "priv get from digest ctx is NULL.\n");
        return 0;
    }

    priv->e_nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));

    digest_priv_ctx_reset(priv);

    ret = uadk_e_init_digest();
    if (unlikely(!ret)) {
        priv->switch_flag = UADK_DO_SOFT;
        fprintf(stderr, "uadk failed to initialize digest.\n");
        return digest_soft_init(priv);
    }

    for (i = 0; i < digest_counts; i++) {
        if (priv->e_nid == digest_info_table[i].nid) {
			digest_priv_ctx_setup(priv, digest_info_table[i].alg,
			digest_info_table[i].mode, digest_info_table[i].out_len);
            break;
        }
    }

    if (unlikely(i == digest_counts)) {
        fprintf(stderr, "failed to setup the private ctx.\n");
        return 0;
    }

    /* Use the default numa parameters */
    if (priv->setup.sched_param != &priv->sched_param)
        uadk_e_digest_ctrl(ctx, 0, -1, NULL);

    if (!priv->sess) {
        priv->sess = wd_digest_alloc_sess(&priv->setup);
        if (unlikely(!priv->sess))
            return 0;

        priv->data = malloc(DIGEST_BLOCK_SIZE);
        if (unlikely(!priv->data))
            goto out;
    }

    priv->switch_threshold = sec_digest_get_sw_threshold(priv->e_nid);

    return 1;

out:
    wd_digest_free_sess(priv->sess);
    priv->sess = 0;
    return 0;
}

static void digest_update_out_length(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);

    if (unlikely(!priv)) {
        fprintf(stderr, "priv get from digest ctx is NULL.\n");
        return;
    }

    /* Sha224 and Sha384 need full length mac buffer as doing long hash */
    if (priv->e_nid == NID_sha224)
        priv->req.out_bytes = WD_DIGEST_SHA224_FULL_LEN;

    if (priv->e_nid == NID_sha384)
        priv->req.out_bytes = WD_DIGEST_SHA384_FULL_LEN;
}

static void digest_set_msg_state(struct digest_priv_ctx *priv, bool is_end)
{
    if (unlikely(priv->is_stream_copy)) {
        priv->req.has_next = is_end ? WD_DIGEST_STREAM_END : WD_DIGEST_STREAM_DOING;
        priv->is_stream_copy = false;
    } else {
        priv->req.has_next = is_end ? WD_DIGEST_END : WD_DIGEST_DOING;
    }
}

static int digest_update_inner(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);
    const unsigned char *tmpdata = (const unsigned char *)data;
    size_t left_len = data_len;
    int copy_to_bufflen;
    int ret;

    if (unlikely(!priv)) {
        fprintf(stderr, "priv get from digest ctx is NULL.\n");
        return 0;
    }

    digest_update_out_length(ctx);
    digest_set_msg_state(priv, false);

    while (priv->last_update_bufflen + left_len > DIGEST_BLOCK_SIZE) {
        copy_to_bufflen = DIGEST_BLOCK_SIZE - priv->last_update_bufflen;
		uadk_memcpy(priv->data + priv->last_update_bufflen, tmpdata,
			    copy_to_bufflen);

        priv->last_update_bufflen = DIGEST_BLOCK_SIZE;
        priv->req.in_bytes = DIGEST_BLOCK_SIZE;
        priv->req.in = priv->data;
        priv->req.out = priv->out;
        left_len -= copy_to_bufflen;
        tmpdata += copy_to_bufflen;

        if (priv->state == SEC_DIGEST_INIT)
            priv->state = SEC_DIGEST_FIRST_UPDATING;
        else if (priv->state == SEC_DIGEST_FIRST_UPDATING)
            priv->state = SEC_DIGEST_DOING;

        ret = wd_do_digest_sync(priv->sess, &priv->req);
        if (ret) {
            fprintf(stderr, "do sec digest sync failed, switch to soft digest.\n");
            goto do_soft_digest;
        }

        priv->last_update_bufflen = 0;
        if (left_len <= DIGEST_BLOCK_SIZE) {
            priv->last_update_bufflen = left_len;
            uadk_memcpy(priv->data, tmpdata, priv->last_update_bufflen);
            break;
        }
    }

    return 1;
do_soft_digest:
	if (priv->state == SEC_DIGEST_FIRST_UPDATING
			&& priv->data
			&& priv->last_update_bufflen != 0) {
        priv->switch_flag = UADK_DO_SOFT;
        (void)digest_soft_init(priv);
        ret = digest_soft_update(priv, priv->data, priv->last_update_bufflen);
        if (ret != 1)
            return ret;

        return digest_soft_update(priv, tmpdata, left_len);
    }

    fprintf(stderr, "do soft digest failed during updating!\n");
    return 0;
}

static int uadk_e_digest_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);

    if (unlikely(!priv)) {
        fprintf(stderr, "priv get from digest ctx is NULL.\n");
        return 0;
    }

    if (unlikely(priv->switch_flag == UADK_DO_SOFT))
        goto soft_update;

    priv->total_data_len += data_len;

    if (priv->last_update_bufflen + data_len <= DIGEST_BLOCK_SIZE) {
        uadk_memcpy(priv->data + priv->last_update_bufflen, data, data_len);
        priv->last_update_bufflen += data_len;
        return 1;
    }

    return digest_update_inner(ctx, data, data_len);

soft_update:
    return digest_soft_update(priv, data, data_len);
}

static void *uadk_e_digest_cb(void *data)
{
    struct wd_digest_req *req = (struct wd_digest_req *)data;
    struct uadk_e_cb_info *cb_param;
    struct async_op *op;

    if (!req)
        return NULL;

    cb_param = req->cb_param;
    if (!cb_param)
        return NULL;

    op = cb_param->op;
    if (op && op->job && !op->done) {
        op->done = 1;
        async_free_poll_task(op->idx, 1);
        async_wake_job(op->job);
    }

    return NULL;
}

static int do_digest_sync(struct digest_priv_ctx *priv)
{
    int ret;

	if (priv->req.in_bytes <= priv->switch_threshold &&
		priv->state == SEC_DIGEST_INIT)
        return 0;

    ret = wd_do_digest_sync(priv->sess, &priv->req);
    if (ret) {
        fprintf(stderr, "do sec digest sync failed, switch to soft digest.\n");
        return 0;
    }
    return 1;
}

static int do_digest_async(struct digest_priv_ctx *priv, struct async_op *op)
{
    struct uadk_e_cb_info *cb_param;
    int ret = 0;
    int cnt = 0;
    int idx;

    if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
        fprintf(stderr, "async cipher init failed.\n");
        return ret;
    }

    cb_param = malloc(sizeof(struct uadk_e_cb_info));
    if (!cb_param) {
        fprintf(stderr, "failed to alloc cb_param.\n");
        return ret;
    }

    cb_param->op = op;
    cb_param->priv = priv;
    priv->req.cb = uadk_e_digest_cb;
    priv->req.cb_param = cb_param;

    ret = async_get_free_task(&idx);
    if (!ret)
        goto free_cb_param;

    op->idx = idx;

    do {
        ret = wd_do_digest_async(priv->sess, &priv->req);
        if (unlikely(ret < 0)) {
            if (unlikely(ret != -EBUSY))
                fprintf(stderr, "do digest async operation failed.\n");
            else if (unlikely(cnt++ > ENGINE_SEND_MAX_CNT))
                fprintf(stderr, "do digest async operation timeout.\n");
            else
                continue;

            async_free_poll_task(op->idx, 0);
            ret = 0;
            goto free_cb_param;
        }
    } while (ret == -EBUSY);

    ret = async_pause_job(priv, op, ASYNC_TASK_DIGEST);

free_cb_param:
    free(cb_param);
    priv->req.cb_param = NULL;
    return ret;
}

static int uadk_e_digest_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);
    struct async_op *op;
    int ret = 1;

    if (unlikely(!priv)) {
        fprintf(stderr, "priv get from digest ctx is NULL.\n");
        return 0;
    }

    digest_set_msg_state(priv, true);
    priv->req.in = priv->data;
    priv->req.out = priv->out;
    priv->req.in_bytes = priv->last_update_bufflen;
    priv->e_nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));

    if (priv->e_nid == NID_sha224)
        priv->req.out_bytes = WD_DIGEST_SHA224_LEN;

    if (priv->e_nid == NID_sha384)
        priv->req.out_bytes = WD_DIGEST_SHA384_LEN;

    op = malloc(sizeof(struct async_op));
    if (!op)
        return 0;

    ret = async_setup_async_event_notification(op);
    if (unlikely(!ret)) {
        fprintf(stderr, "failed to setup async event notification.\n");
        free(op);
        return 0;
    }

    if (!op->job) {
        /* Synchronous, only the synchronous mode supports soft computing */
        if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
            ret = digest_soft_final(priv, digest);
            digest_soft_cleanup(priv);
            goto clear;
        }

        ret = do_digest_sync(priv);
        if (!ret)
            goto sync_err;
    } else {
        ret = do_digest_async(priv, op);
        if (!ret)
            goto clear;
    }
    memcpy(digest, priv->req.out, priv->req.out_bytes);

    free(op);
    return 1;

sync_err:
    if (priv->state == SEC_DIGEST_INIT) {
        ret = uadk_e_digest_soft_work(priv, priv->req.in_bytes, digest);
    } else {
        ret = 0;
        fprintf(stderr, "do sec digest stream mode failed.\n");
    }
clear:
    (void)async_clear_async_event_notification();
    free(op);
    return ret;
}

static int uadk_e_digest_cleanup(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);

    if (!priv)
        return 1;

    if (priv->data) {
        free(priv->data);
        priv->data = NULL;
    }

    if (priv->sess) {
        wd_digest_free_sess(priv->sess);
        priv->sess = 0;
    }

    if (priv->soft_ctx)
        digest_soft_cleanup(priv);

    return 1;
}

static int uadk_e_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
	struct digest_priv_ctx *f =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(from);
	struct digest_priv_ctx *t =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(to);
    struct sched_params params = {0};
    int ret;

    if (!t)
        return 1;

    if (!f) {
        fprintf(stderr, "priv get from digest ctx is NULL.\n");
        return 0;
    }

    if (t->sess) {
        params.numa_id = -1;
        t->setup.sched_param = &params;
        t->sess = wd_digest_alloc_sess(&t->setup);
        if (!t->sess) {
            fprintf(stderr, "failed to alloc session for digest ctx copy.\n");
            return 0;
        }

        t->data = malloc(DIGEST_BLOCK_SIZE);
        if (!t->data)
            goto free_sess;

        if (t->state != SEC_DIGEST_INIT) {
            t->is_stream_copy = true;
            /* Length that the hardware has processed should be equal to
			 * total input data length minus software cache data length.
			 */
            t->req.long_data_len = t->total_data_len - t->last_update_bufflen;
        }

        memcpy(t->data, f->data, f->last_update_bufflen);
    }

    if (t->soft_ctx) {
        t->soft_ctx = NULL;
        ret = digest_soft_init(t);
        if (!ret)
            goto free_data;

        memcpy(t->soft_ctx->md_data, f->soft_ctx->md_data, t->app_datasize);
    }

    return 1;

free_data:
    if (t->data) {
        free(t->data);
        t->data = NULL;
    }
free_sess:
    if (t->sess) {
        wd_digest_free_sess(t->sess);
        t->sess = 0;
    }
    return 0;
}


#define UADK_DIGEST_DESCR(name, pkey_type, md_size, flags,		\
	block_size, ctx_size, init, update, final, cleanup, copy, ctrl)	\
do { \
	uadk_##name = EVP_MD_meth_new(NID_##name, NID_##pkey_type);	\
	if (uadk_##name == 0 ||						\
	    !EVP_MD_meth_set_result_size(uadk_##name, md_size) ||	\
	    !EVP_MD_meth_set_input_blocksize(uadk_##name, block_size) || \
	    !EVP_MD_meth_set_app_datasize(uadk_##name, ctx_size) ||	\
	    !EVP_MD_meth_set_flags(uadk_##name, flags) ||		\
	    !EVP_MD_meth_set_init(uadk_##name, init) ||			\
	    !EVP_MD_meth_set_update(uadk_##name, update) ||		\
	    !EVP_MD_meth_set_final(uadk_##name, final) ||		\
	    !EVP_MD_meth_set_cleanup(uadk_##name, cleanup) ||		\
	    !EVP_MD_meth_set_copy(uadk_##name, copy) ||		\
	    !EVP_MD_meth_set_ctrl(uadk_##name, ctrl))			\
		return 0; \
    } while (0)

void uadk_e_digest_lock_init(void)
{
    pthread_spin_init(&g_digest_engine.lock, PTHREAD_PROCESS_PRIVATE);
}

int uadk_e_bind_digest(ENGINE *e)
{
	UADK_DIGEST_DESCR(md5, md5WithRSAEncryption, MD5_DIGEST_LENGTH,
			  0, MD5_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy, uadk_e_digest_ctrl);
	UADK_DIGEST_DESCR(sm3, sm3WithRSAEncryption, SM3_DIGEST_LENGTH,
			  0, SM3_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy, uadk_e_digest_ctrl);
	UADK_DIGEST_DESCR(sha1, sha1WithRSAEncryption, SHA_DIGEST_LENGTH,
			  EVP_MD_FLAG_FIPS, SHA1_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy, uadk_e_digest_ctrl);
	UADK_DIGEST_DESCR(sha224, sha224WithRSAEncryption, SHA224_DIGEST_LENGTH,
			  EVP_MD_FLAG_FIPS, SHA224_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy, uadk_e_digest_ctrl);
	UADK_DIGEST_DESCR(sha256, sha256WithRSAEncryption, SHA256_DIGEST_LENGTH,
			  EVP_MD_FLAG_FIPS, SHA256_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy, uadk_e_digest_ctrl);
	UADK_DIGEST_DESCR(sha384, sha384WithRSAEncryption, SHA384_DIGEST_LENGTH,
			  EVP_MD_FLAG_FIPS, SHA384_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy, uadk_e_digest_ctrl);
	UADK_DIGEST_DESCR(sha512, sha512WithRSAEncryption, SHA512_DIGEST_LENGTH,
			  EVP_MD_FLAG_FIPS, SHA512_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy, uadk_e_digest_ctrl);

    return ENGINE_set_digests(e, uadk_engine_digests);
}

void uadk_e_destroy_digest(void)
{
    __u32 i;
    int ret;

    if (g_digest_engine.pid == getpid()) {
        ret = uadk_e_is_env_enabled("digest");
        if (ret == ENV_ENABLED) {
            wd_digest_env_uninit();
        } else {
            wd_digest_uninit();
            for (i = 0; i < g_digest_engine.ctx_cfg.ctx_num; i++)
                wd_release_ctx(g_digest_engine.ctx_cfg.ctxs[i].ctx);
            free(g_digest_engine.ctx_cfg.ctxs);
        }
        g_digest_engine.pid = 0;
    }

    pthread_spin_destroy(&g_digest_engine.lock);

    EVP_MD_meth_free(uadk_md5);
    uadk_md5 = 0;
    EVP_MD_meth_free(uadk_sm3);
    uadk_sm3 = 0;
    EVP_MD_meth_free(uadk_sha1);
    uadk_sha1 = 0;
    EVP_MD_meth_free(uadk_sha224);
    uadk_sha224 = 0;
    EVP_MD_meth_free(uadk_sha256);
    uadk_sha256 = 0;
    EVP_MD_meth_free(uadk_sha384);
    uadk_sha384 = 0;
    EVP_MD_meth_free(uadk_sha512);
    uadk_sha512 = 0;
}
