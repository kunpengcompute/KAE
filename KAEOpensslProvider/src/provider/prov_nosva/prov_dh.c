/*
 * Copyright 2025 Huawei Technologies Co.,Ltd.All rights reserved.
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
 */

#include <stdint.h>
#include <time.h>

#include <openssl/async.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/kdf.h>

#include "prov.h"
#define KAE_PKEY_PUBLIC_DISPATCH
#include "prov_pkey.h"
#include <openssl/provider.h>
#include "../../adapter/common/kae_log.h"
#include "../../adapter/common/kae_types.h"
#include "../../adapter/nosva/algorithm/pkey/hpre_dh.h"

KAE_PKEY_KEYMGMT_DESCR(dh, DH);
KAE_PKEY_KEYEXCH_DESCR(dh, DH);

static void *kae_keymgmt_dh_new(void *provctx)
{
    if (get_default_dh_keymgmt().new_fun == NULL) {
        US_WARN("failed to get dh keymgmt new function.");
        return NULL;
    }

    return get_default_dh_keymgmt().new_fun(OSSL_PROVIDER_get0_provider_ctx(get_default_dh_keymgmt().prov));
}

static void kae_keymgmt_dh_free(void *keydata)
{
    if (get_default_dh_keymgmt().free == NULL) {
        US_WARN("failed to get dh keymgmt free function.");
        return;
    }

    get_default_dh_keymgmt().free(keydata);
}

static ossl_inline int kae_keymgmt_dh_get_params(void *key, OSSL_PARAM params[])
{
    if (get_default_dh_keymgmt().get_params == NULL) {
        US_WARN("failed to get dh keymgmt get params function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().get_params(key, params);
}

static const OSSL_PARAM *kae_keymgmt_dh_gettable_params(void *provctx)
{
    if (get_default_dh_keymgmt().gettable_params == NULL) {
        US_WARN("failed to get dh keymgmt gettable params function.");
        return NULL;
    }

    return get_default_dh_keymgmt().gettable_params(OSSL_PROVIDER_get0_provider_ctx(get_default_dh_keymgmt().prov));
}

static int kae_keymgmt_dh_set_params(void *key, const OSSL_PARAM params[])
{
    if (get_default_dh_keymgmt().set_params == NULL) {
        US_WARN("failed to get dh keymgmt set params function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().set_params(key, params);
}

static const OSSL_PARAM *kae_keymgmt_dh_settable_params(void *provctx)
{
    if (get_default_dh_keymgmt().settable_params == NULL) {
        US_WARN("failed to get dh keymgmt settable params function.");
        return NULL;
    }

    return get_default_dh_keymgmt().settable_params(OSSL_PROVIDER_get0_provider_ctx(get_default_dh_keymgmt().prov));
}

static void *kae_keymgmt_dh_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    if (get_default_dh_keymgmt().gen_init == NULL) {
        US_WARN("failed to get dh keymgmt gen init function.");
        return NULL;
    }

    return get_default_dh_keymgmt().gen_init(OSSL_PROVIDER_get0_provider_ctx(get_default_dh_keymgmt().prov), selection, params);
}

static int kae_keymgmt_dh_gen_set_template(void *genctx, void *templ)
{
    if (get_default_dh_keymgmt().gen_set_template == NULL) {
        US_WARN("failed to get dh keymgmt get set template function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().gen_set_template(genctx, templ);
}

static int kae_keymgmt_dh_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    if (get_default_dh_keymgmt().gen_set_params == NULL) {
        US_WARN("failed to get dh keymgmt gen set params function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().gen_set_params(genctx, params);
}

static const OSSL_PARAM *kae_keymgmt_dh_gen_settable_params(ossl_unused void *genctx, ossl_unused void *provctx)
{
    if (get_default_dh_keymgmt().gen_settable_params == NULL) {
        US_WARN("failed to get dh keymgmt gen settable params function.");
        return NULL;
    }

    return get_default_dh_keymgmt().gen_settable_params(genctx, OSSL_PROVIDER_get0_provider_ctx(get_default_dh_keymgmt().prov));
}

/* Keep parameter generation and private-key policy with OpenSSL. */
static void *kae_keymgmt_dh_gen(void *genctx, OSSL_CALLBACK *cb, void *cb_params)
{
    KAE_PKEY_KEYMGMT method = get_default_dh_keymgmt();

    return method.gen == NULL ? NULL : method.gen(genctx, cb, cb_params);
}

static void kae_keymgmt_dh_gen_cleanup(void *genctx)
{
    if (get_default_dh_keymgmt().gen_cleanup == NULL) {
        US_WARN("failed to get dh keymgmt gen cleanup function.");
        return;
    }

    get_default_dh_keymgmt().gen_cleanup(genctx);
}

static void *kae_keymgmt_dh_load(const void *reference, size_t reference_sz)
{
    if (get_default_dh_keymgmt().load == NULL) {
        US_WARN("failed to get dh keymgmt load function.");
        return NULL;
    }

    return get_default_dh_keymgmt().load(reference, reference_sz);
}

static int kae_keymgmt_dh_has(const void *keydata, int selection)
{
    if (get_default_dh_keymgmt().has == NULL) {
        US_WARN("failed to get dh keymgmt has function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().has(keydata, selection);
}

static int kae_keymgmt_dh_validate(const void *keydata, int selection, int checktype)
{
    if (get_default_dh_keymgmt().validate == NULL) {
        US_WARN("failed to get dh keymgmt validate function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().validate(keydata, selection, checktype);
}

static int kae_keymgmt_dh_match(const void *keydata1, const void *keydata2, int selection)
{
    if (get_default_dh_keymgmt().match == NULL) {
        US_WARN("failed to get dh keymgmt match function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().match(keydata1, keydata2, selection);
}

static int kae_keymgmt_dh_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    if (get_default_dh_keymgmt().import == NULL) {
        US_WARN("failed to get dh keymgmt import function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().import(keydata, selection, params);
}

static const OSSL_PARAM *kae_keymgmt_dh_import_types(int selection)
{
    if (get_default_dh_keymgmt().import_types == NULL) {
        US_WARN("failed to get dh keymgmt import types function.");
        return NULL;
    }

    return get_default_dh_keymgmt().import_types(selection);
}

static int kae_keymgmt_dh_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cb_params)
{
    if (get_default_dh_keymgmt().export_fun == NULL) {
        US_WARN("failed to get dh keymgmt export function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keymgmt().export_fun(keydata, selection, cb, cb_params);
}

static const OSSL_PARAM *kae_keymgmt_dh_export_types(int selection)
{
    if (get_default_dh_keymgmt().export_types == NULL) {
        US_WARN("failed to get dh keymgmt export types function.");
        return NULL;
    }

    return get_default_dh_keymgmt().export_types(selection);
}

static void *kae_keymgmt_dh_dup(const void *keydata_from, int selection)
{
    if (get_default_dh_keymgmt().dup == NULL) {
        US_WARN("failed to get dh keymgmt dup function.");
        return NULL;
    }

    return get_default_dh_keymgmt().dup(keydata_from, selection);
}

static const char *kae_keymgmt_dh_query_operation_name(int operation_id)
{
    if (get_default_dh_keymgmt().query_operation_name == NULL) {
        US_WARN("failed to get dh keymgmt query op name function.");
        return NULL;
    }

    return get_default_dh_keymgmt().query_operation_name(operation_id);
}

typedef struct {
    uint64_t hpre_ns;
    uint64_t software_ns;
    unsigned int next_sample;
} KAE_DH_SYNC_COST;

typedef struct {
    void *soft;
    DH *key;
    DH *peer;
    unsigned int pad;
    int use_kdf;
    KAE_DH_SYNC_COST sync_cost;
} KAE_DH_CTX;

static void *dh_default_ctx(void)
{
    return OSSL_PROVIDER_get0_provider_ctx(get_default_dh_keyexch().prov);
}

static void *kae_keyexch_dh_newctx(void *provctx)
{
    KAE_PKEY_KEYEXCH method = get_default_dh_keyexch();
    KAE_DH_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    if (method.newctx == NULL || (ctx->soft = method.newctx(dh_default_ctx())) == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static int kae_keyexch_dh_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    KAE_DH_CTX *ctx = vctx;
    KAE_PKEY_KEYEXCH method = get_default_dh_keyexch();
    const OSSL_PARAM *p;
    unsigned int pad = ctx->pad;

    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &pad))
        return 0;
    if (method.set_ctx_params == NULL || !method.set_ctx_params(ctx->soft, params))
        return 0;
    ctx->pad = pad != 0;
    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL)
        ctx->use_kdf = ((const char *)p->data)[0] != '\0';
    return 1;
}

static int kae_keyexch_dh_init(void *vctx, void *key, const OSSL_PARAM params[])
{
    KAE_DH_CTX *ctx = vctx;
    KAE_PKEY_KEYEXCH method = get_default_dh_keyexch();

    if (key == NULL || !method.init(ctx->soft, key, params) || !DH_up_ref(key))
        return 0;
    DH_free(ctx->key);
    DH_free(ctx->peer);
    ctx->key = key;
    ctx->peer = NULL;
    ctx->pad = 0;
    ctx->use_kdf = 0;
    ctx->sync_cost = (KAE_DH_SYNC_COST){0};
    return kae_keyexch_dh_set_ctx_params(ctx, params);
}

static int kae_keyexch_dh_set_peer(void *vctx, void *peer)
{
    KAE_DH_CTX *ctx = vctx;
    KAE_PKEY_KEYEXCH method = get_default_dh_keyexch();
    int codes = 0;

    if (ctx->key == NULL || peer == NULL ||
        DH_get0_pub_key(peer) == NULL ||
        !method.set_peer(ctx->soft, peer) ||
        !DH_check_pub_key(ctx->key, DH_get0_pub_key(peer), &codes) || codes != 0 ||
        !DH_up_ref(peer))
        return 0;
    DH_free(ctx->peer);
    ctx->peer = peer;
    ctx->sync_cost = (KAE_DH_SYNC_COST){0};
    return 1;
}

static int kae_keyexch_dh_derive_hpre(KAE_DH_CTX *ctx, unsigned char *out, size_t *outlen, int size)
{
    int len;

    len = hpre_dh_compute_key(out, DH_get0_pub_key(ctx->peer), ctx->key);
    if (len <= 0 || len > size)
        return 0;
    if (ctx->pad && len < size) {
        memmove(out + size - len, out, len);
        memset(out, 0, size - len);
        len = size;
    } else if (!ctx->pad) {
        int leading = 0;
        while (leading < len && out[leading] == 0)
            leading++;
        if (leading != 0) {
            memmove(out, out + leading, len - leading);
            len -= leading;
        }
    }
    *outlen = len;
    return len > 0;
}

#define DH_SYNC_SAMPLE_INTERVAL 64

static uint64_t dh_monotonic_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int kae_keyexch_dh_derive(void *vctx, unsigned char *out, size_t *outlen, size_t capacity)
{
    extern int dh_switch_soft;
    KAE_DH_CTX *ctx = vctx;
    int size;

    if (ctx->key == NULL || outlen == NULL)
        return 0;
    /* The default provider owns KDF policy and its private KDF context. */
    if (ctx->use_kdf || dh_switch_soft)
        return get_default_dh_keyexch().derive(ctx->soft, out, outlen, capacity);
    size = DH_size(ctx->key);
    if (size <= 0)
        return 0;
    if (out == NULL) {
        *outlen = size;
        return 1;
    }
    if (capacity < (size_t)size || ctx->peer == NULL || DH_get0_priv_key(ctx->key) == NULL)
        return 0;
    if (ASYNC_get_current_job() != NULL)
        return kae_keyexch_dh_derive_hpre(ctx, out, outlen, size);

    /*
     * Shared HPRE queues can be slower than local software under contention.
     * Sample real derives on repeated synchronous use and retry HPRE regularly
     * so that the context returns to it when accelerator load drops.
     */
    KAE_DH_SYNC_COST *cost = &ctx->sync_cost;
    unsigned int sample = cost->next_sample;
    cost->next_sample = (sample + 1) % DH_SYNC_SAMPLE_INTERVAL;
    /* Interleave the two paths near parity instead of moving all work at once. */
    unsigned int slow_hpre_share = 0;
    if (cost->software_ns != 0 && cost->hpre_ns >= cost->software_ns - cost->software_ns / 8)
        slow_hpre_share = cost->hpre_ns > cost->software_ns + cost->software_ns / 8 ? 3 : 1;
    int use_software = sample == 1 || (sample != 0 && sample % 4 < slow_hpre_share);
    uint64_t begin = sample < 2 ? dh_monotonic_ns() : 0;
    int ret = use_software ? get_default_dh_keyexch().derive(ctx->soft, out, outlen, capacity) :
        kae_keyexch_dh_derive_hpre(ctx, out, outlen, size);

    if (begin != 0 && ret) {
        uint64_t end = dh_monotonic_ns();
        if (end > begin) {
            uint64_t *estimate = use_software ? &cost->software_ns : &cost->hpre_ns;
            uint64_t elapsed = end - begin;
            *estimate = *estimate == 0 ? elapsed : *estimate - *estimate / 4 + elapsed / 4;
        }
    }
    return ret;
}

static void kae_keyexch_dh_freectx(void *vctx)
{
    KAE_DH_CTX *ctx = vctx;
    KAE_PKEY_KEYEXCH method = get_default_dh_keyexch();

    if (ctx == NULL)
        return;
    if (ctx->soft != NULL && method.freectx != NULL)
        method.freectx(ctx->soft);
    DH_free(ctx->key);
    DH_free(ctx->peer);
    OPENSSL_free(ctx);
}

static void *kae_keyexch_dh_dupctx(void *vctx)
{
    KAE_DH_CTX *src = vctx, *dst = OPENSSL_zalloc(sizeof(*dst));
    KAE_PKEY_KEYEXCH method = get_default_dh_keyexch();

    if (dst == NULL)
        return NULL;
    dst->pad = src->pad;
    dst->use_kdf = src->use_kdf;
    if (method.dupctx == NULL || (dst->soft = method.dupctx(src->soft)) == NULL)
        goto err;
    if (src->key != NULL) {
        if (!DH_up_ref(src->key))
            goto err;
        dst->key = src->key;
    }
    if (src->peer != NULL) {
        if (!DH_up_ref(src->peer))
            goto err;
        dst->peer = src->peer;
    }
    return dst;
err:
    kae_keyexch_dh_freectx(dst);
    return NULL;
}

static int kae_keyexch_dh_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    KAE_DH_CTX *ctx = vctx;
    return get_default_dh_keyexch().get_ctx_params(ctx->soft, params);
}

static const OSSL_PARAM *kae_keyexch_dh_gettable_ctx_params(void *vctx, void *provctx)
{
    KAE_DH_CTX *ctx = vctx;
    return get_default_dh_keyexch().gettable_ctx_params(ctx ? ctx->soft : NULL, dh_default_ctx());
}

static const OSSL_PARAM *kae_keyexch_dh_settable_ctx_params(void *vctx, void *provctx)
{
    KAE_DH_CTX *ctx = vctx;
    return get_default_dh_keyexch().settable_ctx_params(ctx ? ctx->soft : NULL, dh_default_ctx());
}
