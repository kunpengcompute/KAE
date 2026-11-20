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

#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/kdf.h>

#include "prov.h"
#include "prov_pkey.h"
#include "internal/prov_ffc.h"
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

    return get_default_dh_keymgmt().new_fun(provctx);
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

    return get_default_dh_keymgmt().gettable_params(provctx);
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

    return get_default_dh_keymgmt().settable_params(provctx);
}

static void *kae_keymgmt_dh_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    if (get_default_dh_keymgmt().gen_init == NULL) {
        US_WARN("failed to get dh keymgmt gen init function.");
        return NULL;
    }

    return get_default_dh_keymgmt().gen_init(provctx, selection, params);
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

    return get_default_dh_keymgmt().gen_settable_params(genctx, provctx);
}

static int ossl_dh_get_named_group_uid_from_size(int pbits)
{
    int nid;

    /*
     * Just choose an approved safe prime group.
     * The alternative to this is to generate FIPS186-4 domain parameters i.e.
     * return dh_generate_ffc_parameters(ret, prime_len, 0, NULL, cb);
     * As the FIPS186-4 generated params are for backwards compatibility,
     * the safe prime group should be used as the default.
     */
    switch (pbits) {
        case DH2048BITS:
            nid = NID_ffdhe2048;
            break;
        case DH3072BITS:
            nid = NID_ffdhe3072;
            break;
        case DH4096BITS:
            nid = NID_ffdhe4096;
            break;
        /*
         * Retain the commonly supported part. The different specifications are
         * listed in the unsupported prime_len scope:
         * 'pbits' 6144 and 8192 are supported by OpenSSL but not supported by kae,
         * 'pbits' 768/1024/1536 are not supported by OpenSSL.
         *
         */
        default:
            US_ERR("kae unsupport dh size.");
            return NID_undef;
    }

    return nid;
}

static DH *ossl_dh_new_ex(OSSL_LIB_CTX *libctx)
{
    DH *dh = OPENSSL_zalloc(sizeof(*dh));

    if (dh == NULL) {
        US_ERR("failed to alloc dh.");
        return NULL;
    }

    dh->references = 1;
    dh->lock = CRYPTO_THREAD_lock_new();
    if (dh->lock == NULL) {
        US_ERR("failed to new dh thread lock.");
        OPENSSL_free(dh);
        return NULL;
    }

    dh->libctx = libctx;

    return dh;
}

static FFC_PARAMS *ossl_dh_get0_params(DH *dh)
{
    if (dh == NULL)
        return NULL;

    return &dh->params;
}

static void ossl_dh_free_ex(DH *dh)
{
    if (dh) {
        CRYPTO_THREAD_lock_free(dh->lock);
        OPENSSL_free(dh);
    }
}

static int dh_gencb(int p, int n, BN_GENCB *cb)
{
    OSSL_PARAM params[] = {OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END};
    PROV_DH_KEYMGMT_CTX *gctx = BN_GENCB_get_arg(cb);

    params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
    params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);

    return gctx->cb(params, gctx->cbarg);
}

static int ossl_dh_generate_ffc_parameters(DH *dh, int type, int pbits, int qbits, BN_GENCB *cb)
{
    int ret, res;

    if (type == DH_PARAMGEN_TYPE_FIPS_186_2)
        ret = ossl_ffc_params_FIPS186_2_generate(dh->libctx, &dh->params, FFC_PARAM_TYPE_DH, pbits, qbits, &res, cb);
    else
        ret = ossl_ffc_params_FIPS186_4_generate(dh->libctx, &dh->params, FFC_PARAM_TYPE_DH, pbits, qbits, &res, cb);
    if (ret > 0)
        dh->dirty_cnt++;

    return ret;
}

static int prov_dh_gen_params_cb(PROV_DH_KEYMGMT_CTX *gctx, DH *dh, OSSL_CALLBACK *cb, void *cb_params)
{
    int ret = KAE_P_SUCCESS;
    BN_GENCB *gencb;

    if (cb == NULL || cb_params == NULL) {
        US_ERR("invalid: cb function or param is NULL.");
        return KAE_P_FAIL;
    }

    gctx->cb = cb;
    gctx->cbarg = cb_params;
    /* gencb can be NULL */
    gencb = BN_GENCB_new();
    if (gencb != NULL)
        BN_GENCB_set(gencb, dh_gencb, gctx);

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /*
         * NOTE: The old safe prime generator code is not used in fips mode,
         * (i.e internally it ignores the generator and chooses a named
         * group based on pbits.
         */
        if (gctx->gen_type == DH_PARAMGEN_TYPE_GENERATOR)
            ret = DH_generate_parameters_ex(dh, gctx->pbits, gctx->generator, gencb);
        else
            ret = ossl_dh_generate_ffc_parameters(dh, gctx->gen_type, gctx->pbits, gctx->qbits, gencb);
        if (ret <= 0) {
            US_ERR("failed to generate ffc parameters.");
            ret = KAE_P_FAIL;
        }
    }

    if (gencb)
        BN_GENCB_free(gencb);

    return ret;
}

static DH *prov_dh_gen_params_ex(PROV_DH_KEYMGMT_CTX *gctx, FFC_PARAMS **ffc)
{
    DH *dh;

    /* Use existing params */
    dh = ossl_dh_new_ex(gctx->libctx);
    if (dh == NULL) {
        US_ERR("failed to new dh by nid.");
        return NULL;
    }

    *ffc = ossl_dh_get0_params(dh);
    if (*ffc == NULL) {
        US_ERR("failed to get ffc params.");
        goto free_dh;
    }

    /* Copy the template value if one was passed */
    if (gctx->ffc_params != NULL && ossl_ffc_params_copy(*ffc, gctx->ffc_params) == 0) {
        US_ERR("failed to copy params.");
        goto free_dh;
    }

    if (ossl_ffc_params_set_seed(*ffc, gctx->seed, gctx->seedlen) == 0) {
        US_ERR("failed to set seed.");
        goto free_dh;
    }

    if (gctx->gindex != -1) {
        ossl_ffc_params_set_gindex(*ffc, gctx->gindex);
        if (gctx->pcounter != -1)
            ossl_ffc_params_set_pcounter(*ffc, gctx->pcounter);
    } else if (gctx->hindex != 0) {
        ossl_ffc_params_set_h(*ffc, gctx->hindex);
    }

    if (gctx->mdname) {
        if (ossl_ffc_set_digest(*ffc, gctx->mdname, gctx->mdprops) == 0) {
            US_ERR("failed to set digest.");
            goto free_dh;
        }
    }

    return dh;

free_dh:
    ossl_dh_free_ex(dh);

    return NULL;
}

static DH *prov_dh_gen_params_with_group(PROV_DH_KEYMGMT_CTX *gctx, FFC_PARAMS **ffc)
{
    const DH_NAMED_GROUP *group;
    DH *dh = NULL;

    /* Select a named group if there is not one already */
    if (gctx->group_nid == NID_undef) {
        gctx->group_nid = ossl_dh_get_named_group_uid_from_size(gctx->pbits);
        if (gctx->group_nid == NID_undef) {
            US_ERR("failed to get named group uid from size.");
            return NULL;
        }
    }

    group = ossl_ffc_uid_to_dh_named_group(gctx->group_nid);
    if (!group) {
        US_ERR("failed to get dh named group.");
        return NULL;
    }

    dh = ossl_dh_new_ex(gctx->libctx);
    if (dh == NULL) {
        US_ERR("failed to get dh from libctx.");
        return NULL;
    }

    dh->meth = DH_get_default_method();
    ossl_ffc_named_group_set(&dh->params, group);
    dh->params.nid = ossl_ffc_named_group_get_uid(group);
    dh->dirty_cnt++;

    *ffc = ossl_dh_get0_params(dh);
    if (*ffc == NULL) {
        US_ERR("failed to gen ffc params.");
        ossl_dh_free_ex(dh);
        return NULL;
    }

    return dh;
}

static DH *prov_dh_gen_params(PROV_DH_KEYMGMT_CTX *gctx, FFC_PARAMS **ffc, OSSL_CALLBACK *cb, void *cb_params)
{
    DH *dh;
    int ret;

    /* For parameter generation - If there is a group name just create it */
    if (gctx->gen_type == DH_PARAMGEN_TYPE_GROUP && gctx->ffc_params == NULL) {
        dh = prov_dh_gen_params_with_group(gctx, ffc);
        if (dh == NULL || *ffc == NULL)
            return NULL;
    } else {
        dh = prov_dh_gen_params_ex(gctx, ffc);
        if (dh == NULL || *ffc == NULL)
            return NULL;

        ret = prov_dh_gen_params_cb(gctx, dh, cb, cb_params);
        if (ret == KAE_P_FAIL) {
            ossl_dh_free_ex(dh);
            return NULL;
        }
    }

    return dh;
}

static void *kae_dh_sw_gen(void *genctx, OSSL_CALLBACK *cb, void *cb_params)
{
    if (!get_default_dh_keymgmt().gen) {
        US_WARN("failed to get dh keymgmt gen function.");
        return NULL;
    }

    return get_default_dh_keymgmt().gen(genctx, cb, cb_params);
}

static void prov_dh_free_params(DH *dh)
{
    FFC_PARAMS *ffc;

    ffc = ossl_dh_get0_params(dh);
    if (ffc)
        ossl_ffc_params_cleanup(ffc);

    /*
     * Release DH object that allocated by uadk_prov_dh_gen_params_ex() or
     * uadk_prov_dh_gen_params_with_group().
     */
    ossl_dh_free_ex(dh);
}

static void *kae_keymgmt_dh_gen(void *genctx, OSSL_CALLBACK *cb, void *cb_params)
{
    PROV_DH_KEYMGMT_CTX *gctx = (PROV_DH_KEYMGMT_CTX *)genctx;
    FFC_PARAMS *ffc = NULL;
    DH *dh = NULL;
    int ret = KAE_P_FAIL;

    if (gctx == NULL) {
        US_ERR("invalid: keygen ctx is NULL.");
        return NULL;
    }

    /*
     * If a group name is selected then the type is group regardless of what
     * the user selected. This overrides rather than errors for backwards
     * compatibility.
     */
    if (gctx->group_nid != NID_undef)
        gctx->gen_type = DH_PARAMGEN_TYPE_GROUP;

    dh = prov_dh_gen_params(gctx, &ffc, cb, cb_params);
    if (dh == NULL || ffc == NULL) {
        ret = KAE_P_FAIL;
        goto free_gen_params;
    }
    /* DH key generation */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        if (ffc->p == NULL || ffc->g == NULL) {
            US_ERR("invalid: ffc->p or ffc->g is NULL.");
            goto free_gen_params;
        }

        if (gctx->priv_len > 0)
            (void)DH_set_length(dh, (long)gctx->priv_len);

        ossl_ffc_params_enable_flags(
            ffc, FFC_PARAM_FLAG_VALIDATE_LEGACY, gctx->gen_type == DH_PARAMGEN_TYPE_FIPS_186_2);

        ret = hpre_dh_generate_key(dh);
        if (ret != KAE_P_SUCCESS) {
            US_ERR("failed to do dh generation key.");
            goto free_gen_params;
        }
    }

    DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
    DH_set_flags(dh, gctx->dh_type);

    return dh;

free_gen_params:
    prov_dh_free_params(dh);

    if (ret == KAE_P_FAIL)
        return kae_dh_sw_gen(genctx, cb, cb_params);
    return NULL;
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

static void *kae_keyexch_dh_newctx(void *provctx)
{
    PROV_DH_KEYEXCH_CTX *pdhctx;

    pdhctx = OPENSSL_zalloc(sizeof(PROV_DH_KEYEXCH_CTX));
    if (pdhctx == NULL) {
        US_ERR("failed to alloc pdhctx.");
        return NULL;
    }

    /* The libctx maybe NULL, if libctx is NULL, will use default ctx. */
    pdhctx->libctx = prov_libctx_of(provctx);
    pdhctx->kdf_type = PROV_DH_KDF_NONE;

    return pdhctx;
}

static int prov_dh_locate_kdf_type(PROV_DH_KEYEXCH_CTX *pdhctx, const OSSL_PARAM params[])
{
    char name[DH_MAX_PARAM_LEN + 1] = {'\0'};
    const OSSL_PARAM *p;
    char *str;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        str = name;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
            return KAE_P_FAIL;

        if (name[0] == '\0')
            pdhctx->kdf_type = PROV_DH_KDF_NONE;
        else if (strcmp(name, OSSL_KDF_NAME_X942KDF_ASN1) == 0)
            pdhctx->kdf_type = PROV_DH_KDF_X9_42_ASN1;
        else
            return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static int prov_dh_locate_kdf_digest(PROV_DH_KEYEXCH_CTX *pdhctx, const OSSL_PARAM params[])
{
    char mdprops[DH_MAX_PARAM_LEN + 1] = {'\0'};
    char name[DH_MAX_PARAM_LEN + 1] = {'\0'};
    const OSSL_PARAM *p;
    char *str;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL) {
        str = name;
        if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(name)))
            return KAE_P_FAIL;

        str = mdprops;
        p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
        if (p != NULL)
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops)))
                return KAE_P_FAIL;

        if (pdhctx->kdf_md)
            EVP_MD_free(pdhctx->kdf_md);

        pdhctx->kdf_md = EVP_MD_fetch(pdhctx->libctx, name, mdprops);
        if (pdhctx->kdf_md == NULL)
            return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static int prov_dh_locate_kdf_outlen(PROV_DH_KEYEXCH_CTX *pdhctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t outlen = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &outlen))
            return KAE_P_FAIL;
        pdhctx->kdf_outlen = outlen;
    }

    return KAE_P_SUCCESS;
}

static int prov_dh_locate_kdf_ukm(PROV_DH_KEYEXCH_CTX *pdhctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    void *tmp_ukm = NULL;
    size_t tmp_ukmlen;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL) {
        if (pdhctx->kdf_ukm)
            OPENSSL_free(pdhctx->kdf_ukm);
        pdhctx->kdf_ukm = NULL;
        pdhctx->kdf_ukmlen = 0;

        /* ukm is an optional field so it can be NULL */
        if (p->data != NULL && p->data_size != 0) {
            if (!OSSL_PARAM_get_octet_string(p, &tmp_ukm, 0, &tmp_ukmlen))
                return KAE_P_FAIL;
            pdhctx->kdf_ukm = tmp_ukm;
            pdhctx->kdf_ukmlen = tmp_ukmlen;
        }
    }

    return KAE_P_SUCCESS;
}

static int prov_dh_locate_kdf_pad(PROV_DH_KEYEXCH_CTX *pdhctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    unsigned int pad = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &pad))
            return KAE_P_FAIL;
        pdhctx->pad = pad ? 1 : 0;
    }

    return KAE_P_SUCCESS;
}

static int kae_keyexch_dh_set_ctx_params(void *dhctx, const OSSL_PARAM params[])
{
    PROV_DH_KEYEXCH_CTX *pdhctx = (PROV_DH_KEYEXCH_CTX *)dhctx;
    int ret = KAE_P_FAIL;

    if (pdhctx == NULL) {
        US_ERR("invalid: dh ctx is NULL.");
        return ret;
    }

    /* If params is NULL, no need to set */
    if (params == NULL)
        return KAE_P_SUCCESS;

    // pthread_mutex_lock(&dh_mutex);
    ret = prov_dh_locate_kdf_type(pdhctx, params);
    if (ret == KAE_P_FAIL) {
        US_ERR("failed to locate kdf type.");
        goto end;
    }

    ret = prov_dh_locate_kdf_digest(pdhctx, params);
    if (ret == KAE_P_FAIL) {
        US_ERR("failed to locate kdf digest.");
        goto end;
    }

    ret = prov_dh_locate_kdf_outlen(pdhctx, params);
    if (ret == KAE_P_FAIL) {
        US_ERR("failed to locate kdf outlen.");
        goto end;
    }

    ret = prov_dh_locate_kdf_ukm(pdhctx, params);
    if (ret == KAE_P_FAIL) {
        US_ERR("failed to locate kdf ukm.");
        goto end;
    }

    ret = prov_dh_locate_kdf_pad(pdhctx, params);
    if (ret == KAE_P_FAIL)
        US_ERR("failed to locate kdf pad.");

end:
    // pthread_mutex_unlock(&dh_mutex);
    return ret;
}

static int kae_keyexch_dh_init(void *dhctx, void *dh, const OSSL_PARAM params[])
{
    PROV_DH_KEYEXCH_CTX *pdhctx = (PROV_DH_KEYEXCH_CTX *)dhctx;

    if (pdhctx == NULL) {
        US_ERR("invalid: dhctx is NULL.");
        return KAE_P_FAIL;
    }

    if (dh == NULL || !DH_up_ref(dh)) {
        US_ERR("invalid: dh is NULL.");
        return KAE_P_FAIL;
    }

    // pthread_mutex_lock(&dh_mutex);
    if (pdhctx->dh) {
        DH_free(pdhctx->dh);
        pdhctx->dh = NULL;
    }

    pdhctx->dh = dh;
    pdhctx->kdf_type = PROV_DH_KDF_NONE;
    // pthread_mutex_unlock(&dh_mutex);

    return kae_keyexch_dh_set_ctx_params(pdhctx, params);
}

static int kae_dh_sw_derive(void *dhctx, unsigned char *secret, size_t *psecretlen, size_t outlen)
{
    if (!get_default_dh_keyexch().derive) {
        US_WARN("failed to get dh keyexch derive function.");
        return KAE_P_FAIL;
    }

    return get_default_dh_keyexch().derive(dhctx, secret, psecretlen, outlen);
}

static int dh_compute_key_padded(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    size_t dhsize;
    int rv, pad;

    /* rv is constant unless compute_key is external */
    rv = hpre_dh_compute_key(key, pub_key, dh);
    if (rv <= 0)
        return rv;

    dhsize = BN_num_bytes(dh->params.p);
    pad = dhsize - rv;
    /* pad is constant (zero) unless compute_key is external */
    if (pad > 0) {
        memmove(key + pad, key, rv);
        memset(key, 0, pad);
    }

    if (pad < 0) {
        US_ERR("invalid: recv key size > dhsize.");
        return KAE_P_FAIL;
    }

    return rv + pad;
}

static int prov_dh_plain_derive(
    PROV_DH_KEYEXCH_CTX *pdhctx, unsigned char *secret, size_t *secretlen, size_t outlen, unsigned int pad)
{
    const BIGNUM *pubkey = NULL;
    size_t dhsize;
    int ret;

    /* pdhctx has been checked when the function is called */
    if (pdhctx->dh == NULL) {
        US_ERR("invalid: dh is NULL.");
        return KAE_P_FAIL;
    }

    dhsize = (size_t)DH_size(pdhctx->dh);
    if (dhsize == 0) {
        US_ERR("invalid: dhszie is zero.");
        return KAE_P_FAIL;
    }

    if (secret == NULL) {
        *secretlen = dhsize;
        return KAE_P_SUCCESS;
    }

    if (outlen < dhsize) {
        US_ERR("invalid: outlen < dhsize.");
        return KAE_P_FAIL;
    }

    if (pdhctx->dhpeer == NULL) {
        US_ERR("invalid: dhpeer is NULL.");
        return KAE_P_FAIL;
    }

    DH_get0_key(pdhctx->dhpeer, &pubkey, NULL);

    if (pad)
        ret = dh_compute_key_padded(secret, pubkey, pdhctx->dh);
    else
        ret = hpre_dh_compute_key(secret, pubkey, pdhctx->dh);
    if (ret <= 0) {
        US_ERR("failed to do dh compute, pad.");
        return ret;
    }

    *secretlen = ret;

    return KAE_P_SUCCESS;
}

/* Key derivation function from X9.63/SECG */
static int ossl_dh_kdf_X9_42_asn1(
    unsigned char *out, PROV_DH_KEYEXCH_CTX *pdhctx, const unsigned char *z, size_t z_len, const char *propq)
{
    OSSL_LIB_CTX *libctx = pdhctx->libctx;
    const char *cek_alg = pdhctx->kdf_cekalg;
    const unsigned char *ukm = pdhctx->kdf_ukm;
    OSSL_PARAM params[KDF_PARAM_NUM] = {0};
    size_t outlen = pdhctx->kdf_outlen;
    size_t ukmlen = pdhctx->kdf_ukmlen;
    const EVP_MD *md = pdhctx->kdf_md;
    OSSL_PARAM *p = params;
    const char *mdname;
    EVP_KDF_CTX *kctx;
    EVP_KDF *kdf;
    int ret = 0;

    kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X942KDF_ASN1, propq);
    if (kdf == NULL)
        return 0;

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL)
        goto end;

    mdname = EVP_MD_get0_name(md);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)mdname, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (unsigned char *)z, z_len);
    if (ukm != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_UKM, (unsigned char *)ukm, ukmlen);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, (char *)cek_alg, 0);
    *p = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(kctx, out, outlen, params) > 0;

end:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    return ret;
}

static int prov_dh_X9_42_kdf_derive(
    PROV_DH_KEYEXCH_CTX *pdhctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    unsigned char *stmp;
    size_t stmplen;
    int ret = 0;

    if (secret == NULL) {
        *secretlen = pdhctx->kdf_outlen;
        return KAE_P_SUCCESS;
    }

    if (outlen < pdhctx->kdf_outlen) {
        US_ERR("invalid: outlen < kdf_outlen.");
        return KAE_P_FAIL;
    }

    if (!prov_dh_plain_derive(pdhctx, NULL, &stmplen, 0, 1))
        return KAE_P_FAIL;

    stmp = OPENSSL_secure_malloc(stmplen);
    if (stmp == NULL) {
        US_ERR("failed to do OPENSSL_secure_malloc.");
        return KAE_P_FAIL;
    }

    ret = prov_dh_plain_derive(pdhctx, stmp, &stmplen, stmplen, USE_PAD);
    if (ret != KAE_P_SUCCESS)
        goto end;

    /* Do KDF stuff */
    if (pdhctx->kdf_type == PROV_DH_KDF_X9_42_ASN1) {
        if (ossl_dh_kdf_X9_42_asn1(secret, pdhctx, stmp, stmplen, NULL) == KAE_P_FAIL) {
            ret = KAE_P_FAIL;
            US_ERR("failed to do ossl_dh_kdf_X9_42_asn1.");
            goto end;
        }
    }

    *secretlen = pdhctx->kdf_outlen;
    ret = KAE_P_SUCCESS;

end:
    OPENSSL_secure_clear_free(stmp, stmplen);

    return ret;
}

static int kae_keyexch_dh_derive(void *dhctx, unsigned char *secret, size_t *psecretlen, size_t outlen)
{
    PROV_DH_KEYEXCH_CTX *pdhctx = (PROV_DH_KEYEXCH_CTX *)dhctx;
    int ret = KAE_P_FAIL;

    if (pdhctx == NULL) {
        US_ERR("invalid: pdhctx is NULL.");
        return KAE_P_FAIL;
    }

    switch (pdhctx->kdf_type) {
        case PROV_DH_KDF_NONE:
            ret = prov_dh_plain_derive(pdhctx, secret, psecretlen, outlen, pdhctx->pad);
            break;
        case PROV_DH_KDF_X9_42_ASN1:
            ret = prov_dh_X9_42_kdf_derive(pdhctx, secret, psecretlen, outlen);
            break;
        default:
            US_ERR("invalid: unsupport kdf type.");
            ret = KAE_P_FAIL;
            break;
    }

    if (ret == KAE_P_SUCCESS)
        return KAE_P_SUCCESS;
    if (ret == KAE_P_FAIL)
        return kae_dh_sw_derive(dhctx, secret, psecretlen, outlen);
    return KAE_P_FAIL;
}

/* The 2 parties must share the same domain parameters */
static int kae_keyexch_dh_match_params(DH *priv, DH *peer)
{
    FFC_PARAMS *dhparams_priv = ossl_dh_get0_params(priv);
    FFC_PARAMS *dhparams_peer = ossl_dh_get0_params(peer);
    int ret;

    if (dhparams_priv == NULL || dhparams_peer == NULL) {
        US_ERR("failed to get dh params.");
        return KAE_P_FAIL;
    }

    ret = ossl_ffc_params_cmp(dhparams_priv, dhparams_peer, IGNORE_Q);
    if (ret == KAE_P_FAIL)
        US_ERR("invalid: domain parameters of both parties do not match.");

    return ret;
}

static int kae_keyexch_dh_set_peer(void *dhctx, void *dh)
{
    PROV_DH_KEYEXCH_CTX *pdhctx = (PROV_DH_KEYEXCH_CTX *)dhctx;

    if (pdhctx == NULL || dh == NULL) {
        US_ERR("invalid: dh ctx or object is NULL.");
        return KAE_P_FAIL;
    }

    if (kae_keyexch_dh_match_params(dh, pdhctx->dh) == KAE_P_FAIL || DH_up_ref(dh) == KAE_P_FAIL) {
        US_ERR("failed to match dh params.");
        return KAE_P_FAIL;
    }

    // pthread_mutex_lock(&dh_mutex);
    if (pdhctx->dhpeer)
        DH_free(pdhctx->dhpeer);
    pdhctx->dhpeer = dh;
    // pthread_mutex_unlock(&dh_mutex);

    return KAE_P_SUCCESS;
}

static void kae_keyexch_dh_freectx(void *dhctx)
{
    PROV_DH_KEYEXCH_CTX *pdhctx = (PROV_DH_KEYEXCH_CTX *)dhctx;

    if (pdhctx == NULL)
        return;

    if (pdhctx->kdf_cekalg) {
        OPENSSL_free(pdhctx->kdf_cekalg);
        pdhctx->kdf_cekalg = NULL;
    }

    if (pdhctx->dh) {
        DH_free(pdhctx->dh);
        pdhctx->dh = NULL;
    }

    if (pdhctx->dhpeer) {
        DH_free(pdhctx->dhpeer);
        pdhctx->dhpeer = NULL;
    }

    if (pdhctx->kdf_md) {
        EVP_MD_free(pdhctx->kdf_md);
        pdhctx->kdf_md = NULL;
    }

    if (pdhctx->kdf_ukm) {
        OPENSSL_clear_free(pdhctx->kdf_ukm, pdhctx->kdf_ukmlen);
        pdhctx->kdf_ukm = NULL;
    }

    if (pdhctx->kdf_cekalg) {
        OPENSSL_free(pdhctx->kdf_cekalg);
        pdhctx->kdf_cekalg = NULL;
    }

    OPENSSL_free(pdhctx);
}

static void *kae_keyexch_dh_dupctx(void *dhctx)
{
    PROV_DH_KEYEXCH_CTX *srcctx = (PROV_DH_KEYEXCH_CTX *)dhctx;
    PROV_DH_KEYEXCH_CTX *dstctx;

    if (srcctx == NULL) {
        US_ERR("invalid: src ctx is NULL.");
        return NULL;
    }

    dstctx = OPENSSL_zalloc(sizeof(*dstctx));
    if (dstctx == NULL) {
        US_ERR("failed to alloc dst ctx.");
        return NULL;
    }

    memcpy(dstctx, srcctx, sizeof(PROV_DH_KEYEXCH_CTX));
    dstctx->dh = NULL;
    dstctx->dhpeer = NULL;
    dstctx->kdf_md = NULL;
    dstctx->kdf_ukm = NULL;
    dstctx->kdf_cekalg = NULL;

    if (srcctx->dh && !DH_up_ref(srcctx->dh))
        goto err;
    else
        dstctx->dh = srcctx->dh;

    if (srcctx->dhpeer && !DH_up_ref(srcctx->dhpeer))
        goto err;
    else
        dstctx->dhpeer = srcctx->dhpeer;

    if (srcctx->kdf_md && !EVP_MD_up_ref(srcctx->kdf_md))
        goto err;
    else
        dstctx->kdf_md = srcctx->kdf_md;

    /* Duplicate UKM data if present */
    if (srcctx->kdf_ukm && srcctx->kdf_ukmlen > 0) {
        dstctx->kdf_ukm = OPENSSL_memdup(srcctx->kdf_ukm, srcctx->kdf_ukmlen);
        if (dstctx->kdf_ukm == NULL)
            goto err;
    }

    if (srcctx->kdf_cekalg != NULL) {
        dstctx->kdf_cekalg = OPENSSL_strdup(srcctx->kdf_cekalg);
        if (dstctx->kdf_cekalg == NULL)
            goto err;
    }

    return dstctx;

err:
    kae_keyexch_dh_freectx(dstctx);

    return NULL;
}

static const OSSL_PARAM known_settable_ctx_params[] = {OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_PAD, NULL),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *kae_keyexch_dh_settable_ctx_params(ossl_unused void *dhctx, ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static int kae_keyexch_dh_get_ctx_params(void *dhctx, OSSL_PARAM params[])
{
    PROV_DH_KEYEXCH_CTX *pdhctx = (PROV_DH_KEYEXCH_CTX *)dhctx;
    const char *kdf_type;
    OSSL_PARAM *p;

    if (pdhctx == NULL) {
        US_ERR("invalid: dh ctx is NULL.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (p != NULL) {
        switch (pdhctx->kdf_type) {
            case PROV_DH_KDF_NONE:
                kdf_type = "";
                break;
            case PROV_DH_KDF_X9_42_ASN1:
                kdf_type = OSSL_KDF_NAME_X942KDF_ASN1;
                break;
            default:
                US_ERR("invalid kdf_type.");
                return KAE_P_FAIL;
        }

        if (!OSSL_PARAM_set_utf8_string(p, kdf_type)) {
            US_ERR("failed to set utf8 string for kdf_type.");
            return KAE_P_FAIL;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdhctx->kdf_md == NULL ? "" : EVP_MD_get0_name(pdhctx->kdf_md))) {
        US_ERR("failed to set kdf_md.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pdhctx->kdf_outlen)) {
        US_ERR("failed to set kdf_outlen.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, pdhctx->kdf_ukm, pdhctx->kdf_ukmlen)) {
        US_ERR("failed to set kdf_ukm.");
        return KAE_P_FAIL;
    }

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_CEK_ALG);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdhctx->kdf_cekalg == NULL ? "" : pdhctx->kdf_cekalg)) {
        US_ERR("failed to set kdf_cekalg.");
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *kae_keyexch_dh_gettable_ctx_params(ossl_unused void *dhctx, ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}