/*
 * Copyright 2026 Huawei Technologies Co.,Ltd.All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <openssl/provider.h>
#include <string.h>
#include "prov_pkey.h"

#define COPY_FN(group, name, field) \
    case OSSL_FUNC_##group: dst->field = OSSL_FUNC_##name(fn); break

static void copy_keymgmt(KAE_PKEY_KEYMGMT *dst, const OSSL_DISPATCH *fn)
{
    switch (fn->function_id) {
        COPY_FN(KEYMGMT_NEW, keymgmt_new, new_fun);
        COPY_FN(KEYMGMT_FREE, keymgmt_free, free);
        COPY_FN(KEYMGMT_GET_PARAMS, keymgmt_get_params, get_params);
        COPY_FN(KEYMGMT_GETTABLE_PARAMS, keymgmt_gettable_params, gettable_params);
        COPY_FN(KEYMGMT_SET_PARAMS, keymgmt_set_params, set_params);
        COPY_FN(KEYMGMT_SETTABLE_PARAMS, keymgmt_settable_params, settable_params);
        COPY_FN(KEYMGMT_GEN_INIT, keymgmt_gen_init, gen_init);
        COPY_FN(KEYMGMT_GEN_SET_TEMPLATE, keymgmt_gen_set_template, gen_set_template);
        COPY_FN(KEYMGMT_GEN_SET_PARAMS, keymgmt_gen_set_params, gen_set_params);
        COPY_FN(KEYMGMT_GEN_SETTABLE_PARAMS, keymgmt_gen_settable_params, gen_settable_params);
        COPY_FN(KEYMGMT_GEN, keymgmt_gen, gen);
        COPY_FN(KEYMGMT_GEN_CLEANUP, keymgmt_gen_cleanup, gen_cleanup);
        COPY_FN(KEYMGMT_LOAD, keymgmt_load, load);
        COPY_FN(KEYMGMT_QUERY_OPERATION_NAME, keymgmt_query_operation_name, query_operation_name);
        COPY_FN(KEYMGMT_HAS, keymgmt_has, has);
        COPY_FN(KEYMGMT_VALIDATE, keymgmt_validate, validate);
        COPY_FN(KEYMGMT_MATCH, keymgmt_match, match);
        COPY_FN(KEYMGMT_IMPORT, keymgmt_import, import);
        COPY_FN(KEYMGMT_IMPORT_TYPES, keymgmt_import_types, import_types);
        COPY_FN(KEYMGMT_EXPORT, keymgmt_export, export_fun);
        COPY_FN(KEYMGMT_EXPORT_TYPES, keymgmt_export_types, export_types);
        COPY_FN(KEYMGMT_DUP, keymgmt_dup, dup);
    }
}

static void copy_signature(KAE_PKEY_SIGNATURE *dst, const OSSL_DISPATCH *fn)
{
    switch (fn->function_id) {
        COPY_FN(SIGNATURE_NEWCTX, signature_newctx, newctx);
        COPY_FN(SIGNATURE_SIGN_INIT, signature_sign_init, sign_init);
        COPY_FN(SIGNATURE_SIGN, signature_sign, sign);
        COPY_FN(SIGNATURE_VERIFY_INIT, signature_verify_init, verify_init);
        COPY_FN(SIGNATURE_VERIFY, signature_verify, verify);
        COPY_FN(SIGNATURE_VERIFY_RECOVER_INIT, signature_verify_recover_init, verify_recover_init);
        COPY_FN(SIGNATURE_VERIFY_RECOVER, signature_verify_recover, verify_recover);
        COPY_FN(SIGNATURE_DIGEST_SIGN_INIT, signature_digest_sign_init, digest_sign_init);
        COPY_FN(SIGNATURE_DIGEST_SIGN_UPDATE, signature_digest_sign_update, digest_sign_update);
        COPY_FN(SIGNATURE_DIGEST_SIGN_FINAL, signature_digest_sign_final, digest_sign_final);
        COPY_FN(SIGNATURE_DIGEST_SIGN, signature_digest_sign, digest_sign);
        COPY_FN(SIGNATURE_DIGEST_VERIFY_INIT, signature_digest_verify_init, digest_verify_init);
        COPY_FN(SIGNATURE_DIGEST_VERIFY_UPDATE, signature_digest_verify_update, digest_verify_update);
        COPY_FN(SIGNATURE_DIGEST_VERIFY_FINAL, signature_digest_verify_final, digest_verify_final);
        COPY_FN(SIGNATURE_DIGEST_VERIFY, signature_digest_verify, digest_verify);
        COPY_FN(SIGNATURE_FREECTX, signature_freectx, freectx);
        COPY_FN(SIGNATURE_DUPCTX, signature_dupctx, dupctx);
        COPY_FN(SIGNATURE_GET_CTX_PARAMS, signature_get_ctx_params, get_ctx_params);
        COPY_FN(SIGNATURE_GETTABLE_CTX_PARAMS, signature_gettable_ctx_params, gettable_ctx_params);
        COPY_FN(SIGNATURE_SET_CTX_PARAMS, signature_set_ctx_params, set_ctx_params);
        COPY_FN(SIGNATURE_SETTABLE_CTX_PARAMS, signature_settable_ctx_params, settable_ctx_params);
        COPY_FN(SIGNATURE_GET_CTX_MD_PARAMS, signature_get_ctx_md_params, get_ctx_md_params);
        COPY_FN(SIGNATURE_GETTABLE_CTX_MD_PARAMS, signature_gettable_ctx_md_params, gettable_ctx_md_params);
        COPY_FN(SIGNATURE_SET_CTX_MD_PARAMS, signature_set_ctx_md_params, set_ctx_md_params);
        COPY_FN(SIGNATURE_SETTABLE_CTX_MD_PARAMS, signature_settable_ctx_md_params, settable_ctx_md_params);
    }
}

static void copy_asym_cipher(KAE_PKEY_ASYM_CIPHER *dst, const OSSL_DISPATCH *fn)
{
    switch (fn->function_id) {
        COPY_FN(ASYM_CIPHER_NEWCTX, asym_cipher_newctx, newctx);
        COPY_FN(ASYM_CIPHER_ENCRYPT_INIT, asym_cipher_encrypt_init, encrypt_init);
        COPY_FN(ASYM_CIPHER_ENCRYPT, asym_cipher_encrypt, encrypt);
        COPY_FN(ASYM_CIPHER_DECRYPT_INIT, asym_cipher_decrypt_init, decrypt_init);
        COPY_FN(ASYM_CIPHER_DECRYPT, asym_cipher_decrypt, decrypt);
        COPY_FN(ASYM_CIPHER_FREECTX, asym_cipher_freectx, freectx);
        COPY_FN(ASYM_CIPHER_DUPCTX, asym_cipher_dupctx, dupctx);
        COPY_FN(ASYM_CIPHER_GET_CTX_PARAMS, asym_cipher_get_ctx_params, get_ctx_params);
        COPY_FN(ASYM_CIPHER_GETTABLE_CTX_PARAMS, asym_cipher_gettable_ctx_params, gettable_ctx_params);
        COPY_FN(ASYM_CIPHER_SET_CTX_PARAMS, asym_cipher_set_ctx_params, set_ctx_params);
        COPY_FN(ASYM_CIPHER_SETTABLE_CTX_PARAMS, asym_cipher_settable_ctx_params, settable_ctx_params);
    }
}

static void copy_keyexch(KAE_PKEY_KEYEXCH *dst, const OSSL_DISPATCH *fn)
{
    switch (fn->function_id) {
        COPY_FN(KEYEXCH_NEWCTX, keyexch_newctx, newctx);
        COPY_FN(KEYEXCH_INIT, keyexch_init, init);
        COPY_FN(KEYEXCH_SET_PEER, keyexch_set_peer, set_peer);
        COPY_FN(KEYEXCH_DERIVE, keyexch_derive, derive);
        COPY_FN(KEYEXCH_FREECTX, keyexch_freectx, freectx);
        COPY_FN(KEYEXCH_DUPCTX, keyexch_dupctx, dupctx);
        COPY_FN(KEYEXCH_GET_CTX_PARAMS, keyexch_get_ctx_params, get_ctx_params);
        COPY_FN(KEYEXCH_GETTABLE_CTX_PARAMS, keyexch_gettable_ctx_params, gettable_ctx_params);
        COPY_FN(KEYEXCH_SET_CTX_PARAMS, keyexch_set_ctx_params, set_ctx_params);
        COPY_FN(KEYEXCH_SETTABLE_CTX_PARAMS, keyexch_settable_ctx_params, settable_ctx_params);
    }
}

static int has_name(const char *names, const char *name)
{
    size_t len = strlen(name);

    while (*names) {
        size_t n = strcspn(names, ":");
        if (n == len && OPENSSL_strncasecmp(names, name, n) == 0)
            return 1;
        names += n;
        if (*names)
            names++;
    }
    return 0;
}

int kae_copy_pkey_dispatch(void *dst, const OSSL_PROVIDER *provider,
    int operation, const char *algorithm)
{
    const OSSL_ALGORITHM *algs, *alg;
    const OSSL_DISPATCH *fn;
    int no_cache = 0, found = 0;

    algs = OSSL_PROVIDER_query_operation(provider, operation, &no_cache);
    if (algs == NULL)
        return 0;
    for (alg = algs; alg->algorithm_names != NULL; alg++) {
        if (!has_name(alg->algorithm_names, algorithm))
            continue;
        for (fn = alg->implementation; fn->function_id != 0; fn++) {
            if (operation == OSSL_OP_KEYMGMT)
                copy_keymgmt(dst, fn);
            else if (operation == OSSL_OP_SIGNATURE)
                copy_signature(dst, fn);
            else if (operation == OSSL_OP_ASYM_CIPHER)
                copy_asym_cipher(dst, fn);
            else if (operation == OSSL_OP_KEYEXCH)
                copy_keyexch(dst, fn);
        }
        if (operation == OSSL_OP_KEYMGMT)
            ((KAE_PKEY_KEYMGMT *)dst)->prov = (OSSL_PROVIDER *)provider;
        else if (operation == OSSL_OP_SIGNATURE)
            ((KAE_PKEY_SIGNATURE *)dst)->prov = (OSSL_PROVIDER *)provider;
        else if (operation == OSSL_OP_ASYM_CIPHER)
            ((KAE_PKEY_ASYM_CIPHER *)dst)->prov = (OSSL_PROVIDER *)provider;
        else if (operation == OSSL_OP_KEYEXCH)
            ((KAE_PKEY_KEYEXCH *)dst)->prov = (OSSL_PROVIDER *)provider;
        found = 1;
        break;
    }
    OSSL_PROVIDER_unquery_operation(provider, operation, algs);
    return found;
}
