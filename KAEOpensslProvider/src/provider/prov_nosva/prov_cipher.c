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

#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

#include "prov.h"
#include "prov_cipher.h"
#include "../../adapter/common/kae_log.h"
#include "../../adapter/nosva/algorithm/cipher/sec_ciphers_utils.h"

EVP_CIPHER *get_default_soft_cipher(int nid)
{
    EVP_CIPHER *cipher;
    switch (nid) {
        case NID_aes_128_cbc:
            cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", "provider=default");
            break;
        case NID_aes_192_cbc:
            cipher = EVP_CIPHER_fetch(NULL, "AES-192-CBC", "provider=default");
            break;
        case NID_aes_256_cbc:
            cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", "provider=default");
            break;
        case NID_aes_128_ecb:
            cipher = EVP_CIPHER_fetch(NULL, "AES-128-ECB", "provider=default");
            break;
        case NID_aes_192_ecb:
            cipher = EVP_CIPHER_fetch(NULL, "AES-192-ECB", "provider=default");
            break;
        case NID_aes_256_ecb:
            cipher = EVP_CIPHER_fetch(NULL, "AES-256-ECB", "provider=default");
            break;
        case NID_sm4_cbc:
            cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", "provider=default");
            break;
        case NID_sm4_ecb:
            cipher = EVP_CIPHER_fetch(NULL, "SM4-ECB", "provider=default");
            break;
        case NID_des_ede3_cbc:
            cipher = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", "provider=default");
            break;
        case NID_des_ede3_ecb:
            cipher = EVP_CIPHER_fetch(NULL, "DES-EDE3-ECB", "provider=default");
            break;
        case NID_aes_128_ctr:
            cipher = EVP_CIPHER_fetch(NULL, "AES-128-CTR", "provider=default");
            break;
        case NID_aes_192_ctr:
            cipher = EVP_CIPHER_fetch(NULL, "AES-192-CTR", "provider=default");
            break;
        case NID_aes_256_ctr:
            cipher = EVP_CIPHER_fetch(NULL, "AES-256-CTR", "provider=default");
            break;
        case NID_aes_128_ofb128:
            cipher = EVP_CIPHER_fetch(NULL, "AES-128-OFB", "provider=default");
            break;
        case NID_aes_192_ofb128:
            cipher = EVP_CIPHER_fetch(NULL, "AES-192-OFB", "provider=default");
            break;
        case NID_aes_256_ofb128:
            cipher = EVP_CIPHER_fetch(NULL, "AES-256-OFB", "provider=default");
            break;
        case NID_aes_128_cfb128:
            cipher = EVP_CIPHER_fetch(NULL, "AES-128-CFB", "provider=default");
            break;
        case NID_aes_192_cfb128:
            cipher = EVP_CIPHER_fetch(NULL, "AES-192-CFB", "provider=default");
            break;
        case NID_aes_256_cfb128:
            cipher = EVP_CIPHER_fetch(NULL, "AES-256-CFB", "provider=default");
            break;
        case NID_sm4_ofb128:
            cipher = EVP_CIPHER_fetch(NULL, "SM4-OFB", "provider=default");
            break;
        case NID_sm4_cfb128:
            cipher = EVP_CIPHER_fetch(NULL, "SM4-CFB", "provider=default");
            break;
        case NID_sm4_ctr:
            cipher = EVP_CIPHER_fetch(NULL, "SM4-CTR", "provider=default");
            break;
        case NID_aes_128_xts:
            cipher = EVP_CIPHER_fetch(NULL, "AES-128-XTS", "provider=default");
            break;
        case NID_aes_256_xts:
            cipher = EVP_CIPHER_fetch(NULL, "AES-256-XTS", "provider=default");
            break;
        default:
            US_ERR("invalid: kae unsupport digest cipher nid.");
            cipher = NULL;
            break;
    }

    return cipher;
}

int ciphers_sw_impl_init(cipher_priv_ctx *priv, const unsigned char *key, const unsigned char *iv, int enc)
{
    if (!priv->sw_ctx)
        priv->sw_ctx = EVP_CIPHER_CTX_new();
    if (!priv->sw_ctx) {
        US_ERR("new soft cipher ctx failed.");
        return OPENSSL_FAIL;
    }

    if (unlikely(priv->sw_cipher == NULL)) {
        US_ERR("get openssl software cipher failed. nid = %d", priv->nid);
        return OPENSSL_FAIL;
    }

    // if (!EVP_CipherInit_ex2(priv->sw_ctx, priv->sw_cipher, key, iv, priv->encrypt, NULL)) {
    //     US_ERR("soft cipher init failed.");
    //     return OPENSSL_FAIL;
    // }

    return OPENSSL_SUCCESS;
}

static void init_soft_cipher_ctx(cipher_priv_ctx *priv, const unsigned char *key, const unsigned char *iv)
{
    if (!priv->sw_cipher)
        priv->sw_cipher = get_default_soft_cipher(priv->nid);
    ciphers_sw_impl_init(priv, key, iv, priv->encrypt);
}

static int kae_cipher_einit(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;
    int ret;

    if (!vctx)
        return KAE_P_FAIL;

    priv->encrypt = 1;

    ret = sec_ciphers_init_priv_ctx(priv, key, keylen, iv, ivlen);
    if (!ret) {
        US_ERR("sec cipher init ctx failed.");
    }

    if (priv->c_mode == XTS && priv->ecb_encryto) {
        if (priv->ecb_encryto->key2_len == 32) {  // 256-xts key2len is 32
            priv->ecb_encryto->cipher_type = get_default_soft_cipher(NID_aes_256_ecb);
        } else {
            priv->ecb_encryto->cipher_type = get_default_soft_cipher(NID_aes_128_ecb);
        }
    }

    init_soft_cipher_ctx(priv, key, iv);

    return ret;
}

static int kae_cipher_dinit(void *vctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;
    int ret;

    if (!vctx) {
        US_ERR("invalid: cipher ctx failed.");
        return KAE_P_FAIL;
    }

    priv->encrypt = 0;

    ret = sec_ciphers_init_priv_ctx(priv, key, keylen, iv, ivlen);
    if (!ret) {
        US_ERR("sec cipher init ctx failed.");
    }

    if (priv->c_mode == XTS && priv->ecb_encryto) {
        if (priv->ecb_encryto->key2_len == 32) {  // 256-xts key2len is 32
            priv->ecb_encryto->cipher_type = get_default_soft_cipher(NID_aes_256_ecb);
        } else {
            priv->ecb_encryto->cipher_type = get_default_soft_cipher(NID_aes_128_ecb);
        }
    }

    init_soft_cipher_ctx(priv, key, iv);

    return ret;
}

static int prov_cipher_soft_update(
    cipher_priv_ctx *priv, unsigned char *out, int *outl, const unsigned char *in, size_t len)
{
    if (!priv->sw_cipher) {
        US_ERR("invalid: soft cipher is NULL.");
        return KAE_P_FAIL;
    }

    if (!EVP_CipherInit_ex2(priv->sw_ctx, priv->sw_cipher, priv->key, priv->iv, priv->encrypt, NULL)) {
        US_ERR("soft cipher init failed.");
        return KAE_P_FAIL;
    }
    // priv->sw_init = 1;

    if (!EVP_CipherUpdate(priv->sw_ctx, out, outl, in, len)) {
        US_ERR("soft cipher update failed.");
        return KAE_P_FAIL;
    }
    EVP_CIPHER_CTX_get_updated_iv(priv->sw_ctx, priv->iv, priv->iv_len);
    priv->sw_update = 1;

    return KAE_P_SUCCESS;
}

/*
 * Fills the buffer with trailing data from an encryption/decryption that didn't
 * fit into a full block.
 */
static int ossl_cipher_trailingdata(
    unsigned char *buf, size_t *buflen, size_t blocksize, const unsigned char **in, size_t *inlen)
{
    if (*inlen == 0)
        return KAE_P_SUCCESS;

    if (*buflen + *inlen > blocksize) {
        return KAE_P_FAIL;
    }

    memcpy(buf + *buflen, *in, *inlen);
    *buflen += *inlen;
    *inlen = 0;

    return KAE_P_SUCCESS;
}

static size_t ossl_cipher_fillblock(
    unsigned char *buf, size_t *buflen, size_t blocksize, const unsigned char **in, size_t *inlen)
{
    size_t blockmask = ~(blocksize - 1);
    size_t bufremain = blocksize - *buflen;

    if (*inlen < bufremain)
        bufremain = *inlen;
    memcpy(buf + *buflen, *in, bufremain);
    *in += bufremain;
    *inlen -= bufremain;
    *buflen += bufremain;

    return *inlen & blockmask;
}

static int prov_do_cipher(
    cipher_priv_ctx *priv, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inlen)
{
    size_t blksz = priv->blk_size;
    size_t nextblocks;
    int outlint = 0;
    int ret;

    if (priv->buf_size != 0)
        nextblocks = ossl_cipher_fillblock(priv->buf, &priv->buf_size, blksz, &in, &inlen);
    else
        nextblocks = inlen & ~(blksz - 1);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (priv->buf_size == blksz && (priv->encrypt || inlen > 0 || !priv->pad)) {
        ret = sec_ciphers_do_cipher(priv, out, outsize, priv->buf, blksz);
        if (ret != KAE_P_SUCCESS) {
            if (priv->sw_cipher)
                goto do_soft;
            return ret;
        }

        priv->buf_size = 0;
        outlint = blksz;
        out += blksz;
    }

    if (nextblocks == 0)
        goto out;

    if (!priv->encrypt && priv->pad && nextblocks == inlen)
        nextblocks -= blksz;

    if (nextblocks > 0) {
        ret = sec_ciphers_do_cipher(priv, out, outsize, in, nextblocks);
        if (ret != KAE_P_SUCCESS) {
            if (priv->sw_cipher)
                goto do_soft;
            return ret;
        }

        outlint += nextblocks;
        in += nextblocks;
        inlen -= nextblocks;
    }
out:
    if (inlen != 0 && !ossl_cipher_trailingdata(priv->buf, &priv->buf_size, blksz, &in, &inlen))
        return KAE_P_FAIL;

    *outl = outlint;
    return inlen == 0;

do_soft:
    US_WARN("kae cipher update failed, switch to soft.");
    ret = prov_cipher_soft_update(priv, out, &outlint, in, inlen);
    if (!ret) {
        return OPENSSL_FAIL;
    }

    if (!priv->encrypt) {
        in += nextblocks;
        inlen -= nextblocks;
        if (!ossl_cipher_trailingdata(priv->buf, &priv->buf_size, blksz, &in, &inlen)){
            return KAE_P_FAIL;
        }
    }

    *outl = outlint;
    return KAE_P_SUCCESS;
}

static int kae_cipher_block_update(
    void *vctx, unsigned char *output, size_t *outl, size_t outsize, const unsigned char *input, size_t inl)
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;

    if (!vctx || !input || !output || !outl)
        return KAE_P_FAIL;

    if (inl == 0) {
        *outl = 0;
        return KAE_P_SUCCESS;
    }

    if (outsize < inl) {
        US_ERR("invalid: outsize is less than inlen.");
        return KAE_P_FAIL;
    }

    return prov_do_cipher(priv, output, outl, outsize, input, inl);
}

static int kae_cipher_stream_update(
    void *vctx, unsigned char *output, size_t *outl, size_t outsize, const unsigned char *input, size_t inl)
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;
    int len = 0;
    int ret;

    if (!vctx || !outl || !input || !output) {
        US_ERR("invaild: cipher ctx or outlen or input or output is NULL.");
        return KAE_P_FAIL;
    }

    if (inl == 0) {
        *outl = 0;
        US_ERR("invalid: inlen is zero.");
        return KAE_P_SUCCESS;
    }

    if (outsize < inl) {
        US_ERR("invalid: outsize is less than inlen.");
        return KAE_P_FAIL;
    }

    ret = sec_ciphers_do_cipher(priv, output, outsize, input, inl);
    if (ret == KAE_CRYPTO_FAIL) {
        if (priv->sw_cipher)
            goto do_soft;
    }
    if (ret != KAE_P_SUCCESS) {
        US_ERR("cipher update failed.");
        return ret;
    }

    *outl = inl;
    return KAE_P_SUCCESS;

do_soft:
    US_WARN("sec cipher update failed, switch to soft.");
    /* have isseu if both using hw and soft partly */
    ret = prov_cipher_soft_update(priv, output, &len, input, inl);
    if (ret) {
        *outl = len;
        return KAE_P_SUCCESS;
    }

    US_ERR("cipher update failed.");
    return KAE_P_FAIL;
}

/* Pad the final block for encryption */
void ossl_cipher_padblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
    size_t i;
    unsigned char pad = (unsigned char)(blocksize - *buflen);

    for (i = *buflen; i < blocksize; i++)
        buf[i] = pad;
}

static int prov_cipher_soft_final(cipher_priv_ctx *priv, unsigned char *out, size_t *outl)
{
    int sw_final_len = 0;

    if (!priv->sw_update) {
        US_ERR("invalid: soft cipher is NULL.");
        return KAE_P_FAIL;
    }

    // if (!EVP_CipherInit_ex2(priv->sw_ctx, priv->sw_cipher, priv->key, priv->iv, priv->encrypt, NULL)) {
    //     US_ERR("soft cipher init failed.");
    //     return KAE_P_FAIL;
    // }

    if (!EVP_CipherFinal_ex(priv->sw_ctx, out, &sw_final_len)) {
        US_WARN("soft cipher final failed.");
        return KAE_P_FAIL;
    }

    *outl = sw_final_len;

    return KAE_P_SUCCESS;
}

static int kae_cipher_block_encrypto(cipher_priv_ctx *priv, unsigned char *out, size_t *outl, size_t outsize)
{
    size_t blksz = priv->blk_size;
    int ret;

    if (priv->pad) {
        ossl_cipher_padblock(priv->buf, &priv->buf_size, blksz);
    } else if (priv->buf_size == 0) {
        *outl = 0;
        return KAE_P_SUCCESS;
    } else if (priv->buf_size != blksz) {
        US_ERR("invalid: buf size is not equal to block size.");
        return KAE_P_FAIL;
    }

    if (outsize < blksz) {
        US_ERR("invalid: outsize is less than ");
        return KAE_P_FAIL;
    }

    ret = sec_ciphers_do_cipher(priv, out, outsize, priv->buf, blksz);
    if (ret != KAE_P_SUCCESS) {
        // kae_memcpy(priv->sw_ctx->buf, priv->buf, priv->blk_size);
        US_WARN("sec cipher failed, switch to soft.");
        return prov_cipher_soft_final(priv, out, outl);
    }

    *outl = blksz;

    return KAE_P_SUCCESS;
}

static int ossl_cipher_unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
    size_t len = *buflen;
    size_t pad, i;

    if (len != blocksize) {
        return KAE_P_FAIL;
    }

    /*
     * The following assumes that the ciphertext has been authenticated.
     * Otherwise it provides a padding oracle.
     */
    pad = buf[blocksize - 1];
    if (pad == 0 || pad > blocksize) {
        return KAE_P_FAIL;
    }
    for (i = 0; i < pad; i++) {
        if (buf[--len] != pad) {
            return KAE_P_FAIL;
        }
    }
    *buflen = len;

    return KAE_P_SUCCESS;
}

static int kae_cipher_block_decrypto(cipher_priv_ctx *priv, unsigned char *out, size_t *outl, size_t outsize)
{
    int ret;

    /* Dec should handle last blk since pad */
    if (priv->buf_size != priv->blk_size) {
        if (priv->buf_size == 0 && !priv->pad) {
            *outl = 0;
            return KAE_P_SUCCESS;
        }
        US_ERR("kae cipher block decrypto failed.");
        return KAE_P_FAIL;
    }

    ret = sec_ciphers_do_cipher(priv, priv->buf, outsize, priv->buf, priv->blk_size);
    if (ret != KAE_P_SUCCESS) {
        US_WARN("sec cipher failed, switch to soft.");
        return prov_cipher_soft_final(priv, out, outl);
    }

    if (priv->pad && !ossl_cipher_unpadblock(priv->buf, &priv->buf_size, priv->blk_size)) {
        /* ERR_raise already called */
        return KAE_P_FAIL;
    }

    if (outsize < priv->buf_size) {
        US_ERR("invalid: out size is less than buf size.");
        return KAE_P_FAIL;
    }

    memcpy(out, priv->buf, priv->buf_size);
    *outl = priv->buf_size;
    priv->buf_size = 0;

    return KAE_P_SUCCESS;
}

static int kae_cipher_block_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;
    int ret;

    if (!vctx || !out || !outl) {
        US_ERR("cipher ctx or out or out len is NULL.");
        return KAE_P_FAIL;
    }

    if (priv->encrypt)
        ret = kae_cipher_block_encrypto(priv, out, outl, outsize);
    else
        ret = kae_cipher_block_decrypto(priv, out, outl, outsize);

    return ret;
}

static int kae_cipher_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    if (!vctx || !out || !outl) {
        US_ERR("invalid: cipher ctx or out or out len is NULL.");
        return KAE_P_FAIL;
    }

    *outl = 0;

    return KAE_P_SUCCESS;
}

static int kae_cipher_cipher(
    void *vctx, unsigned char *output, size_t *outl, size_t outsize, const unsigned char *input, size_t inl)
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;
    int ret;

    if (!vctx || !output || !input || !outl) {
        US_ERR("cipher ctx or output or input or out len is NULL.");
        return KAE_P_FAIL;
    }

    if (inl == 0) {
        *outl = 0;
        return KAE_P_SUCCESS;
    }

    if (outsize < inl) {
        US_ERR("invalid: out size is less than in len.");
        return KAE_P_FAIL;
    }

    ret = prov_do_cipher(priv, output, outl, outsize, input, inl);
    if (ret != KAE_P_SUCCESS) {
        US_ERR("kae cipher failed.");
        return ret;
    }

    *outl = inl;

    return KAE_P_SUCCESS;
}

static void kae_cipher_freectx(void *dctx)
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)dctx;

    if (priv == NULL)
        return;

    if (priv->sw_cipher)
        EVP_CIPHER_free(priv->sw_cipher);

    if (priv->sw_ctx)
        EVP_CIPHER_CTX_free(priv->sw_ctx);

    sec_ciphers_priv_ctx_cleanup(priv);

    OPENSSL_clear_free(priv, sizeof(*priv));
}

int prov_cipher_generic_get_params(
    OSSL_PARAM params[], unsigned int md, uint64_t flags, size_t kbits, size_t blkbits, size_t ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }

    return KAE_P_SUCCESS;
}

static const OSSL_PARAM prov_cipher_known_gettable_params[] = {OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *kae_cipher_gettable_params(ossl_unused void *provctx)
{
    return prov_cipher_known_gettable_params;
}

static int kae_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;
    OSSL_PARAM *p;

    if (!vctx || !params)
        return KAE_P_FAIL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, priv->key_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, priv->iv_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, priv->pad)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, priv->iv, priv->iv_len) &&
        !OSSL_PARAM_set_octet_ptr(p, &priv->iv, priv->iv_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, priv->iv, priv->iv_len) &&
        !OSSL_PARAM_set_octet_ptr(p, &priv->iv, priv->iv_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return KAE_P_FAIL;
    }
    // p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS_MODE);
    // if (p != NULL) {
    // 	const char *name = ossl_cipher_cbc_cts_mode_id2name(priv->c_mode);

    // 	if (name == NULL || !OSSL_PARAM_set_utf8_string(p, name)) {
    // 		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
    // 		return KAE_P_FAIL;
    // 	}
    // }
    return KAE_P_SUCCESS;
}

static const OSSL_PARAM prov_default_ctx_params[] = {OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *kae_cipher_gettable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return prov_default_ctx_params;
}

static int kae_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    cipher_priv_ctx *priv = (cipher_priv_ctx *)vctx;
    const OSSL_PARAM *p;

    if (!vctx)
        return KAE_P_FAIL;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return KAE_P_FAIL;
        }
        priv->pad = pad ? 1 : 0;
        // EVP_CIPHER_CTX_set_padding(priv->sw_ctx, pad);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return KAE_P_FAIL;
        }
        if (priv->key_len != keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return KAE_P_FAIL;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t ivlen;

        if (!OSSL_PARAM_get_size_t(p, &ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return KAE_P_FAIL;
        }
        if (priv->iv_len != ivlen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return KAE_P_FAIL;
        }
    }

    // p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
    // if (p != NULL) {
    // 	int id;

    // 	if (p->data_type != OSSL_PARAM_UTF8_STRING) {
    // 		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
    // 		return KAE_P_FAIL;
    // 	}

    // 	id = ossl_cipher_cbc_cts_mode_name2id(p->data);
    // 	if (id < 0) {
    // 		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
    // 		return KAE_P_FAIL;
    // 	}

    // 	priv->c_mode = (unsigned int)id;
    // 	// priv->setup.mode = priv->c_mode;
    // 	// strncpy(priv->alg_name, cts_modes[id - WD_CIPHER_CBC_CS1].kae_alg_name,
    // 	// 	ALG_NAME_SIZE - 1);
    // }

    return KAE_P_SUCCESS;
}

static const OSSL_PARAM prov_settable_ctx_params[] = {OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
    OSSL_PARAM_END};

const OSSL_PARAM *kae_cipher_settable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
    return prov_settable_ctx_params;
}
