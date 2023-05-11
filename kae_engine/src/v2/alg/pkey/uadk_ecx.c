/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
#include <string.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "v2/alg/pkey/uadk_pkey.h"
#include "v2/uadk.h"

#define X25519_KEYLEN		32
#define X448_KEYLEN		56
#define X25519_KEYBITS		256
#define X448_KEYBITS		448
#define ECX_MAX_KEYLEN		57
#define UADK_E_SUCCESS		1
#define UADK_E_FAIL		0

struct ecx_key {
	unsigned char pubkey[ECX_MAX_KEYLEN];
	unsigned char *privkey;
};

struct ecx_ctx {
	handle_t sess;
	int key_size;
	int nid;
};

static int reverse_bytes(unsigned char *to_buf, unsigned int size)
{
	unsigned char *tmp_buf = to_buf + size - 1;
	unsigned char tmp;

	if (!size) {
		fprintf(stderr, "invalid size, size = %u\n", size);
		return UADK_E_FAIL;
	}

	if (!to_buf) {
		fprintf(stderr, "to_buf is NULL\n");
		return UADK_E_FAIL;
	}

	while (to_buf < tmp_buf) {
		tmp = *tmp_buf;
		*tmp_buf-- = *to_buf;
		*to_buf++ = tmp;
	}

	return UADK_E_SUCCESS;
}

static int x25519_init(EVP_PKEY_CTX *ctx)
{
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};
	struct ecx_ctx *x25519_ctx;
	int ret;

	ret = uadk_init_ecc();
	if (ret) {
		fprintf(stderr, "failed to uadk_init_ecc, ret = %d\n", ret);
		return UADK_E_FAIL;
	}

	x25519_ctx = malloc(sizeof(struct ecx_ctx));
	if (!x25519_ctx) {
		fprintf(stderr, "failed to alloc x25519 ctx\n");
		return UADK_E_FAIL;
	}
	memset(x25519_ctx, 0, sizeof(struct ecx_ctx));

	setup.alg = "x25519";
	setup.key_bits = X25519_KEYBITS;
	params.numa_id = uadk_e_ecc_get_numa_id();
	setup.sched_param = &params;
	x25519_ctx->sess = wd_ecc_alloc_sess(&setup);
	if (!x25519_ctx->sess) {
		fprintf(stderr, "failed to alloc sess\n");
		free(x25519_ctx);
		return UADK_E_FAIL;
	}

	EVP_PKEY_CTX_set_data(ctx, x25519_ctx);

	return UADK_E_SUCCESS;
}

static void x25519_uninit(EVP_PKEY_CTX *ctx)
{
	struct ecx_ctx *x25519_ctx = EVP_PKEY_CTX_get_data(ctx);

	if (!x25519_ctx)
		return;

	if (x25519_ctx->sess)
		wd_ecc_free_sess(x25519_ctx->sess);

	free(x25519_ctx);

	EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int x448_init(EVP_PKEY_CTX *ctx)
{
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};
	struct ecx_ctx *x448_ctx;
	int ret;

	ret = uadk_init_ecc();
	if (ret) {
		fprintf(stderr, "failed to do uadk_init_ecc, ret = %d\n", ret);
		return UADK_E_FAIL;
	}

	x448_ctx = malloc(sizeof(struct ecx_ctx));
	if (!x448_ctx) {
		fprintf(stderr, "failed to alloc x448 ctx\n");
	        return UADK_E_FAIL;
	}

	memset(x448_ctx, 0, sizeof(struct ecx_ctx));
	setup.alg = "x448";
	setup.key_bits = X448_KEYBITS;
	params.numa_id = uadk_e_ecc_get_numa_id();
	setup.sched_param = &params;
	x448_ctx->sess = wd_ecc_alloc_sess(&setup);
	if (!x448_ctx->sess) {
		fprintf(stderr, "failed to alloc sess\n");
		free(x448_ctx);
		return UADK_E_FAIL;
	}

	EVP_PKEY_CTX_set_data(ctx, x448_ctx);

	return UADK_E_SUCCESS;
}

static void x448_uninit(EVP_PKEY_CTX *ctx)
{
	struct ecx_ctx *x448_ctx = EVP_PKEY_CTX_get_data(ctx);

	if (!x448_ctx)
		return;

	if (x448_ctx->sess)
		wd_ecc_free_sess(x448_ctx->sess);

	free(x448_ctx);

	EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	if (type == EVP_PKEY_CTRL_PEER_KEY)
		return UADK_E_SUCCESS;

	return UADK_E_INVALID;
}

static int ecx_genkey_check(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	if (!ctx) {
		fprintf(stderr, "ctx is NULL\n");
		return UADK_E_FAIL;
	}

	if (!pkey) {
		fprintf(stderr, "pkey is NULL\n");
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int ecx_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecx_out;

	ecx_out = wd_ecxdh_new_out(sess);
	if (!ecx_out) {
		fprintf(stderr, "failed to new sign out\n");
		return UADK_E_FAIL;
	}

	uadk_ecc_fill_req(req, WD_ECXDH_GEN_KEY, NULL, ecx_out);

	return UADK_E_SUCCESS;
}

static int ecx_get_nid(EVP_PKEY_CTX *ctx)
{
	const EVP_PKEY_METHOD **pmeth_from_ctx;
	int nid;

	pmeth_from_ctx = (const EVP_PKEY_METHOD **)ctx;

	EVP_PKEY_meth_get0_info(&nid, NULL, *pmeth_from_ctx);
	if (nid != EVP_PKEY_X25519 && nid != EVP_PKEY_X448)
		return UADK_E_FAIL;

	return nid;
}

static int ecx_create_privkey(struct ecx_key **ecx_key, int key_size)
{
	unsigned char *privkey;
	int ret;

	*ecx_key = OPENSSL_zalloc(sizeof(struct ecx_key));
	if (!(*ecx_key)) {
		fprintf(stderr, "failed to alloc ecx_key\n");
		return UADK_E_FAIL;
	}

	privkey = OPENSSL_secure_malloc(key_size);
	if (!privkey) {
		fprintf(stderr, "failed to alloc private key\n");
		goto free_ecx_key;
	}

	ret = RAND_priv_bytes(privkey, key_size);
	if (ret <= 0) {
		fprintf(stderr, "failed to gen private key\n");
		goto free_pri;
	}

	(*ecx_key)->privkey = privkey;

	return UADK_E_SUCCESS;

free_pri:
	OPENSSL_secure_free(privkey);
free_ecx_key:
	OPENSSL_free(*ecx_key);

	return UADK_E_FAIL;
}

static int ecx_keygen_set_private_key(struct ecx_ctx *ecx_ctx,
				      struct ecx_key *ecx_key)
{
	handle_t sess = ecx_ctx->sess;
	struct wd_ecc_key *ecc_key;
	struct wd_dtb prikey;
	int ret;

	prikey.data = (char *)ecx_key->privkey;
	prikey.dsize = ecx_ctx->key_size;

	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int ecx_keygen_set_pkey(EVP_PKEY *pkey, struct ecx_ctx *ecx_ctx,
			       struct wd_ecc_req *req, struct ecx_key *ecx_key)
{
	struct wd_ecc_point *pubkey = NULL;
	int key_size = ecx_ctx->key_size;
	int ret;

	wd_ecxdh_get_out_params(req->dst, &pubkey);
	if (key_size > ECX_MAX_KEYLEN) {
		fprintf(stderr, "invalid key size, key_size = %d\n", key_size);
		return UADK_E_FAIL;
	}

	memcpy(ecx_key->pubkey, (const unsigned char *)pubkey->x.data,
	       key_size);
	/* Trans public key from big-endian to little-endian */
	ret = reverse_bytes(ecx_key->pubkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans public key\n");
		return UADK_E_FAIL;
	}
	/* Trans private key from big-endian to little-endian */
	ret = reverse_bytes(ecx_key->privkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_E_FAIL;
	}
	/*
	 * This is a pretreatment of X25519/X448 described in RFC 7748.
	 * In order to decode the random bytes as an integer scaler, there
	 * are some special data processing. And use little-endian mode for
	 * decoding.
	 */
	if (ecx_ctx->nid == EVP_PKEY_X25519) {
		/* Set the three LSB of the first byte to 0 */
		ecx_key->privkey[0] &= 0xF8;

		/* Set the MSB of the last byte to 0 */
		ecx_key->privkey[X25519_KEYLEN - 1] &= 0x7F;

		/* Set the second MSB of the last byte to 1 */
		ecx_key->privkey[X25519_KEYLEN - 1] |= 0x40;
	} else if (ecx_ctx->nid == EVP_PKEY_X448) {
		/* Set the two LSB of the first byte to 0 */
		ecx_key->privkey[0] &= 0xFC;

		/* Set the MSB of the last byte to 1 */
		ecx_key->privkey[X448_KEYLEN - 1] |= 0x80;
	}

	ret = EVP_PKEY_assign(pkey, ecx_ctx->nid, ecx_key);

	return ret;
}

static int openssl_do_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
			     size_t *keylen)
{
	int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
	const EVP_PKEY_METHOD *sw_ecx_method;
	int nid = ecx_get_nid(ctx);

	sw_ecx_method = EVP_PKEY_meth_find(nid);
	if (!sw_ecx_method) {
		fprintf(stderr, "failed to get software method\n");
		return UADK_E_FAIL;
	}

	EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_ecx_method, NULL,
				 &sw_fn_ptr);

	return (*sw_fn_ptr)(ctx, key, keylen);
}

static int openssl_do_ecx_genkey(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	int (*sw_fn_ptr)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
	const EVP_PKEY_METHOD *sw_ecx_method;
	int nid = ecx_get_nid(ctx);

	sw_ecx_method = EVP_PKEY_meth_find(nid);
	if (!sw_ecx_method) {
                fprintf(stderr, "failed to get software method\n");
                return UADK_E_FAIL;
	}

	EVP_PKEY_meth_get_keygen((EVP_PKEY_METHOD *)sw_ecx_method, NULL,
				 &sw_fn_ptr);

	return (*sw_fn_ptr)(ctx, pkey);
}

static int x25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	struct ecx_ctx *keygen_ctx = NULL;
	struct ecx_key *ecx_key = NULL;
	struct wd_ecc_req req = {0};
	int ret;

	ret = ecx_genkey_check(ctx, pkey);
	if (!ret)
		goto do_soft;

	ret = x25519_init(ctx);
	if (!ret)
		goto do_soft;

	keygen_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (!keygen_ctx)
		goto do_soft;
	keygen_ctx->nid = EVP_PKEY_X25519;
	keygen_ctx->key_size = X25519_KEYLEN;

	ret = ecx_create_privkey(&ecx_key, keygen_ctx->key_size);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_keygen_init_iot(keygen_ctx->sess, &req);
	if (!ret)
		goto free_key;

	ret = ecx_keygen_set_private_key(keygen_ctx, ecx_key);
	if (!ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(keygen_ctx->sess, &req, (void *)keygen_ctx->sess);
	if (!ret)
		goto uninit_iot;

	ret = ecx_keygen_set_pkey(pkey, keygen_ctx, &req, ecx_key);
	if (!ret)
		goto uninit_iot;

	wd_ecc_del_out(keygen_ctx->sess, req.dst);
	x25519_uninit(ctx);

	return ret;

uninit_iot:
	wd_ecc_del_out(keygen_ctx->sess, req.dst);
free_key:
	OPENSSL_secure_free(ecx_key->privkey);
	OPENSSL_free(ecx_key);
uninit_ctx:
	x25519_uninit(ctx);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_ecx_genkey(ctx, pkey);
}

static int x448_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	struct ecx_ctx *keygen_ctx = NULL;
	struct ecx_key *ecx_key = NULL;
	struct wd_ecc_req req = {0};
	int ret;

	ret = ecx_genkey_check(ctx, pkey);
	if (!ret)
		goto do_soft;

	ret = x448_init(ctx);
	if (!ret)
		goto do_soft;

	keygen_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (!keygen_ctx)
		goto uninit_ctx;
	keygen_ctx->nid = EVP_PKEY_X448;
	keygen_ctx->key_size = X448_KEYLEN;

	ret = ecx_create_privkey(&ecx_key, keygen_ctx->key_size);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_keygen_init_iot(keygen_ctx->sess, &req);
	if (!ret)
		goto free_key;

	ret = ecx_keygen_set_private_key(keygen_ctx, ecx_key);
	if (!ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(keygen_ctx->sess, &req, (void *)keygen_ctx->sess);
	if (!ret)
		goto uninit_iot;

	ret = ecx_keygen_set_pkey(pkey, keygen_ctx, &req, ecx_key);
	if (!ret)
		goto uninit_iot;

	wd_ecc_del_out(keygen_ctx->sess, req.dst);
	x448_uninit(ctx);

	return ret;

uninit_iot:
	wd_ecc_del_out(keygen_ctx->sess, req.dst);
free_key:
	OPENSSL_secure_free(ecx_key->privkey);
	OPENSSL_free(ecx_key);
uninit_ctx:
	x448_uninit(ctx);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_ecx_genkey(ctx, pkey);
}

static int ecx_compkey_init_iot(struct ecx_ctx *ecx_ctx, struct wd_ecc_req *req,
				struct ecx_key *peer_ecx_key,
				struct ecx_key *ecx_key)
{
	int key_size = ecx_ctx->key_size;
	char buf_y[ECX_MAX_KEYLEN] = {0};
	handle_t sess = ecx_ctx->sess;
	struct wd_ecc_point in_pubkey;
	struct wd_ecc_out *ecx_out;
	struct wd_ecc_in *ecx_in;
	int ret;

	/* Trans public key from little-endian to big-endian */
	ret = reverse_bytes(peer_ecx_key->pubkey, key_size);
	if(!ret) {
		fprintf(stderr, "failed to trans public key\n");
		return UADK_E_FAIL;
	}

	in_pubkey.x.data = (char *)peer_ecx_key->pubkey;
	in_pubkey.x.dsize = key_size;
	in_pubkey.y.data = buf_y;
	in_pubkey.y.dsize = 1;

	ecx_in = wd_ecxdh_new_in(sess, &in_pubkey);
	if (!ecx_in) {
		fprintf(stderr, "failed to new ecxdh in\n");
		return UADK_E_FAIL;
	}

	ecx_out = wd_ecxdh_new_out(sess);
	if (!ecx_out) {
		fprintf(stderr, "failed to new ecxdh out\n");
		ret = UADK_E_FAIL;
		goto del_in;
	}

	uadk_ecc_fill_req(req, WD_ECXDH_COMPUTE_KEY, ecx_in, ecx_out);

	/* Trans public key from big-endian to little-endian */
	ret = reverse_bytes(peer_ecx_key->pubkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans public key\n");
		goto del_out;
	}

	return ret;

del_out:
	wd_ecc_del_out(sess, ecx_out);
del_in:
	wd_ecc_del_in(sess, ecx_in);

	return ret;
}

static void ecx_compkey_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_out(sess, req->dst);
	wd_ecc_del_in(sess, req->src);
}

static int ecx_derive_set_private_key(struct ecx_ctx *ecx_ctx,
				      struct ecx_key *ecx_key)
{
	int key_size = ecx_ctx->key_size;
	handle_t sess = ecx_ctx->sess;
	struct wd_ecc_key *ecc_key;
	struct wd_dtb prikey;
	int ret;

	/* Trans private key from little-endian to big-endian */
	ret = reverse_bytes(ecx_key->privkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_E_FAIL;
	}

	prikey.data = (char *)ecx_key->privkey;
	prikey.dsize = ecx_ctx->key_size;
	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		return UADK_E_FAIL;
	}

	/* Trans private key from big-endian to little-endian */
	ret = reverse_bytes(ecx_key->privkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int ecx_get_key(EVP_PKEY_CTX *ctx, struct ecx_key **ecx_key,
		       struct ecx_key **peer_ecx_key)
{
	EVP_PKEY *pkey, *peer_key;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (!pkey)
		return UADK_E_FAIL;

	peer_key = EVP_PKEY_CTX_get0_peerkey(ctx);
	if (!peer_key)
		return UADK_E_FAIL;

	*peer_ecx_key = EVP_PKEY_get0(peer_key);
	if (!(*peer_ecx_key))
		return UADK_E_FAIL;

	*ecx_key = EVP_PKEY_get0(pkey);
	if (!(*ecx_key))
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;
}

static void x25519_pad_out_key(unsigned char *dst_key, unsigned char *src_key,
			       size_t len)
{
	unsigned char x25519_pad_key[X25519_KEYLEN] = {0};

	if (len != X25519_KEYLEN) {
		memcpy(x25519_pad_key, src_key, len);
		memcpy(dst_key, x25519_pad_key, X25519_KEYLEN);
	} else {
		memcpy(dst_key, src_key, X25519_KEYLEN);
	}
}

/**
 * x25519_derive: generate shared key.
 * @ctx: the X25519 key ctx, contain own private key,
 * public key and peer public key.
 * @key: the output shared key.
 * @keylen: the length of output shared key.
 */
static int x25519_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
			 size_t *keylen)
{
	struct ecx_key *peer_ecx_key = NULL;
	struct wd_ecc_point *s_key = NULL;
	struct ecx_ctx *derive_ctx = NULL;
	struct ecx_key *ecx_key = NULL;
	struct wd_ecc_req req = {0};
	int ret;

	ret = x25519_init(ctx);
	if (!ret)
		goto do_soft;

	if (!key || !(*keylen)) {
		*keylen = (size_t) X25519_KEYLEN;
		x25519_uninit(ctx);
		return UADK_E_SUCCESS;
	}

	derive_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (!derive_ctx)
		goto uninit_ctx;
	derive_ctx->nid = EVP_PKEY_X25519;
	derive_ctx->key_size = X25519_KEYLEN;

	ret = ecx_get_key(ctx, &ecx_key, &peer_ecx_key);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_compkey_init_iot(derive_ctx, &req, peer_ecx_key, ecx_key);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_derive_set_private_key(derive_ctx, ecx_key);
	if (!ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(derive_ctx->sess, &req, (void *)derive_ctx);
	if (!ret)
		goto uninit_iot;

	wd_ecxdh_get_out_params(req.dst, &s_key);
	if (!s_key)
		goto uninit_iot;

	ret = reverse_bytes((unsigned char *)s_key->x.data, s_key->x.dsize);
	if (!ret)
		goto uninit_iot;

	x25519_pad_out_key(key, (unsigned char *)s_key->x.data, s_key->x.dsize);

	ecx_compkey_uninit_iot(derive_ctx->sess, &req);
	x25519_uninit(ctx);

	return ret;

uninit_iot:
	ecx_compkey_uninit_iot(derive_ctx->sess, &req);
uninit_ctx:
	x25519_uninit(ctx);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_derive(ctx, key, keylen);
}

static void x448_pad_out_key(unsigned char *dst_key, unsigned char *src_key,
			     size_t len)
{
	unsigned char x448_pad_key[X448_KEYLEN] = {0};

	if (len != X448_KEYLEN) {
		memcpy(x448_pad_key, src_key, len);
		memcpy(dst_key, x448_pad_key, X448_KEYLEN);
	} else {
		memcpy(dst_key, src_key, X448_KEYLEN);
	}
}

/**
 * x448_derive: generate shared key.
 * @ctx: the X448 key ctx, contain own private key,
 * public key and peer public key.
 * @key: the output shared key.
 * @keylen: the length of output shared key.
 */
static int x448_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
		       size_t *keylen)
{
	struct ecx_key *peer_ecx_key = NULL;
	struct wd_ecc_point *s_key = NULL;
	struct ecx_ctx *derive_ctx = NULL;
	struct ecx_key *ecx_key = NULL;
	struct wd_ecc_req req = {0};
	int ret;

	ret = x448_init(ctx);
	if (!ret)
		goto do_soft;

	if (!key || !(*keylen)) {
		*keylen = (size_t) X448_KEYLEN;
		x448_uninit(ctx);
		return UADK_E_SUCCESS;
	}

	derive_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (!derive_ctx)
		goto uninit_ctx;
	derive_ctx->nid = EVP_PKEY_X448;
	derive_ctx->key_size = X448_KEYLEN;

	ret = ecx_get_key(ctx, &ecx_key, &peer_ecx_key);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_compkey_init_iot(derive_ctx, &req, peer_ecx_key, ecx_key);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_derive_set_private_key(derive_ctx, ecx_key);
	if (!ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(derive_ctx->sess, &req, (void *)derive_ctx);
	if (!ret)
		goto uninit_iot;

	wd_ecxdh_get_out_params(req.dst, &s_key);
	if (!s_key)
		goto uninit_iot;

	ret = reverse_bytes((unsigned char *)s_key->x.data, s_key->x.dsize);
	if (!ret)
		goto uninit_iot;

	x448_pad_out_key(key, (unsigned char *)s_key->x.data, s_key->x.dsize);

	ecx_compkey_uninit_iot(derive_ctx->sess, &req);
	x448_uninit(ctx);

	return ret;

uninit_iot:
	ecx_compkey_uninit_iot(derive_ctx->sess, &req);
uninit_ctx:
	x448_uninit(ctx);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_derive(ctx, key, keylen);
}

int uadk_x25519_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	if (pkey_meth->x25519)
		return UADK_E_SUCCESS;

	meth = EVP_PKEY_meth_new(EVP_PKEY_X25519, 0);
	if (!meth) {
		fprintf(stderr, "failed to EVP_PKEY_meth_new\n");
		return UADK_E_FAIL;
	}

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_X25519);

	EVP_PKEY_meth_copy(meth, openssl_meth);

	if (!uadk_support_algorithm("x25519")) {
		pkey_meth->x25519 = meth;
		return UADK_E_SUCCESS;
	}

	EVP_PKEY_meth_set_ctrl(meth, ecx_ctrl, NULL);
	EVP_PKEY_meth_set_keygen(meth, NULL, x25519_keygen);
	EVP_PKEY_meth_set_derive(meth, NULL, x25519_derive);

	pkey_meth->x25519 = meth;

	return UADK_E_SUCCESS;
}

void uadk_x25519_delete_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	if (!pkey_meth || !pkey_meth->x25519)
		return;

	EVP_PKEY_meth_free(pkey_meth->x25519);
	pkey_meth->x25519 = NULL;
}

int uadk_x448_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	if (pkey_meth->x448)
		return UADK_E_SUCCESS;

	meth = EVP_PKEY_meth_new(EVP_PKEY_X448, 0);
	if (!meth) {
		fprintf(stderr, "failed to EVP_PKEY_meth_new\n");
		return UADK_E_FAIL;
	}

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_X448);

	EVP_PKEY_meth_copy(meth, openssl_meth);

	if (!uadk_support_algorithm("x448")) {
		pkey_meth->x448 = meth;
		return UADK_E_SUCCESS;
	}

	EVP_PKEY_meth_set_ctrl(meth, ecx_ctrl, NULL);
	EVP_PKEY_meth_set_keygen(meth, NULL, x448_keygen);
	EVP_PKEY_meth_set_derive(meth, NULL, x448_derive);

	pkey_meth->x448 = meth;

	return UADK_E_SUCCESS;
}

void uadk_x448_delete_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	if (!pkey_meth || !pkey_meth->x448)
		return;

	EVP_PKEY_meth_free(pkey_meth->x448);
	pkey_meth->x448 = NULL;
}
