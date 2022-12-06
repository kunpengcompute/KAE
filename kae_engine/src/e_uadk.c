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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/engine.h>
#include <uadk/wd.h>
#include "uadk.h"
#include "uadk_async.h"
#ifdef KAE
#include "v1/uadk_v1.h"
#endif

#define UADK_CMD_ENABLE_CIPHER_ENV	ENGINE_CMD_BASE
#define UADK_CMD_ENABLE_DIGEST_ENV	(ENGINE_CMD_BASE + 1)
#define UADK_CMD_ENABLE_RSA_ENV		(ENGINE_CMD_BASE + 2)
#define UADK_CMD_ENABLE_DH_ENV		(ENGINE_CMD_BASE + 3)
#define UADK_CMD_ENABLE_ECC_ENV		(ENGINE_CMD_BASE + 4)

/* Constants used when creating the ENGINE */
const char *engine_uadk_id = "uadk_engine";
static const char *engine_uadk_name = "uadk hardware engine support";

static int uadk_cipher;
static int uadk_digest;
static int uadk_rsa;
static int uadk_dh;
static int uadk_ecc;
static int uadk_inited;
static pthread_mutex_t uadk_engine_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef KAE
static int uadk_cipher_nosva;
static int uadk_digest_nosva;
static int uadk_rsa_nosva;
static int uadk_dh_nosva;
#endif

static const ENGINE_CMD_DEFN g_uadk_cmd_defns[] = {
	{
		UADK_CMD_ENABLE_CIPHER_ENV,
		"UADK_CMD_ENABLE_CIPHER_ENV",
		"Enable or Disable cipher engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_DIGEST_ENV,
		"UADK_CMD_ENABLE_DIGEST_ENV",
		"Enable or Disable digest engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_RSA_ENV,
		"UADK_CMD_ENABLE_RSA_ENV",
		"Enable or Disable rsa engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_DH_ENV,
		"UADK_CMD_ENABLE_DH_ENV",
		"Enable or Disable dh engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_ECC_ENV,
		"UADK_CMD_ENABLE_ECC_ENV",
		"Enable or Disable ecc engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		0, NULL, NULL, 0
	}
};

static void __attribute__((constructor)) uadk_constructor(void)
{
}

static void __attribute__((destructor)) uadk_destructor(void)
{
}

struct uadk_alg_env_enabled {
	const char *alg_name;
	__u8 env_enabled;
};

static struct uadk_alg_env_enabled uadk_env_enabled[] = {
	{ "cipher", 0 },
	{ "digest", 0 },
	{ "rsa", 0 },
	{ "dh", 0 },
	{ "ecc", 0 }
};

int uadk_e_is_env_enabled(const char *alg_name)
{
	int len = ARRAY_SIZE(uadk_env_enabled);
	int i = 0;

	while (i < len) {
		if (!strcmp(uadk_env_enabled[i].alg_name, alg_name))
			return uadk_env_enabled[i].env_enabled;
		i++;
	}

	return 0;
}

static void uadk_e_set_env_enabled(const char *alg_name, __u8 value)
{
	int len = ARRAY_SIZE(uadk_env_enabled);
	int i = 0;

	while (i < len) {
		if (!strcmp(uadk_env_enabled[i].alg_name, alg_name)) {
			uadk_env_enabled[i].env_enabled = value;
			return;
		}

		i++;
	}
}

int uadk_e_set_env(const char *var_name, int numa_id)
{
	char env_string[ENV_STRING_LEN] = {0};
	const char *var_s;
	int ret;

	var_s = secure_getenv(var_name);
	if (!var_s || !strlen(var_s)) {
		/* uadk will request ctxs from device on specified numa node */
		ret = snprintf(env_string, ENV_STRING_LEN, "%s%d%s%d",
			       "sync:2@", numa_id,
			       ",async:2@", numa_id);
		if (ret < 0)
			return ret;

		ret = setenv(var_name, env_string, 1);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int uadk_engine_ctrl(ENGINE *e, int cmd, long i,
			    void *p, void (*f) (void))
{
	(void)p;
	(void)f;

	if (!e) {
		fprintf(stderr, "Null Engine\n");
		return 0;
	}

	switch (cmd) {
	case UADK_CMD_ENABLE_CIPHER_ENV:
		uadk_e_set_env_enabled("cipher", i);
		break;
	case UADK_CMD_ENABLE_DIGEST_ENV:
		uadk_e_set_env_enabled("digest", i);
		break;
	case UADK_CMD_ENABLE_RSA_ENV:
		uadk_e_set_env_enabled("rsa", i);
		break;
	case UADK_CMD_ENABLE_DH_ENV:
		uadk_e_set_env_enabled("dh", i);
		break;
	case UADK_CMD_ENABLE_ECC_ENV:
		uadk_e_set_env_enabled("ecc", i);
		break;
	default:
		return 0;
	}

	return 1;
}

static int uadk_destroy(ENGINE *e)
{
#ifdef KAE
	if (uadk_cipher_nosva)
		sec_ciphers_free_ciphers();
	if (uadk_digest_nosva)
		sec_digests_free_methods();
	if (uadk_rsa_nosva)
		hpre_destroy();
	if (uadk_dh_nosva)
		hpre_dh_destroy();
	kae_debug_close_log();
#endif

	if (uadk_cipher)
		uadk_e_destroy_cipher();
	if (uadk_digest)
		uadk_e_destroy_digest();
	if (uadk_rsa)
		uadk_e_destroy_rsa();
	if (uadk_ecc)
		uadk_e_destroy_ecc();
	if (uadk_dh)
		uadk_e_destroy_dh();

	pthread_mutex_lock(&uadk_engine_mutex);
	uadk_inited = 0;
	pthread_mutex_unlock(&uadk_engine_mutex);

	return 1;
}

static int uadk_init(ENGINE *e)
{
	int ret;

	pthread_mutex_lock(&uadk_engine_mutex);
	if (uadk_inited) {
		pthread_mutex_unlock(&uadk_engine_mutex);
		return 1;
	}

	if (uadk_cipher || uadk_digest || uadk_rsa || uadk_dh || uadk_ecc) {
		ret = async_module_init();
		if (!ret) {
			pthread_mutex_unlock(&uadk_engine_mutex);
			fprintf(stderr, "failed to init async module!\n");
			return 0;
		}
	}

	if (uadk_digest)
		uadk_e_digest_lock_init();
	if (uadk_cipher)
		uadk_e_cipher_lock_init();
	if (uadk_rsa)
		uadk_e_rsa_lock_init();
	if (uadk_dh)
		uadk_e_dh_lock_init();
	if (uadk_ecc)
		uadk_e_ecc_lock_init();

	uadk_inited = 1;
	pthread_mutex_unlock(&uadk_engine_mutex);

	return 1;
}

static int uadk_finish(ENGINE *e)
{
	return 1;
}

static void engine_init_child_at_fork_handler(void)
{
	int ret;

	ret = async_module_init();
	if (!ret)
		fprintf(stderr, "failed to init child async module!\n");
}

#ifdef KAE
static void bind_fn_kae_alg(ENGINE *e)
{
	int dev_num;

	dev_num = wd_get_nosva_dev_num("cipher");
	if (dev_num > 0) {
		cipher_module_init();
		if (!ENGINE_set_ciphers(e, sec_engine_ciphers))
			fprintf(stderr, "uadk bind cipher failed\n");
		else
			uadk_cipher_nosva = 1;
	}

	dev_num = wd_get_nosva_dev_num("digest");
	if (dev_num > 0) {
		digest_module_init();
		if (!ENGINE_set_digests(e, sec_engine_digests))
			fprintf(stderr, "uadk bind digest failed\n");
		else
			uadk_digest_nosva = 1;
	}

	dev_num = wd_get_nosva_dev_num("rsa");
	if (dev_num > 0) {
		hpre_module_init();
		if (!ENGINE_set_RSA(e, hpre_get_rsa_methods()))
			fprintf(stderr, "uadk bind rsa failed\n");
		else
			uadk_rsa_nosva = 1;
	}

	dev_num = wd_get_nosva_dev_num("dh");
	if (dev_num > 0) {
		hpre_module_dh_init();
		if (!ENGINE_set_DH(e, hpre_get_dh_methods()))
			fprintf(stderr, "uadk bind dh failed\n");
		else
			uadk_dh_nosva = 1;
	}
}
#endif

static void bind_fn_uadk_alg(ENGINE *e)
{
	struct uacce_dev *dev;

	dev = wd_get_accel_dev("cipher");
	if (dev) {
		if (!uadk_e_bind_cipher(e))
			fprintf(stderr, "uadk bind cipher failed\n");
		else
			uadk_cipher = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("digest");
	if (dev) {
		if (!uadk_e_bind_digest(e))
			fprintf(stderr, "uadk bind digest failed\n");
		else
			uadk_digest = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("rsa");
	if (dev) {
		if (!uadk_e_bind_rsa(e))
			fprintf(stderr, "uadk bind rsa failed\n");
		else
			uadk_rsa = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("dh");
	if (dev) {
		if (!uadk_e_bind_dh(e))
			fprintf(stderr, "uadk bind dh failed\n");
		else
			uadk_dh = 1;
		free(dev);
	}

	/* find an ecc device, no difference for sm2/ecdsa/ecdh/x25519/x448 */
	dev = wd_get_accel_dev("ecdsa");
	if (dev) {
		if (!uadk_e_bind_ecc(e))
			fprintf(stderr, "uadk bind ecc failed\n");
		else
			uadk_ecc = 1;
		free(dev);
	}
}

/*
 * Connect uadk_engine to OpenSSL engine library.
 */
static int bind_fn(ENGINE *e, const char *id)
{
	int ret;

	if (!ENGINE_set_id(e, engine_uadk_id) ||
	    !ENGINE_set_destroy_function(e, uadk_destroy) ||
	    !ENGINE_set_init_function(e, uadk_init) ||
	    !ENGINE_set_finish_function(e, uadk_finish) ||
	    !ENGINE_set_name(e, engine_uadk_name)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}

#ifdef KAE
	kae_debug_init_log();
	bind_fn_kae_alg(e);

	if (uadk_cipher_nosva || uadk_digest_nosva || uadk_rsa_nosva ||
	    uadk_dh_nosva) {
		async_module_init_v1();
		pthread_atfork(NULL, NULL, engine_init_child_at_fork_handler_v1);
	}
#endif
	bind_fn_uadk_alg(e);

	if (uadk_cipher || uadk_digest || uadk_rsa || uadk_dh || uadk_ecc)
		pthread_atfork(NULL, NULL, engine_init_child_at_fork_handler);

	ret = ENGINE_set_ctrl_function(e, uadk_engine_ctrl);
	if (ret != 1) {
		fprintf(stderr, "failed to set ctrl function\n");
		return 0;
	}

	ret = ENGINE_set_cmd_defns(e, g_uadk_cmd_defns);
	if (ret != 1) {
		fprintf(stderr, "failed to set defns\n");
		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
