VERSION = 2:0:2
ACLOCAL_AMFLAGS = -I m4

DEPSHEADDIR = $(CURDIR)/../../kae_build/head/
WD_CFLAGS = -I$(DEPSHEADDIR)
WD_CFLAGS += -I$(DEPSHEADDIR)/uadk
WD_CFLAGS += -I$(DEPSHEADDIR)/uadk/v1
AM_LDFLAGS = -L$(DEPSHEADDIR)/../lib
kae_la_LIBADD=-ldl $(WD_LIBS) -lpthread
kae_la_LDFLAGS=-module -version-number $(VERSION)
kae_la_CFLAGS=$(WD_CFLAGS)
lib_LTLIBRARIES=kae.la

if WD_KAE_GMSSL
kae_la_CFLAGS += -DKAE_GMSSL
kae_la_CFLAGS += -I v1/alg/ciphers/sw
kae_la_CFLAGS += -I v1/alg/ciphers/
kae_la_SOURCES=v2/utils/uadk_utils.c e_uadk.c v2/async/uadk_async.c \
		utils/engine_log.c utils/engine_config.c utils/engine_utils.c
kae_la_SOURCES+=v1/alg/ciphers/sw/e_sms4_gcm.c
kae_la_SOURCES+=v1/alg/ciphers/sw/vpsms4_ex-armv8.s
else
kae_la_SOURCES=v2/utils/uadk_utils.c e_uadk.c v2/alg/ciphers/uadk_cipher.c v2/alg/digest/uadk_digest.c v2/async/uadk_async.c \
		v2/alg/rsa/uadk_rsa.c v2/alg/pkey/uadk_sm2.c v2/alg/pkey/uadk_pkey.c v2/alg/dh/uadk_dh.c v2/alg/pkey/uadk_ec.c v2/alg/pkey/uadk_ecx.c \
		utils/engine_log.c utils/engine_config.c utils/engine_utils.c
endif #WD_KAE_GMSSL

AUTOMAKE_OPTIONS = subdir-objects

if WD_KAE
kae_la_CFLAGS += -DKAE
kae_la_SOURCES+=v1/alg/ciphers/sec_ciphers.c \
		 v1/alg/ciphers/sec_ciphers_soft.c \
		 v1/alg/ciphers/sec_ciphers_utils.c \
		 v1/alg/ciphers/sec_ciphers_wd.c \
		 v1/alg/dh/hpre_dh.c \
		 v1/alg/dh/hpre_dh_soft.c \
		 v1/alg/dh/hpre_dh_wd.c \
		 v1/alg/digests/sec_digests.c \
		 v1/alg/digests/sec_digests_soft.c \
		 v1/alg/digests/sec_digests_wd.c \
		 v1/alg/pkey/hpre_rsa.c \
		 v1/alg/pkey/hpre_rsa_soft.c \
		 v1/alg/pkey/hpre_rsa_utils.c \
		 v1/alg/pkey/hpre_wd.c \
		 v1/wdmngr/wd_alg_queue.c \
		 v1/wdmngr/wd_queue_memory.c \
		 v1/utils/engine_check.c \
		 v1/utils/engine_fork.c \
		 v1/utils/engine_opensslerr.c \
		 v1/async/async_callback.c \
		 v1/async/async_event.c \
		 v1/async/async_poll.c \
		 v1/async/async_task_queue.c
endif #WD_KAE
