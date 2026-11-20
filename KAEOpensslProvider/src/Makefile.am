VERSION = 2:0:4
ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects
CFLAGS =-ftrapv -fPIC -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2
CFLAGS +=-Wl,-z,now -Wl,-z,relro -Wl,--disable-new-dtags -Wl,-s

lib_LTLIBRARIES=kae_provider.la
kae_provider_la_SOURCES=adapter/common/kae_config.c \
		adapter/common/kae_log.c \
		adapter/common/kae_opensslerr.c \
		adapter/common/kae_utils.c \
		adapter/nosva/async/async_callback.c \
		adapter/nosva/async/async_event.c \
		adapter/nosva/async/async_poll.c \
		adapter/nosva/async/async_task_queue.c \
		adapter/nosva/async/async_check.c \ 
		adapter/nosva/async/async_fork.c  \
		adapter/nosva/wdwarp/wd_alg_queue.c \
		adapter/nosva/wdwarp/wd_queue_memory.c \
		adapter/nosva/algorithm/cipher/sec_ciphers_aead.c \
		adapter/nosva/algorithm/cipher/sec_ciphers_soft.c \
		adapter/nosva/algorithm/cipher/sec_ciphers_utils.c \
		adapter/nosva/algorithm/cipher/sec_ciphers_wd.c \
		adapter/nosva/algorithm/cipher/sec_ciphers.c \
		adapter/nosva/algorithm/digest/sec_digests_wd.c \
		adapter/nosva/algorithm/digest/sec_digests.c \
		adapter/nosva/algorithm/pkey/hpre_rsa_utils.c \
		adapter/nosva/algorithm/pkey/hpre_rsa_wd.c \
		adapter/nosva/algorithm/pkey/hpre_rsa.c \
		adapter/nosva/algorithm/pkey/hpre_sm2.c \
		adapter/nosva/algorithm/pkey/hpre_dh_soft.c \
		adapter/nosva/algorithm/pkey/hpre_dh_wd.c \
		adapter/nosva/algorithm/pkey/hpre_dh.c \
		provider/prov_nosva.c \
		provider/prov_nosva/prov_rsa.c \
		provider/prov_nosva/prov_pkey_35.c \
		provider/prov_nosva/prov_sm2.c \
		provider/prov_nosva/prov_digest.c \ 
		provider/prov_nosva/prov_cipher.c \
		provider/prov_nosva/prov_dh.c \
		provider/prov_nosva/internal/prov_bio.c \
		provider/prov_nosva/internal/prov_der_writer.c \
		provider/prov_nosva/internal/prov_packet.c \
		provider/prov_nosva/internal/prov_ffc.c

kae_provider_la_LDFLAGS=-module -version-number $(VERSION)
kae_provider_la_LIBADD=$(WD_LIBS) -lpthread
kae_provider_la_CFLAGS=$(includes_openssl) $(libcrypto_CFLAGS)
kae_provider_la_CFLAGS+=-DOPENSSL_SUPPRESS_DEPRECATED
