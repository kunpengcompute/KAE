#!/bin/sh

#to build hpre
# git clone openssl # get openssl from github, or get from else where
# cd openssl
# ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu-
# add the following configure to this project (assume it is in paralle dir):
# --with-openssl_dir=`pwd`/../openssl
#
ASAN_FLAGS="$1"
ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes ./configure \
	--host aarch64-linux-gnu \
	--target aarch64-linux-gnu \
	--program-prefix aarch64-linux-gnu- \
	CFLAGS="-g -fsigned-char -fstack-protector-strong -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wformat=2 -Wfloat-equal -fPIC $ASAN_FLAGS" CXXFLAGS=-fPIC --enable-shared	\
