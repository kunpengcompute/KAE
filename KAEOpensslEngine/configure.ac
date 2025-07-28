AC_PREREQ([2.69])
AC_INIT([uadk_engine], [1.1])
AC_CONFIG_SRCDIR([src/e_uadk.c])
AM_INIT_AUTOMAKE([1.10 no-define])
AM_PROG_AS([AS])


AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

# 定义命令行参数
AC_ARG_ENABLE([kae], [AS_HELP_STRING([--enable-kae], [Enable kae support])], [enable_kae="yes"], [enable_kae="no"])
AC_ARG_ENABLE([kae-gmssl], [AS_HELP_STRING([--enable-kae-gmssl], [Enable kae gmssl support])], [enable_kae_gmssl="yes"], [enable_kae_gmssl="no"])
AC_ARG_ENABLE([kae-tongsuo], [AS_HELP_STRING([--enable-kae-tongsuo], [Enable kae tongsuo support])], [enable_kae_tongsuo="yes"], [enable_kae_tongsuo="no"])
AC_ARG_ENABLE([kae-boringssl], [AS_HELP_STRING([--enable-kae-boringssl], [Enable kae boringssl support])], [enable_kae_boringssl="yes"], [enable_kae_boringssl="no"])
AC_ARG_ENABLE([kae-asm], [AS_HELP_STRING([--enable-kae-asm], [Enable asm support])], [enable_kae_asm="yes"], [enable_kae_asm="no"])
AC_ARG_ENABLE(engine, AS_HELP_STRING([--enable-engine],[Enable engine in OpenSSL 3.0]))

# 设置条件变量
AM_CONDITIONAL([WD_KAE], [test "$enable_kae" = "yes"])
AM_CONDITIONAL([WD_KAE_GMSSL], [test "$enable_kae_gmssl" = "yes"])
AM_CONDITIONAL([WD_KAE_TONGSUO], [test "$enable_kae_tongsuo" = "yes"])
AM_CONDITIONAL([WD_KAE_BORINGSSL], [test "$enable_kae_boringssl" = "yes"])
AM_CONDITIONAL([WD_ENGINE], [test "$enable_engine" = "yes"])
AM_CONDITIONAL([WD_ASM], [test "$enable_kae_asm" = "yes"])

# 通过命令传入openssl的安装路径，不然就用默认的
AC_ARG_WITH(openssl_install_dir,
              AS_HELP_STRING([--with-openssl_install_dir],
                             [Path to where the OpenSSL3.0 are installed to. The Engine will be installed to the lib/engines subdirectory of this path.]))
AC_SUBST(with_openssl_install_dir)

# 判断openssl版本
if test "x$with_openssl_install_dir" != "x"
then
	ac_default_prefix=$with_openssl_install_dir
	if grep "define OPENSSL_VERSION_NUMBER  0x1010"  $with_openssl_install_dir/include/openssl/opensslv.h
	then
		#OPENSSL 1.1.1
		AC_MSG_NOTICE([Build KAE engine against OpenSSL 1.1.1])
		AC_SUBST([CFLAGS], [-Wl,-z,relro,-z,now -fstack-protector-strong])
	else
		#OPENSSL 3.0
		if test "x$enable_kae_provider" = "xyes"
		then
			AC_MSG_NOTICE([Build KAE Provider against OpenSSL 3.0])
		else
			AC_MSG_NOTICE([Build KAE Engine against OpenSSL 3.0])
		fi
	fi
	AC_SUBST([includes_openssl], ["-I\$(with_openssl_install_dir)/include"])
	AC_MSG_NOTICE([includes_openssl value: $includes_openssl])
else
	# Default OPENSSL from the system
	AC_PATH_TOOL(PKGCONFIG, pkg-config)
	AS_IF([test "x$PKGCONFIG" = "x"], [AC_MSG_ERROR(pkg-config not found.)], )
	includes_openssl="`pkg-config --variable=includedir libcrypto`"
	if grep "define OPENSSL_VERSION_NUMBER  0x1010" $includes_openssl/openssl/opensslv.h
	then
		AC_MSG_NOTICE([Build KAE Engine against system OpenSSL 1.1.1])
	else
		if test "x$enable_kae_provider" = "xyes"
		then
			AC_MSG_NOTICE([Build KAE Provider against system OpenSSL 3.0])
		else
			AC_MSG_NOTICE([Build KAE Engine against system OpenSSL 3.0])
			AC_SUBST([cflags_openssl_3], ["-DKAE_OPENSSL_3 -DOPENSSL_SUPPRESS_DEPRECATED"])
		fi
	fi
	AC_MSG_NOTICE([Install engine/provider in the system OpenSSL Path])
	AC_SUBST([includes_openssl], ["-I`pkg-config --variable=includedir libcrypto`"])
fi

if test "x$enable_kae_boringssl" = "xyes"
then
	AC_SUBST([lib_boringssl], ["-L$with_openssl_install_dir/lib64"])
else
	AC_SUBST([lib_boringssl], [""])
fi

AC_CHECK_HEADERS([openssl/engine.h])

PKG_CHECK_MODULES(WD, libwd libwd_crypto, [-L/usr/local/lib -L$(AM_LDFLAGS)], [with_wd=yes], [with_wd=no])
AM_CONDITIONAL(HAVE_WD, [test "$with_wd" != "no"])

PKG_CHECK_MODULES(libcrypto, libcrypto < 3.0 libcrypto >= 1.1,
		  [with_crypto=yes], [with_crypto=no])
AM_CONDITIONAL(HAVE_CRYPTO, test "$with_crypto" != "no")

PKG_CHECK_MODULES(libcrypto, libcrypto >= 3.0,
		  [with_crypto3=yes], [with_crypto3=no])
AM_CONDITIONAL(HAVE_CRYPTO3, test "$with_crypto3" != "no")

if test "x$enable_kae_boringssl" = "xyes"
then
    AM_CONDITIONAL(HAVE_CRYPTO, test "$enable_kae_boringssl" = "yes")
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile])
AC_OUTPUT
