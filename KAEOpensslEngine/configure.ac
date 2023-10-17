AC_PREREQ([2.69])
AC_INIT([uadk_engine], [1.1])
AC_CONFIG_SRCDIR([src/e_uadk.c])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

# 定义命令行参数
AC_ARG_ENABLE([kae], [AS_HELP_STRING([--enable-kae], [Enable kae support])], [enable_kae="yes"], [enable_kae="no"])
AC_ARG_ENABLE([kae-gmssl], [AS_HELP_STRING([--enable-kae-gmssl], [Enable kae gmssl support])], [enable_kae_gmssl="yes"], [enable_kae_gmssl="no"])

# 设置条件变量
AM_CONDITIONAL([WD_KAE], [test "$enable_kae" = "yes"])
AM_CONDITIONAL([WD_KAE_GMSSL], [test "$enable_kae_gmssl" = "yes"])

AC_CHECK_HEADERS([openssl/engine.h])

PKG_CHECK_MODULES(WD, libwd libwd_crypto, [-L/usr/local/lib -L$(AM_LDFLAGS)], [with_wd=yes], [with_wd=no])
AM_CONDITIONAL(HAVE_WD, [test "$with_wd" != "no"])

PKG_CHECK_MODULES(libcrypto, libcrypto < 3.0 libcrypto >= 1.1,
		  [with_crypto=yes], [with_crypto=no])
AM_CONDITIONAL(HAVE_CRYPTO, test "$with_crypto" != "no")

AC_CONFIG_FILES([
	Makefile
	src/Makefile])
AC_OUTPUT
