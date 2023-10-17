AC_PREREQ([2.69])
AC_INIT([uadk_engine], [1.1])
AC_CONFIG_SRCDIR([src/e_uadk.c])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

AC_ARG_ENABLE(kae,
	      AS_HELP_STRING([--enable-kae],[Enable kae support]))
AC_SUBST(enable_kae)
AM_CONDITIONAL([WD_KAE], [test "$enable_kae" = "yes"])

AC_ARG_ENABLE(kae,
	      AS_HELP_STRING([--enable-kae-v2],[Enable kae2 support]))
AC_SUBST(enable_kae_v2)
AM_CONDITIONAL([WD_KAE_V2], [test "$enable_kae_v2" = "yes"])

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
