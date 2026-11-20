AC_PREREQ([2.69])
AC_INIT([uadk_engine], [1.1])
AC_CONFIG_SRCDIR([src/Makefile.am])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AM_PROG_AS([AS])


AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

# 定义命令行参数
AC_ARG_ENABLE([kae], [AS_HELP_STRING([--enable-kae], [Enable kae support])], [enable_kae="yes"], [enable_kae="no"])

# 设置条件变量
AM_CONDITIONAL([WD_KAE], [test "$enable_kae" = "yes"])
AM_CONDITIONAL([WD_ENGINE], [test "$enable_provider" = "yes"])

# 通过命令传入openssl的安装路径，不然就用默认的
AC_ARG_WITH(openssl_install_dir,
              AS_HELP_STRING([--with-openssl_install_dir],
                             [Path to where the OpenSSL3.0 are installed to.]))
AC_SUBST(with_openssl_install_dir)

AC_SUBST([includes_openssl], ["-I\$(with_openssl_install_dir)/include"])

PKG_CHECK_MODULES(WD, libwd libwd_crypto, [-L/usr/local/lib -L$(AM_LDFLAGS)], [with_wd=yes], [with_wd=no])
AM_CONDITIONAL(HAVE_WD, [test "$with_wd" != "no"])

PKG_CHECK_MODULES(libcrypto, libcrypto < 3.0 libcrypto >= 1.1,
		  [with_crypto=yes], [with_crypto=no])
AM_CONDITIONAL(HAVE_CRYPTO, test "$with_crypto" != "no")

PKG_CHECK_MODULES(libcrypto, libcrypto >= 3.0,
		  [with_crypto3=yes], [with_crypto3=no])
AM_CONDITIONAL(HAVE_CRYPTO3, test "$with_crypto3" != "no")

AC_CONFIG_FILES([
	Makefile
	src/Makefile])
AC_OUTPUT
