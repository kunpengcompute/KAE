ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign
CONFIGURE_DEPENDENCIES = $(top_srcdir)/../VERSION $(top_srcdir)/../scripts/kae-version.sh

if HAVE_CRYPTO
if HAVE_WD
SUBDIRS = src
endif
endif

if HAVE_CRYPTO3
if HAVE_WD
SUBDIRS = src
endif
endif
