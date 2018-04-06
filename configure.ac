AC_PREREQ(2.61)
AC_INIT([pam-pico], [0.0.3], [Frank.Stajano@cl.cam.ac.uk, David.Llewellyn-Jones@cl.cam.ac.uk])
AC_CONFIG_SRCDIR([src/pam_pico.c])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([build])

AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE([enable])

LT_INIT
AC_PROG_CC
AC_PROG_CC_STDC

AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen])

if test "$DOXYGEN" = doxygen; then
echo Use \"make doxygen\" to generate library documentation.
else
echo ===================================================================
echo Install doxygen to allow the library documentation to be generated.
echo ===================================================================
fi

AC_CHECK_HEADERS([sys/fsuid.h])
AC_CHECK_FUNCS([setfsuid])
AC_CHECK_HEADERS([security/_pam_types.h])
AC_CHECK_HEADERS([security/pam_types.h])

AC_CHECK_HEADERS_ONCE([security/pam_appl.h])
# On Solaris at least, <security/pam_modules.h> requires <security/pam_appl.h>
# to be included first
AC_CHECK_HEADER([security/pam_modules.h], [], [], \
		[#ifdef HAVE_SECURITY_PAM_APPL_H
		# include <security/pam_appl.h>
		#endif
		])
AC_CHECK_LIB([pam], [pam_get_user], [:])
AS_IF([test "x$ac_cv_header_security_pam_modules_h" = "xno" \
       -o "x$ac_cv_lib_pam_pam_get_user" = "xno"], [
  AC_MSG_ERROR([Unable to find the PAM library or the PAM header files])
])

PKG_CHECK_MODULES([PICO], [libpico-1 >= 0.0.1, libcrypto, libcurl])
PKG_CHECK_MODULES([PICOBT], [libpicobt, bluez], [HAVE_BLUETOOTH=1], [HAVE_BLUETOOTH=0])
PKG_CHECK_MODULES([GLIB], [gio-unix-2.0, glib-2.0, libsoup-2.4])
PKG_CHECK_MODULES([DBUSGLIB], [dbus-glib-1])
PKG_CHECK_MODULES([GTK], [gtk+-3.0], [HAVE_GTK=1], [HAVE_GTK=0])
PKG_CHECK_MODULES([QRENCODE], [libqrencode])
PKG_CHECK_MODULES([URLDISPATCHER], [url-dispatcher-1], [HAVE_URLDISPATCH=1], [HAVE_URLDISPATCH=0])

# Checks for the Check libraries. See https://libcheck.github.io/check/
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])
CFLAGS+=" -Wall"

AC_PATH_PROG(GDBUS_CODEGEN, [gdbus-codegen], [])

AS_IF([test "x$GDBUS_CODEGEN" = "x"], [
	AC_MSG_ERROR([Could not find gdbus-codegen])
])

# Check whether the LD -z,nodelete linker flag is available
AC_MSG_CHECKING([for -z,nodelete linker flag])
ax_check_save_flags=$LDFLAGS
LDFLAGS="$LDFLAGS -Wl,-z,nodelete"
AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([], [])],
      [AC_DEFINE([LDNODELETE], [-Wl,-z,nodelete],
		 [Define if -z,nodelete linker flag is available])
      AC_MSG_RESULT([yes])],
      [AC_DEFINE([LDNODELETE], [],
		 [Avoid using -z,nodelete linker flag])
      AC_MSG_RESULT([no])])
LDFLAGS=$ax_check_save_flags

AC_MSG_CHECKING([whether certain PAM functions require const arguments])
AC_LANG_PUSH(C)
# Force test to bail if const isn't needed
AC_LANG_WERROR
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <security/pam_appl.h>
	#include <security/pam_modules.h>
]],[[
	const void **item = 0;
	int dummy = 0;
	/*
	 * since pam_handle_t is opaque on at least some platforms, give it
	 * a non-NULL dummy value
	 */
	 const pam_handle_t *ph = (const pam_handle_t *)&dummy;
	(void) pam_get_item(ph, 0, item);
]])],[AC_DEFINE([PAM_CONST], [const], \
	[Define if certain PAM functions require const arguments])
		AC_MSG_RESULT([yes])],
	[AC_DEFINE([PAM_CONST], [], \
	[Prevent certain PAM functions from using const arguments])
	AC_MSG_RESULT([no])])
AC_LANG_POP(C)

# Set up systemd directories
# See man 7 daemon ("Installing Systemd Service Files" section) for details
PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
	[AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
	[with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
	def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
	AS_IF([test "x$def_systemdsystemunitdir" = "x"],
	[AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
		[AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
	with_systemdsystemunitdir=no],
	[with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
	[AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 service/Makefile
                 assets/Makefile
                 assets/icons/Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
