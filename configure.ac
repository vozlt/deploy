# @file:    configure.ac
# @brief:   Process this file with autoconf to produce a configure script
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

AC_PREREQ(2.60)

AC_INIT([deploy], [1.0], [vozlt@vozlt.com])
AC_PREFIX_DEFAULT([/usr/local])

AC_SUBST(perlpath)
AC_SUBST(vendorlib)

AC_ARG_WITH(perl,
[  --with-perl=PATH        perl path (Default: system)])

AC_ARG_WITH(vendor-lib,
[  --with-vendor-lib=PATH  perl vendorlib path (Default: system)])

# Checks for programs.
AC_PROG_INSTALL

# perl
if test "x$with_perl" != "x"; then
	if test -f $with_perl ; then
		AC_MSG_CHECKING(for perl)
		AC_MSG_RESULT([$with_perl])
		perlpath=$with_perl
	else
		AC_PATH_PROG(PERL, perl)
		if test "x$ac_cv_path_PERL " != "x"; then
			perlpath=$ac_cv_path_PERL
		else
			AC_MSG_ERROR(Can't not found perl)
		fi
	fi
else
	AC_PATH_PROG(PERL, perl)
	if test "x$ac_cv_path_PERL " != "x"; then
		perlpath=$ac_cv_path_PERL
	else
		AC_MSG_ERROR(Can't not found perl)
	fi
fi

# vendorlib
if test "x$with_vendor_lib" != "x"; then
	AC_MSG_CHECKING(for vndorlib)
	if test "x$with_vendor_lib" = "xyes"; then
		vendorlib=$(perl -V:vendorlib | perl -p -e "s/.*='|'|;//g")
	else
		vendorlib=$with_vendor_lib
	fi
	AC_MSG_RESULT([$vendorlib])
fi

AC_PATH_PROG(MAKE, make)
if test ! -f "$ac_cv_path_MAKE"; then
	AC_MSG_ERROR(Can't not found make)
fi

AC_PATH_PROG(RM, rm)
if test ! -f "$ac_cv_path_RM"; then
	AC_MSG_ERROR(Can't not found rm)
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
