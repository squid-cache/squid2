dnl AC_CHECK_SIZEOF_SYSTYPE is as the standard AC_CHECK_SIZEOF macro
dnl but also capable of checking the size of system defined types, not
dnl only compiler defined types.
dnl
dnl AC_CHECK_SYSTYPE is the same thing but replacing AC_CHECK_TYPE
dnl However AC_CHECK_TYPE is not by far as limited as AC_CHECK_SIZEOF
dnl (it at least makes use of <sys/types.h>, <stddef.h> and <stdlib.h>)

dnl AC_CHECK_SIZEOF_SYSTYPE(TYPE [, CROSS-SIZE])
AC_DEFUN([AC_CHECK_SIZEOF_SYSTYPE],
[
AC_REQUIRE([AC_HEADER_STDC])dnl
AC_CHECK_SIZEOF($1, ,
[
#include <stdio.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
])
])dnl

dnl AC_CHECK_SYSTYPE(TYPE, DEFAULT)
AC_DEFUN([AC_CHECK_SYSTYPE],
[AC_REQUIRE([AC_HEADER_STDC])dnl
AC_CHECK_TYPE($1, ,
[AC_DEFINE_UNQUOTED($1, $2, [Define to '$2' if not defined])], 
[
/* What a mess.. many systems have added the (now standard) bit types
 * in their own ways, so we need to scan a wide variety of headers to
 * find them..
 */
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
])
])dnl
