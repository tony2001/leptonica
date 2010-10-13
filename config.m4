dnl $Id: config.m4,v 1.5 2009/05/18 08:40:55 tony Exp $

PHP_ARG_WITH(leptonica, for Leptonica support,
[  --with-leptonica             Include Leptonica support])

if test "$PHP_LEPTONICA" != "no"; then

  if test "x$PHP_LIBDIR" = "x"; then
    PHP_LIBDIR=lib
  fi

  SEARCH_PATH="/usr/local /usr /local"
  SEARCH_FOR="/include/liblept/allheaders.h"
  if test -r $PHP_LEPTONICA/; then
    LEPTONICA_DIR=$PHP_LEPTONICA
  else
    AC_MSG_CHECKING([for Leptonica files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        LEPTONICA_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi
  
  if test -z "$LEPTONICA_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please reinstall Leptonica])
  fi

  PHP_ADD_INCLUDE($LEPTONICA_DIR/include)

  LIBNAME=lept
  LIBSYMBOL=pixGetRGBPixel

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $LEPTONICA_DIR/$PHP_LIBDIR, LEPTONICA_SHARED_LIBADD)
  ],[
    AC_MSG_ERROR([wrong Leptonica version (1.52+ is required) or Leptonica library not found])
  ],[
    -L$LEPTONICA_DIR/$PHP_LIBDIR -lm 
  ])
  
  PHP_SUBST(LEPTONICA_SHARED_LIBADD)
  PHP_NEW_EXTENSION(leptonica, leptonica.c, $ext_shared)
fi
