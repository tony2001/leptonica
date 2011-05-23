dnl $Id: config.m4,v 1.5 2009/05/18 08:40:55 tony Exp $

PHP_ARG_WITH(leptonica, for Leptonica support,
[  --with-leptonica             Include Leptonica support])

AC_DEFUN([PHP_LEPTONICA_ZLIB],[
    if test -n "$PHP_ZLIB_DIR" && test "$PHP_ZLIB_DIR" != "no" && test "$PHP_ZLIB_DIR" != "yes"; then
        if test -f "$PHP_ZLIB_DIR/include/zlib/zlib.h"; then
            PHP_ZLIB_DIR="$PHP_ZLIB_DIR"
            PHP_ZLIB_INCDIR="$PHP_ZLIB_DIR/include/zlib"
        elif test -f "$PHP_ZLIB_DIR/include/zlib.h"; then
            PHP_ZLIB_DIR="$PHP_ZLIB_DIR"
            PHP_ZLIB_INCDIR="$PHP_ZLIB_DIR/include"
        else
            AC_MSG_ERROR([Can't find zlib headers under "$PHP_ZLIB_DIR"])
        fi
    else
        for i in /usr/local /usr /local; do
            if test -f "$i/include/zlib/zlib.h"; then
                PHP_ZLIB_DIR="$i"
                PHP_ZLIB_INCDIR="$i/include/zlib"
            elif test -f "$i/include/zlib.h"; then
                PHP_ZLIB_DIR="$i"
                PHP_ZLIB_INCDIR="$i/include"
            fi
        done
    fi
])

AC_DEFUN([PHP_LEPTONICA_TIFF],[
  if test -n "$PHP_TIFF_DIR" || test "$PHP_TIFF_DIR" != "no"; then

    for i in $PHP_TIFF_DIR /usr/local /usr; do
      test -f $i/$PHP_LIBDIR/libtiff.$SHLIB_SUFFIX_NAME -o -f $i/$PHP_LIBDIR/libtiff.a && LEPTONICA_TIFF_DIR=$i && break
    done

    if test -z "$LEPTONICA_TIFF_DIR"; then
      AC_MSG_ERROR([libtiff.(a|so) not found.])
    fi

    PHP_CHECK_LIBRARY(tiff,TIFFOpen,
    [
      PHP_ADD_INCLUDE($LEPTONICA_TIFF_DIR/include)
      PHP_ADD_LIBRARY_WITH_PATH(tiff, $LEPTONICA_TIFF_DIR/$PHP_LIBDIR, LEPTONICA_SHARED_LIBADD)
    ],[
      AC_MSG_ERROR([Problem with libtiff.(a|so). Please check config.log for more information.])
    ],[
      -L$LEPTONICA_TIFF_DIR/$PHP_LIBDIR
    ])
  else
    AC_MSG_RESULT([If configure fails try --with-tiff-dir=<DIR>])
  fi
])

AC_DEFUN([PHP_LEPTONICA_JPEG],[
  if test -n "$PHP_JPEG_DIR" || test "$PHP_JPEG_DIR" != "no"; then

    for i in $PHP_JPEG_DIR /usr/local /usr; do
      test -f $i/$PHP_LIBDIR/libjpeg.$SHLIB_SUFFIX_NAME -o -f $i/$PHP_LIBDIR/libjpeg.a && LEPTONICA_JPEG_DIR=$i && break
    done

    if test -z "$LEPTONICA_JPEG_DIR"; then
      AC_MSG_ERROR([libjpeg.(a|so) not found.])
    fi

    PHP_CHECK_LIBRARY(jpeg,jpeg_read_header,
    [
      PHP_ADD_INCLUDE($LEPTONICA_JPEG_DIR/include)
      PHP_ADD_LIBRARY_WITH_PATH(jpeg, $LEPTONICA_JPEG_DIR/$PHP_LIBDIR, LEPTONICA_SHARED_LIBADD)
    ],[
      AC_MSG_ERROR([Problem with libjpeg.(a|so). Please check config.log for more information.])
    ],[
      -L$LEPTONICA_JPEG_DIR/$PHP_LIBDIR
    ])
  else
    AC_MSG_RESULT([If configure fails try --with-jpeg-dir=<DIR>])
  fi
])

AC_DEFUN([PHP_LEPTONICA_PNG],[
  if test -n "$PHP_PNG_DIR" || test "$PHP_PNG_DIR" != "no"; then

    for i in $PHP_PNG_DIR /usr/local /usr; do
      test -f $i/$PHP_LIBDIR/libpng.$SHLIB_SUFFIX_NAME -o -f $i/$PHP_LIBDIR/libpng.a && LEPTONICA_PNG_DIR=$i && break
    done

    if test -z "$LEPTONICA_PNG_DIR"; then
      AC_MSG_ERROR([libpng.(a|so) not found.])
    fi

    if test "$PHP_ZLIB_DIR" = "no"; then
      AC_MSG_ERROR([PNG support requires ZLIB. Use --with-zlib-dir=<DIR>])
    fi

    if test ! -f $LEPTONICA_PNG_DIR/include/png.h; then
      AC_MSG_ERROR([png.h not found.])
    fi

    PHP_CHECK_LIBRARY(png,png_write_image,
    [
      PHP_ADD_INCLUDE($LEPTONICA_PNG_DIR/include)
      PHP_ADD_LIBRARY_WITH_PATH(z, $PHP_ZLIB_DIR/$PHP_LIBDIR, LEPTONICA_SHARED_LIBADD)
      PHP_ADD_LIBRARY_WITH_PATH(png, $LEPTONICA_PNG_DIR/$PHP_LIBDIR, LEPTONICA_SHARED_LIBADD)
    ],[
      AC_MSG_ERROR([Problem with libpng.(a|so) or libz.(a|so). Please check config.log for more information.])
    ],[
      -L$PHP_ZLIB_DIR/$PHP_LIBDIR -lz -L$LEPTONICA_PNG_DIR/$PHP_LIBDIR
    ])

  else
    AC_MSG_RESULT([If configure fails try --with-png-dir=<DIR> and --with-zlib-dir=<DIR>])
  fi
])

if test "$PHP_LEPTONICA" != "no"; then

  if test "x$PHP_LIBDIR" = "x"; then
    PHP_LIBDIR=lib
  fi

  SEARCH_PATH="/usr/local /usr /local"
  SEARCH_FOR="allheaders.h"
  if test -r $PHP_LEPTONICA/; then
    AC_MSG_CHECKING([for Leptonica files in $PHP_LEPTONICA])
    if test -r $PHP_LEPTONICA/include/liblept/$SEARCH_FOR; then
      LEPTONICA_DIR=$PHP_LEPTONICA
      LEPTONICA_INCDIR=$PHP_LEPTONICA/include/liblept
      AC_MSG_RESULT(found)
    elif test -r $PHP_LEPTONICA/include/leptonica/$SEARCH_FOR; then
      LEPTONICA_DIR=$PHP_LEPTONICA
      LEPTONICA_INCDIR=$PHP_LEPTONICA/include/leptonica
      AC_MSG_RESULT(found)
    fi
  else
    AC_MSG_CHECKING([for Leptonica files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/include/liblept/$SEARCH_FOR; then
        LEPTONICA_DIR=$i
        LEPTONICA_INCDIR=$i/include/liblept
        AC_MSG_RESULT(found in $i)
        break;
      elif test -r $i/include/leptonica/$SEARCH_FOR; then
        LEPTONICA_DIR=$i
        LEPTONICA_INCDIR=$i/include/leptonica
        AC_MSG_RESULT(found in $i)
        break;
      fi
    done
  fi
  
  if test -z "$LEPTONICA_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please reinstall Leptonica])
  fi

  PHP_ADD_INCLUDE($LEPTONICA_INCDIR)

  LIBNAME=lept
  LIBSYMBOL=pixGetRGBPixel

  dnl PHP_LEPTONICA_ZLIB
  dnl PHP_LEPTONICA_JPEG
  dnl PHP_LEPTONICA_PNG
  dnl PHP_LEPTONICA_TIFF

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $LEPTONICA_DIR/$PHP_LIBDIR, LEPTONICA_SHARED_LIBADD)
  ],[
    AC_MSG_ERROR([wrong Leptonica version (1.52+ is required) or Leptonica library not found])
  ],[
    -L$LEPTONICA_DIR/$PHP_LIBDIR -lm -L$LEPTONICA_TIFF_DIR/$PHP_LIBDIR -L$LEPTONICA_JPEG_DIR/$PHP_LIBDIR -L$LEPTONICA_PNG_DIR/$PHP_LIBDIR -ljpeg -lpng -ltiff
  ])
  
  PHP_SUBST(LEPTONICA_SHARED_LIBADD)
  PHP_NEW_EXTENSION(leptonica, leptonica.c, $ext_shared)
fi
