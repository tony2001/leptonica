/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2009 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Antony Dovgal <tony@daylessday.org>                          |
  +----------------------------------------------------------------------+
*/

/* $Id: php_leptonica.h,v 1.2 2008/11/13 09:49:18 tony Exp $ */

#ifndef PHP_LEPTONICA_H
#define PHP_LEPTONICA_H

extern zend_module_entry leptonica_module_entry;
#define phpext_leptonica_ptr &leptonica_module_entry

#ifdef PHP_WIN32
#define PHP_LEPTONICA_API __declspec(dllexport)
#else
#define PHP_LEPTONICA_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#endif	/* PHP_LEPTONICA_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */
