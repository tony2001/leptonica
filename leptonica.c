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

/* $Id: leptonica.c,v 1.21 2009/07/08 08:37:09 tony Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_leptonica.h"

#include <liblept/allheaders.h>

static int le_leptonica_pix;
static int le_leptonica_box;

typedef struct _php_leptonica_exif_data {
	int orientation;
	char *datetime;
	char *make;
	char *model;
} php_leptonica_exif_data;

typedef struct _php_leptonica_pix {
	PIX *pix;
	php_leptonica_exif_data *exif;
	char *filename;
} php_leptonica_pix;

#ifdef COMPILE_DL_LEPTONICA
ZEND_GET_MODULE(leptonica)
#endif

#define PHP_LEPTONICA_VERSION "0.0.2"

#define PHP_ZVAL_TO_PIX(zval, pix) \
		    ZEND_FETCH_RESOURCE(pix, php_leptonica_pix *, &zval, -1, "leptonica image", le_leptonica_pix)

#define PHP_ZVAL_TO_BOX(zval, box) \
		    ZEND_FETCH_RESOURCE(box, BOX *, &zval, -1, "leptonica box", le_leptonica_box)

enum {
	LEPT_SCALE,
	LEPT_SCALE_SMOOTH,
	LEPT_SCALE_AREA_MAP,
	LEPT_SCALE_BY_SAMPLING
};

static void php_leptonica_exif_data_free(php_leptonica_exif_data *exif) /* {{{ */
{
	if (!exif) {
		return;
	}

	if (exif->make) {
		efree(exif->make);
	}
	if (exif->model) {
		efree(exif->model);
	}
	if (exif->datetime) {
		efree(exif->datetime);
	}
	efree(exif);
}
/* }}} */

static void php_leptonica_pix_free(php_leptonica_pix *pix) /* {{{ */
{
	php_leptonica_exif_data_free(pix->exif);

	if (pix->pix) {
		pixDestroy(&(pix->pix));
	}

	if (pix->filename) {
		efree(pix->filename);
	}

	efree(pix);
}
/* }}} */

static void php_leptonica_pix_dtor(zend_rsrc_list_entry *entry TSRMLS_DC) /* {{{ */
{
	php_leptonica_pix *pix = (php_leptonica_pix *)entry->ptr;

	php_leptonica_pix_free(pix);
}
/* }}} */

static void php_leptonica_box_dtor(zend_rsrc_list_entry *entry TSRMLS_DC) /* {{{ */
{
	BOX *box = (BOX *)entry->ptr;

	boxDestroy(&box);
}
/* }}} */

static php_leptonica_exif_data *php_leptonica_exif_data_copy(php_leptonica_exif_data *exif) /* {{{ */
{
	php_leptonica_exif_data *newexif;

	if (!exif) {
		return NULL;
	}

	newexif = ecalloc(1, sizeof(php_leptonica_exif_data));
	newexif->orientation = exif->orientation;

	if (exif->make) {
		newexif->make = estrdup(exif->make);
	}
	if (exif->model) {
		newexif->model = estrdup(exif->model);
	}
	if (exif->datetime) {
		newexif->datetime = estrdup(exif->datetime);
	}

	return newexif;
}
/* }}} */

static php_leptonica_pix *php_leptonica_pix_copy(php_leptonica_pix *pix) /* {{{ */
{
	php_leptonica_pix *newpix;

	newpix = ecalloc(1, sizeof(php_leptonica_pix));
	newpix->exif = php_leptonica_exif_data_copy(pix->exif);
	newpix->filename = estrdup(pix->filename);

	return newpix;
}
/* }}} */

static int php_exif_get32s(void *data, int is_motorola) /* {{{ */
{
	if (is_motorola) {
		return  (((char  *)data)[0] << 24)
			| (((unsigned char *)data)[1] << 16)
			| (((unsigned char *)data)[2] << 8 )
			| (((unsigned char *)data)[3]      );
	} else {
		return  (((char  *)data)[3] << 24)
			| (((unsigned char *)data)[2] << 16)
			| (((unsigned char *)data)[1] << 8 )
			| (((unsigned char *)data)[0]      );
	}
}
/* }}} */

static unsigned php_exif_get32u(void *data, int is_motorola) /* {{{ */
{
	return (unsigned)php_exif_get32s(data, is_motorola) & 0xffffffff;
}
/* }}} */

static inline int php_exif_get16u(void *data, int is_motorola) /* {{{ */
{
	if (is_motorola) {
		return (((unsigned char *)data)[0] << 8) | ((unsigned char *)data)[1];
	} else {
		return (((unsigned char *)data)[1] << 8) | ((unsigned char *)data)[0];
	}
}
/* }}} */

static inline unsigned char php_exif_get8u(void *data, int is_motorola) /* {{{ */
{
	if (is_motorola) {
		if (((unsigned char *)data)[0] != 0) {
			return 0;
		}
		return ((unsigned char *)data)[1];
	} else {
		if (((unsigned char *)data)[1] != 0) {
			return 0;
		}
		return ((unsigned char *)data)[0];
	}
}
/* }}} */

static inline int php_exif_strlen(void *data, int length) /* {{{ */
{
	int i;

	if (length <= 0) {
		return 0;
	}

	for (i = 0; i < length; i++) {
		if (((unsigned char *)data)[i] == 0) {
			return i;
		}
	}
	/* the data is not zero-terminated */
	return -1;
}
/* }}} */

#define TAG_FMT_BYTE       1
#define TAG_FMT_STRING     2
#define TAG_FMT_USHORT     3

static int php_leptonica_exif_data_read(char *filename, char *data, size_t data_len, php_leptonica_exif_data **ppexif TSRMLS_DC) /* {{{ */
{
	int is_motorola;
	php_stream *stream = NULL;
	php_leptonica_exif_data *pexif = NULL;
	unsigned char buf[32], *dbuf = NULL;
	unsigned int length, offset, number_of_tags, tagnum, tagformat, read_len;

	if (filename) {
		stream = php_stream_open_wrapper(filename, "rb", ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL);

		if (!stream) {
			goto failure;
		}

		if (php_stream_read(stream, (char *)buf, 2) != 2) {
			goto failure;
		}
	} else if (data && data_len > 2) {
		memcpy(buf, data, 2);
		read_len = 2;
	}

	if (buf[0] != 0xFF || buf[1] != 0xD8 /* M_SOI, start of the image */) {
		goto failure;
	}

	while (1) {
		int marker;
		
		if (filename && php_stream_read(stream, (char *)buf, 4) != 4) {
			goto failure;
		} else if (data && data_len > (read_len + 4)) {
			memcpy(buf, data + read_len, 4);
			read_len += 4;
		}

		if (buf[0] != 0xFF) {
			goto failure;
		}

		marker = buf[1];
		length = ((unsigned int)buf[2] << 8) + (unsigned int)buf[3];

		if (length < 2) {
			goto failure;
		}

		switch(marker) {
			case 0xE1: /* EXIF section */
				goto exif_section_found;
				break;
			default:
				/* just skip this section and move to the next one */
				if (filename && php_stream_seek(stream, length-2, SEEK_CUR) != 0) {
					goto failure;
				} else if (data && data_len > (read_len + length - 2)) {
					read_len += length - 2;
				}
				break;
		}
	}

exif_section_found:

	if (length < 8) {
		goto failure;
	}
	length -= 8;

	if (filename && php_stream_read(stream, (char *)buf, 6) != 6) {
		goto failure;
	} else if (data && data_len > (read_len + 6)) {
		memcpy(buf, data + read_len, 6);
		read_len += 6;
	}

	if (buf[0] != 0x45 || buf[1] != 0x78 || buf[2] != 0x69 || buf[3] != 0x66 || buf[4] != 0 || buf[5] != 0) {
		goto failure;
	}

	dbuf = safe_emalloc(1, length, 1);
	if (filename && php_stream_read(stream, (char *)dbuf, length) != length) {
		goto failure;
	} else if (data && data_len > (read_len + length)) {
		memcpy(dbuf, data + read_len, length);
		read_len += length;
	}

	/* Discover byte order */
	if (dbuf[0] == 0x49 && dbuf[1] == 0x49) {
		is_motorola = 0;
	} else if (dbuf[0] == 0x4D && dbuf[1] == 0x4D) {
		is_motorola = 1;
	} else {
		goto failure;
	}

	/* Check Tag Mark */
	if (is_motorola) {
		if (dbuf[2] != 0) goto failure;
		if (dbuf[3] != 0x2A) goto failure;
	} else {
		if (dbuf[3] != 0) goto failure;
		if (dbuf[2] != 0x2A) goto failure;
	}

	/* Get first IFD offset (offset to IFD0) */
	if (is_motorola) {
		if (dbuf[4] != 0) goto failure;
		if (dbuf[5] != 0) goto failure;
		offset = dbuf[6];
		offset <<= 8;
		offset += dbuf[7];
	} else {
		if (dbuf[7] != 0) goto failure;
		if (dbuf[6] != 0) goto failure;
		offset = dbuf[5];
		offset <<= 8;
		offset += dbuf[4];
	}

	if (offset > length - 2) {
		goto failure; /* check end of data segment */
	}

	/* Get the number of directory entries contained in this IFD */
	number_of_tags = php_exif_get16u(dbuf + offset, is_motorola);

	if (number_of_tags == 0 || (int)number_of_tags < 0) {
		goto failure;
	}
	offset += 2;

	pexif = ecalloc(1, sizeof(php_leptonica_exif_data));

	/* Search for Orientation Tag in IFD0 */
	for (;;) {
		if (offset > length - 12) {
			goto failure; /* check end of data segment */
		}
		/* Get Tag number */
		tagnum = php_exif_get16u(dbuf + offset, is_motorola);
		tagformat = php_exif_get16u(dbuf + offset + 2, is_motorola);

		switch(tagnum) {
			case 0x0112: /* Orientation Tag */
				if (tagformat != TAG_FMT_USHORT) {
					goto failure;
				}

				pexif->orientation = (int)php_exif_get8u(dbuf + offset + 8, is_motorola);

				if (pexif->orientation < 0 || pexif->orientation > 8) {
					pexif->orientation = -1;
					goto failure;
				}
				break;
			case 0x010F: /* Make Tag (manufacturer) */
				if (tagformat != TAG_FMT_STRING) {
					goto failure;
				} else {
					int tmp_offset = php_exif_get32u(dbuf + offset + 8, is_motorola);
					int str_len;
					void *p = dbuf + tmp_offset;
					
					if (tmp_offset <= 0) {
						break;
					}

					str_len = php_exif_strlen(p, length - offset - 12 - tmp_offset);
					if (str_len > 0) {
						pexif->make = estrndup((const char *)p, str_len);
					} else {
						goto failure;
					}
				}
				break;
			case 0x0110: /* Model Tag (camera model name) */
				if (tagformat != TAG_FMT_STRING) {
					goto failure;
				} else {
					int tmp_offset = php_exif_get32u(dbuf + offset + 8, is_motorola);
					int str_len;
					void *p = dbuf + tmp_offset;

					if (tmp_offset <= 0) {
						break;
					}

					str_len = php_exif_strlen(p, length - offset - 12 - tmp_offset);
					if (str_len > 0) {
						pexif->model = estrndup((const char *)p, str_len);
					} else {
						goto failure;
					}
				}
				break;
			case 0x0132: /* Datetime */
				if (tagformat != TAG_FMT_STRING) {
					goto failure;
				} else {
					int tmp_offset = php_exif_get32u(dbuf + offset + 8, is_motorola);
					int str_len;
					void *p = dbuf + tmp_offset;

					if (tmp_offset <= 0) {
						break;
					}

					str_len = php_exif_strlen(p, length - offset - 12 - tmp_offset);
					if (str_len > 0) {
						pexif->datetime = estrndup((const char *)p, str_len);
					} else {
						goto failure;
					}
				}
				break;
			default:
				/* do nothing */
				break;
		}
		if (--number_of_tags == 0) {
			break;
		}
		offset += 12;
	}

	*ppexif = pexif;

	efree(dbuf);
	if (stream) {
		php_stream_close(stream);
	}
	return SUCCESS;

failure:
	if (pexif) {
		php_leptonica_exif_data_free(pexif);
		pexif = NULL;
	}
	if (dbuf) {
		efree(dbuf);
	}
	*ppexif = NULL;

	if (stream) {
		php_stream_close(stream);
	}
	return FAILURE;
}
/* }}} */

/* {{{ proto resource leptonica_open(string file[, zend_bool autorotate) */
static PHP_FUNCTION(leptonica_open)
{
	php_leptonica_pix *pix; 
	PIX *rotated_pix;
	char *file;
	int file_len, resource_id;
	zend_bool autorotate = 0;
	int format;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|b", &file, &file_len, &autorotate) != SUCCESS) {
		return;
	}

	if (file_len > MAXPATHLEN) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "File name exceeds the maximum allowed length of %d characters", MAXPATHLEN);
		RETURN_FALSE;
	}

	pix = ecalloc(1, sizeof(php_leptonica_pix));
	pix->filename = estrndup(file, file_len);
		
	pix->pix = pixRead(file);

	if (!pix->pix) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "unable to read image '%s'", pix->filename);
		php_leptonica_pix_free(pix);
		RETURN_FALSE;
	}

	format = pixGetInputFormat(pix->pix);
	switch (format) {
		case IFF_TIFF:
		case IFF_TIFF_PACKBITS:
		case IFF_TIFF_RLE:
		case IFF_TIFF_G3:
		case IFF_TIFF_G4:
		case IFF_TIFF_LZW:
		case IFF_TIFF_ZIP:
		case IFF_JFIF_JPEG:
			/* this function might fail, but that's not an error */
			php_leptonica_exif_data_read(file, NULL, 0, &(pix->exif) TSRMLS_CC);
			break;
		default:
			/* there can be no EXIF data, do nothing */
			break;
	}

	if (autorotate && pix->exif) {

		switch(pix->exif->orientation) {
			case 1:
				/* the image is already in correction position */
				break;
			case 2:
				if (pixFlipLR(pix->pix, pix->pix) == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image left-right");
					RETURN_FALSE;
				}
				break;
			case 3:
				if (pixRotate180(pix->pix, pix->pix) == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 180 degrees");
					RETURN_FALSE;
				}
				break;
			case 4:
				if (pixFlipTB(pix->pix, pix->pix) == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image top-bottom");
					RETURN_FALSE;
				}
				break;
			case 5:
				rotated_pix = pixRotate90(pix->pix, 1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				
				pix->pix = pixFlipLR(NULL, rotated_pix);
				if (pix == NULL) {
					pixDestroy(&rotated_pix);
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image left-right");
					RETURN_FALSE;
				}
				pixDestroy(&rotated_pix);
				break;
			case 6:
				rotated_pix = pixRotate90(pix->pix, 1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				pix->pix = rotated_pix;
				break;
			case 7:
				rotated_pix = pixRotate90(pix->pix, -1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				
				pix->pix = pixFlipLR(NULL, rotated_pix);
				if (pix == NULL) {
					pixDestroy(&rotated_pix);
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image left-right");
					RETURN_FALSE;
				}
				pixDestroy(&rotated_pix);
				break;
			case 8:
				rotated_pix = pixRotate90(pix->pix, -1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				pix->pix = rotated_pix;
				break;
			default:
				/* ignore invalid orientation tag value
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid orientation value '%d', please report (with the image attached)", orientation);
				*/
				break;
		}
	}

	resource_id = zend_list_insert(pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_open_from_string(string data[, zend_bool autorotate) */
static PHP_FUNCTION(leptonica_open_from_string)
{
	php_leptonica_pix *pix; 
	PIX *rotated_pix;
	char *data;
	int data_len, resource_id;
	zend_bool autorotate = 0;
	int format;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|b", &data, &data_len, &autorotate) != SUCCESS) {
		return;
	}

	if (!data_len) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "unable to read image from an empty string");
		RETURN_FALSE;
	}

	pix = ecalloc(1, sizeof(php_leptonica_pix));
	pix->filename = estrndup("memory", sizeof("memory")-1);
		
	pix->pix = pixReadMem((unsigned char *)data, data_len);

	if (!pix->pix) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "unable to read image from the data string");
		php_leptonica_pix_free(pix);
		RETURN_FALSE;
	}

	format = pixGetInputFormat(pix->pix);
	switch (format) {
		case IFF_TIFF:
		case IFF_TIFF_PACKBITS:
		case IFF_TIFF_RLE:
		case IFF_TIFF_G3:
		case IFF_TIFF_G4:
		case IFF_TIFF_LZW:
		case IFF_TIFF_ZIP:
		case IFF_JFIF_JPEG:
			/* this function might fail, but that's not an error */
			php_leptonica_exif_data_read(NULL, data, data_len, &(pix->exif) TSRMLS_CC);
			break;
		default:
			/* there can be no EXIF data, do nothing */
			break;
	}

	if (autorotate && pix->exif) {

		switch(pix->exif->orientation) {
			case 1:
				/* the image is already in correction position */
				break;
			case 2:
				if (pixFlipLR(pix->pix, pix->pix) == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image left-right");
					RETURN_FALSE;
				}
				break;
			case 3:
				if (pixRotate180(pix->pix, pix->pix) == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 180 degrees");
					RETURN_FALSE;
				}
				break;
			case 4:
				if (pixFlipTB(pix->pix, pix->pix) == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image top-bottom");
					RETURN_FALSE;
				}
				break;
			case 5:
				rotated_pix = pixRotate90(pix->pix, 1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				
				pix->pix = pixFlipLR(NULL, rotated_pix);
				if (pix == NULL) {
					pixDestroy(&rotated_pix);
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image left-right");
					RETURN_FALSE;
				}
				pixDestroy(&rotated_pix);
				break;
			case 6:
				rotated_pix = pixRotate90(pix->pix, 1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				pix->pix = rotated_pix;
				break;
			case 7:
				rotated_pix = pixRotate90(pix->pix, -1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				
				pix->pix = pixFlipLR(NULL, rotated_pix);
				if (pix == NULL) {
					pixDestroy(&rotated_pix);
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to flip image left-right");
					RETURN_FALSE;
				}
				pixDestroy(&rotated_pix);
				break;
			case 8:
				rotated_pix = pixRotate90(pix->pix, -1);
				
				if (rotated_pix == NULL) {
					php_leptonica_pix_free(pix);
					php_error_docref(NULL TSRMLS_CC, E_WARNING, "failed to rotate image to 90 degrees");
					RETURN_FALSE;
				}
				pixDestroy(&(pix->pix));
				pix->pix = rotated_pix;
				break;
			default:
				/* ignore invalid orientation tag value
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid orientation value '%d', please report (with the image attached)", orientation);
				*/
				break;
		}
	}

	resource_id = zend_list_insert(pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_box_create(int x, int y, int width, int height) */
static PHP_FUNCTION(leptonica_box_create)
{
	BOX *box;
	int resource_id;
	long x, y, width, height;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "llll", &x, &y, &width, &height) != SUCCESS) {
		return;
	}

	if (width <= 0 || height <= 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "both width and height must be greater than zero");
		RETURN_FALSE;
	}

	if (x < 0) {
		width += x;
		x = 0;
		if (width <= 0) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "x coordinate exceeds the image width");
			RETURN_FALSE;
		}
	}

	if (y < 0) {
		height += y;
		y = 0;
		if (height <= 0) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "y coordinate exceeds the image height");
			RETURN_FALSE;
		}
	}

	box = boxCreate(x, y, width, height);

	if (!box) {
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(box, le_leptonica_box);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_scale(resource image, float scalefactorx, float scalefactory [, int mode ]) */
static PHP_FUNCTION(leptonica_scale)
{
	double scalex, scaley;
	zval *image;
	php_leptonica_pix *pix, *dest_pix;
	long mode = LEPT_SCALE;
	int resource_id;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rdd|l", &image, &scalex, &scaley, &mode) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	dest_pix = php_leptonica_pix_copy(pix);

	switch(mode) {
		case LEPT_SCALE:
			dest_pix->pix = pixScale(pix->pix, scalex, scaley);
			break;
		case LEPT_SCALE_SMOOTH:
			dest_pix->pix = pixScaleSmooth(pix->pix, scalex, scaley);
			break;
		case LEPT_SCALE_AREA_MAP:
			dest_pix->pix = pixScaleAreaMap(pix->pix, scalex, scaley);
			break;
		case LEPT_SCALE_BY_SAMPLING:
			dest_pix->pix = pixScaleBySampling(pix->pix, scalex, scaley);
			break;
		default:
			php_leptonica_pix_free(dest_pix);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid scaling mode '%ld'", mode);
			RETURN_FALSE;
			break;

	}

	if (!dest_pix->pix) {
		php_leptonica_pix_free(dest_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(dest_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_rotate(resource image, float angle [, int type [, int incolor [, int width [, int height]]]]) */
static PHP_FUNCTION(leptonica_rotate)
{
	double angle, deg2rad = 3.1415926535 / 180.;
	zval *image;
	php_leptonica_pix *pix, *dest_pix;
	int resource_id;
	long width = 0, height = 0;
	long type = L_ROTATE_AREA_MAP;
	long incolor = L_BRING_IN_WHITE;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rd|llll", &image, &angle, &type, &incolor, &width, &height) != SUCCESS) {
		return;
	}

	switch(type) {
		case L_ROTATE_AREA_MAP:
		case L_ROTATE_SHEAR:
			/* only these two are ok */
			break;
		default:
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid rotating type '%ld'", type);
			RETURN_FALSE;
			break;
	}

	switch(type) {
		case L_BRING_IN_WHITE:
		case L_BRING_IN_BLACK:
			/* only these two are ok */
			break;
		default:
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid incolor parameter value '%ld'", incolor);
			RETURN_FALSE;
			break;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	dest_pix = php_leptonica_pix_copy(pix);
	dest_pix->pix = pixRotate(pix->pix, angle * deg2rad, type, incolor, width, height);

	if (!dest_pix->pix) {
		php_leptonica_pix_free(dest_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(dest_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_rotate_orth(resource image, int quads) */
static PHP_FUNCTION(leptonica_rotate_orth)
{
	zval *image;
	php_leptonica_pix *pix, *dest_pix;
	int resource_id;
	long quads;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &image, &quads) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	switch (quads) {
		case 1:
		case 2:
		case 3:
		case 4:
			break;
		default:
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "invalid quads parameter '%ld'", quads);
			RETURN_FALSE;
			break;
	}

	dest_pix = php_leptonica_pix_copy(pix);
	dest_pix->pix = pixRotateOrth(pix->pix, quads);

	if (!dest_pix->pix) {
		php_leptonica_pix_free(dest_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(dest_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_clip(resource image, resource box) */
static PHP_FUNCTION(leptonica_clip)
{
	zval *image, *region;
	php_leptonica_pix *pix, *dest_pix;
	BOX *box;
	int resource_id;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rr", &image, &region) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);
	PHP_ZVAL_TO_BOX(region, box);

	dest_pix = php_leptonica_pix_copy(pix);
	dest_pix->pix = pixClipRectangle(pix->pix, box, NULL);

	if (!dest_pix->pix) {
		php_leptonica_pix_free(dest_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(dest_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_unsharpmask(resource image, int smooth, float fract) */
static PHP_FUNCTION(leptonica_unsharpmask)
{
	zval *image;
	php_leptonica_pix *pix, *dest_pix;
	int resource_id;
	long smooth;
	double fract;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rld", &image, &smooth, &fract) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	dest_pix = php_leptonica_pix_copy(pix);
	dest_pix->pix = pixUnsharpMasking(pix->pix, smooth, fract);

	if (!dest_pix->pix) {
		php_leptonica_pix_free(dest_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(dest_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto bool leptonica_save(resource image, string filename [, int format [, int quality ]]) */
static PHP_FUNCTION(leptonica_save)
{
	zval *image;
	php_leptonica_pix *pix;
	char *file;
	int file_len;
	long format = IFF_JFIF_JPEG, quality = 75;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|ll", &image, &file, &file_len, &format, &quality) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	if (file_len > MAXPATHLEN) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "File name exceeds the maximum allowed length of %d characters", MAXPATHLEN);
		RETURN_FALSE;
	}

	switch(format) {
		case IFF_JFIF_JPEG:
			/* JPEG is a special case */
			if (quality <= 0 || quality > 100) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid quality value: %ld, it must be greater than zero and equal or less than 100", quality);
				RETURN_FALSE;
			}

			if (pixWriteJpeg(file, pix->pix, quality, 0)) {
				RETURN_FALSE;		
			}
			RETURN_TRUE;
			break;
		case IFF_BMP:
		case IFF_PNG:
		case IFF_TIFF:
		case IFF_TIFF_PACKBITS:
		case IFF_TIFF_RLE:
		case IFF_TIFF_G3:
		case IFF_TIFF_G4:
		case IFF_TIFF_LZW:
		case IFF_TIFF_ZIP:
		case IFF_PNM:
		case IFF_PS:
		case IFF_GIF:
			break;
		default:
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unknown format '%ld'", format);
			RETURN_FALSE;
			break;
	}

	if (pixWrite(file, pix->pix, format)) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string leptonica_save_to_string(resource image[, int format [, int quality ]]) */
static PHP_FUNCTION(leptonica_save_to_string)
{
	zval *image;
	php_leptonica_pix *pix;
	long format = IFF_JFIF_JPEG, quality = 75;
	l_uint8 *data = NULL;
	size_t data_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|ll", &image, &format, &quality) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	switch(format) {
		case IFF_JFIF_JPEG:
			/* JPEG is a special case */
			if (quality <= 0 || quality > 100) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid quality value: %ld, it must be greater than zero and equal or less than 100", quality);
				RETURN_FALSE;
			}

			if (pixWriteMemJpeg(&data, &data_len, pix->pix, quality, 0)) {
				RETURN_FALSE;		
			}
			if (data && data_len) {
				RETVAL_STRINGL(data, data_len, 1);
				free(data);
				return;
			} else {
				RETURN_FALSE;		
			}
			break;
		case IFF_BMP:
		case IFF_PNG:
		case IFF_TIFF:
		case IFF_TIFF_PACKBITS:
		case IFF_TIFF_RLE:
		case IFF_TIFF_G3:
		case IFF_TIFF_G4:
		case IFF_TIFF_LZW:
		case IFF_TIFF_ZIP:
		case IFF_PNM:
		case IFF_PS:
		case IFF_GIF:
			break;
		default:
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unknown format '%ld'", format);
			RETURN_FALSE;
			break;
	}

	if (pixWriteMem(&data, &data_len, pix->pix, format)) {
		RETURN_FALSE;
	}
	if (data && data_len) {
		RETVAL_STRINGL(data, data_len, 1);
		free(data);
		return;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto bool leptonica_close(resource image) */
static PHP_FUNCTION(leptonica_close)
{
	zval *image;
	php_leptonica_pix *pix;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &image) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	if (zend_list_delete(Z_LVAL_P(image)) != SUCCESS) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto resource leptonica_clone(resource image) */
static PHP_FUNCTION(leptonica_clone)
{
	zval *image;
	php_leptonica_pix *pix, *new_pix;
	int resource_id;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &image) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	new_pix = php_leptonica_pix_copy(pix);
	new_pix->pix = pixClone(pix->pix);

	if (!new_pix->pix) {
		php_leptonica_pix_free(new_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(new_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto bool leptonica_box_close(resource box) */
static PHP_FUNCTION(leptonica_box_close)
{
	zval *zbox;
	BOX *box;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zbox) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_BOX(zbox, box);

	if (zend_list_delete(Z_LVAL_P(zbox)) != SUCCESS) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool leptonica_comment_set(resource image, mixed comment) */
static PHP_FUNCTION(leptonica_comment_set)
{
	zval *image;
	php_leptonica_pix *pix;
	zval *comment;
	int res;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz/", &image, &comment) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	if (Z_TYPE_P(comment) == IS_NULL) {
		res = pixSetText(pix->pix, NULL);
	} else {
		convert_to_string(comment);
		res = pixSetText(pix->pix, Z_STRVAL_P(comment));
	}

	if (res == 0) {
		RETURN_TRUE;
	}
	RETURN_FALSE;
}
/* }}} */

/* {{{ proto string leptonica_comment_get(resource image) */
static PHP_FUNCTION(leptonica_comment_get)
{
	zval *image;
	php_leptonica_pix *pix;
	char *comment;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &image) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	comment = pixGetText(pix->pix);

	if (!comment) {
		RETURN_FALSE;
	}
	RETURN_STRING(comment, 1);
}
/* }}} */

/* {{{ proto array leptonica_pixel_get(resource image, int x, int y) */
static PHP_FUNCTION(leptonica_pixel_get)
{
	zval *image;
	php_leptonica_pix *pix;
	PIXCMAP *cmap;
	long x, y;
	int red, green, blue, depth;
	unsigned int val;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rll", &image, &x, &y) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	cmap = pixGetColormap(pix->pix);

	/* cmap may be present even in 32bit image, so try with 
	 * cmap first and fallthrough if this fails */
	if (cmap) {
		if (pixGetPixel(pix->pix, x, y, &val) != 0) {
			RETURN_FALSE;
		}

		if (((int)val > 0) && pixcmapGetColor(cmap, val, &red, &green, &blue) == 0) {
			goto cmap_success;
		}
	} 

	depth = pixGetDepth(pix->pix);

	switch (depth) {
		case 32:
			/* 32bit image */

			if (pixGetRGBPixel(pix->pix, x, y, &red, &green, &blue)) {
				RETURN_FALSE;
			}
			break;
		case 8:
			if (pixGetPixel(pix->pix, x, y, &val) != 0) {
				RETURN_FALSE;
			}
			red = green = blue = val;
			break;
		default:
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "%d-bit pictures without color map are not supported", depth);
			RETURN_FALSE;
			break;
	}

cmap_success:
	array_init(return_value);
	add_assoc_long_ex(return_value, "red", sizeof("red"), red);
	add_assoc_long_ex(return_value, "green", sizeof("green"), green);
	add_assoc_long_ex(return_value, "blue", sizeof("blue"), blue);
}
/* }}} */

/* {{{ proto array leptonica_image_info(resource image) */
static PHP_FUNCTION(leptonica_image_info)
{
	zval *image, *exif;
	php_leptonica_pix *pix;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &image) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	array_init(return_value);
	add_assoc_long_ex(return_value, "width", sizeof("width"), pixGetWidth(pix->pix));
	add_assoc_long_ex(return_value, "height", sizeof("height"), pixGetHeight(pix->pix));
	add_assoc_long_ex(return_value, "depth", sizeof("depth"), pixGetDepth(pix->pix));
	add_assoc_long_ex(return_value, "format", sizeof("format"), pixGetInputFormat(pix->pix));
	
	MAKE_STD_ZVAL(exif);
	array_init(exif);

	if (pix->exif) {
		add_assoc_long_ex(exif, "orientation", sizeof("orientation"), pix->exif->orientation);
		add_assoc_string_ex(exif, "maker", sizeof("maker"), pix->exif->make ? pix->exif->make : "", 1);
		add_assoc_string_ex(exif, "model", sizeof("model"), pix->exif->model ? pix->exif->model : "", 1);
		add_assoc_string_ex(exif, "datetime", sizeof("datetime"), pix->exif->datetime ? pix->exif->datetime : "", 1);
	}

	add_assoc_zval_ex(return_value, "exif", sizeof("exif"), exif);
}
/* }}} */

/* {{{ proto resource leptonica_filter_rank(resource image, int width, int height [, double rank ]) */
static PHP_FUNCTION(leptonica_filter_rank)
{
	zval *image;
	php_leptonica_pix *pix, *dest_pix;
	int resource_id;
	long width, height;
	double rank = 0.5;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rll|d", &image, &width, &height, &rank) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	dest_pix = php_leptonica_pix_copy(pix);
	dest_pix->pix = pixRankFilter(pix->pix, width, height, rank);

	if (!dest_pix->pix) {
		php_leptonica_pix_free(dest_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(dest_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto resource leptonica_to_8bit_gray(resource image) */
static PHP_FUNCTION(leptonica_to_8bit_gray)
{
	zval *image;
	php_leptonica_pix *pix, *dest_pix;
	int resource_id;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &image) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);
	
	dest_pix = php_leptonica_pix_copy(pix);
	if (pixGetDepth(pix->pix) == 32) {
		/* for 32bit images use fastest conversion available */
		dest_pix->pix = pixConvertRGBToGrayFast(pix->pix);
	} else {
		dest_pix->pix = pixConvertTo8(pix->pix, 0 /* no cmap */);
	}
	
	if (!dest_pix->pix) {
		php_leptonica_pix_free(dest_pix);
		RETURN_FALSE;
	}

	resource_id = zend_list_insert(dest_pix, le_leptonica_pix);
	RETURN_RESOURCE(resource_id);
}
/* }}} */

/* {{{ proto string leptonica_data_get(resource image) */
static PHP_FUNCTION(leptonica_data_get)
{
	zval *image;
	php_leptonica_pix *pix;
	int wpl, h, data_len;
	unsigned int *data;
	char *datad;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &image) != SUCCESS) {
		return;
	}

	PHP_ZVAL_TO_PIX(image, pix);

	h = pixGetHeight(pix->pix);
	if (h <= 0) {
		RETURN_FALSE;
	}
	
	wpl = pixGetWpl(pix->pix);
	if (wpl <= 0) {
		RETURN_FALSE;
	}

	data = pixGetData(pix->pix);
	if (!data) {
		RETURN_FALSE;
	}

	data_len = sizeof(int) * wpl * h;
	/* safe_emalloc() checks for overflows */
	datad = safe_emalloc(sizeof(int) * wpl, h, 1);
	if (!datad) {
		RETURN_FALSE;
	}

	memcpy((char *)datad, (char *)data, data_len);
	datad[data_len] = '\0';

	RETURN_STRINGL(datad, data_len, 0);
}
/* }}} */

/* {{{ proto int leptonica_color(int red, int blue, int green) */
static PHP_FUNCTION(leptonica_color)
{
	long red, blue, green;
	l_uint32 color = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lll", &red, &blue, &green) != SUCCESS) {
		return;
	}

	SET_DATA_BYTE(&color, COLOR_RED, red);
	SET_DATA_BYTE(&color, COLOR_BLUE, blue);
	SET_DATA_BYTE(&color, COLOR_GREEN, green);

	RETURN_LONG(color);
}
/* }}} */

/* {{{ leptonica_functions[]
 */
zend_function_entry leptonica_functions[] = {
	PHP_FE(leptonica_open, NULL)
	PHP_FE(leptonica_open_from_string, NULL)
	PHP_FE(leptonica_box_create, NULL)
	PHP_FE(leptonica_scale, NULL)
	PHP_FE(leptonica_rotate, NULL)
	PHP_FE(leptonica_rotate_orth, NULL)
	PHP_FE(leptonica_clip, NULL)
	PHP_FE(leptonica_unsharpmask, NULL)
	PHP_FE(leptonica_save, NULL)
	PHP_FE(leptonica_save_to_string, NULL)
	PHP_FE(leptonica_close, NULL)
	PHP_FE(leptonica_clone, NULL)
	PHP_FE(leptonica_box_close, NULL)
	PHP_FE(leptonica_comment_set, NULL)
	PHP_FE(leptonica_comment_get, NULL)
	PHP_FE(leptonica_pixel_get, NULL)
	PHP_FE(leptonica_image_info, NULL)
	PHP_FE(leptonica_filter_rank, NULL)
	PHP_FE(leptonica_to_8bit_gray, NULL)
	PHP_FE(leptonica_data_get, NULL)
	PHP_FE(leptonica_color, NULL)
	{NULL, NULL, NULL}
};
/* }}} */

static PHP_MINIT_FUNCTION(leptonica) /* {{{ */
{
	le_leptonica_pix = zend_register_list_destructors_ex(php_leptonica_pix_dtor, NULL, "leptonica image", module_number);
	le_leptonica_box = zend_register_list_destructors_ex(php_leptonica_box_dtor, NULL, "leptonica box", module_number);

	/* constants */
	REGISTER_LONG_CONSTANT("LEPT_SCALE", LEPT_SCALE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_SCALE_SMOOTH", LEPT_SCALE_SMOOTH, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_SCALE_AREA_MAP", LEPT_SCALE_AREA_MAP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_SCALE_BY_SAMPLING", LEPT_SCALE_BY_SAMPLING, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("LEPT_ROTATE_SHEAR", L_ROTATE_SHEAR, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_ROTATE_AREA_MAP", L_ROTATE_AREA_MAP, CONST_CS | CONST_PERSISTENT);
	
	REGISTER_LONG_CONSTANT("LEPT_BRING_IN_WHITE", L_BRING_IN_WHITE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_BRING_IN_BLACK", L_BRING_IN_BLACK, CONST_CS | CONST_PERSISTENT);
	
	REGISTER_LONG_CONSTANT("LEPT_JPEG", IFF_JFIF_JPEG, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_BMP", IFF_BMP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_PNG", IFF_PNG, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_TIFF", IFF_TIFF, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_TIFF_PACKBITS", IFF_TIFF_PACKBITS, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_TIFF_RLE", IFF_TIFF_RLE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_TIFF_G3", IFF_TIFF_G3, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_TIFF_G4", IFF_TIFF_G4, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_TIFF_LZW", IFF_TIFF_LZW, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_TIFF_ZIP", IFF_TIFF_ZIP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_PNM", IFF_PNM, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_PS", IFF_PS, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("LEPT_GIF", IFF_GIF, CONST_CS | CONST_PERSISTENT);

	return SUCCESS;
}
/* }}} */

static PHP_MINFO_FUNCTION(leptonica) /* {{{ */
{
	php_info_print_table_start();
	php_info_print_table_header(2, "leptonica support", "enabled");
	php_info_print_table_row(2, "Version", PHP_LEPTONICA_VERSION);
	php_info_print_table_row(2, "Revision", "$Revision: 1.21 $");
	php_info_print_table_end();

}
/* }}} */

static PHP_RINIT_FUNCTION(leptonica) /* {{{ */
{
	return SUCCESS;
}
/* }}} */

static PHP_RSHUTDOWN_FUNCTION(leptonica) /* {{{ */
{
	return SUCCESS;
}
/* }}} */

/* {{{ leptonica_module_entry
 */
zend_module_entry leptonica_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"leptonica",
	leptonica_functions,
	PHP_MINIT(leptonica),
	NULL,
	PHP_RINIT(leptonica),
	PHP_RSHUTDOWN(leptonica),
	PHP_MINFO(leptonica),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_LEPTONICA_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
