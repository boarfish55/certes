/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/file.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util.h"

int
is_hex_str(const char *str)
{
	const char *p;

	for (p = str; *p; p++) {
		if (!((*p >= '0' && *p <= '9') ||
		    (*p >= 'a' && *p <= 'f') ||
		    (*p >= 'A' && *p <= 'F'))) {
			return 0;
		}
	}
	return 1;
}

int
strlist_join(const char **strlist, size_t strlist_sz, char **dst)
{
	int   i;
	int   sz = 0;
	char *str_p;

	if (strlist_sz >= INT_MAX) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < strlist_sz && strlist[i] != NULL; i++)
		sz += strlen(strlist[i]) + 1;

	if (sz == 0) {
		*dst = NULL;
		return 0;
	}

	if ((*dst = malloc(sz)) == NULL)
		return -1;

	for (i = 0, str_p = *dst; i < strlist_sz && strlist[i] != NULL; i++)
		str_p += strlcpy(str_p, strlist[i], strlen(strlist[i]) + 1) + 1;

	return sz;
}

int
strlist_split(char ***strlist, const char *src, size_t src_len)
{
	int   i;
	int   sz = 0;
	char *str_p, **strlist_p;

	if (strlist == NULL) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < src_len; i++)
		if (src[i] == '\0')
			sz++;

	*strlist = malloc(((sz + 1) * sizeof(char *)) + src_len);
	if (*strlist == NULL)
		return -1;

	str_p = (char *)((*strlist) + sz + 1);
	strlist_p = *strlist;
	*strlist_p = str_p;
	for (i = 0; i < src_len; i++) {
		*str_p = src[i];
		if (*str_p++ == '\0') {
			strlist_p++;
			*strlist_p = str_p;
		}
	}
	*strlist_p = NULL;

	return sz;
}

int
b64enc(char *dst, size_t dst_sz, const uint8_t *bytes, size_t sz)
{
	BIO *b, *b64;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL)
		return -1;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	if ((b = BIO_new(BIO_s_mem())) == NULL) {
		BIO_free(b64);
		return -1;
	}
	BIO_push(b64, b);

	if (BIO_write(b64, bytes, sz) <= 0) {
		BIO_free_all(b64);
		return -1;
	}
	BIO_flush(b64);

	if (BIO_read(b, dst, dst_sz) != dst_sz) {
		BIO_free_all(b64);
		errno = EAGAIN;
		return -1;
	}

	BIO_free_all(b64);
	return 0;
}

int
b64dec(uint8_t *dst, size_t dst_sz, const char *str)
{
	BIO *b, *b64;
	int  r;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL)
		return -1;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	if ((b = BIO_new(BIO_s_mem())) == NULL) {
		BIO_free(b64);
		return -1;
	}
	BIO_push(b64, b);

	if (BIO_write(b, str, strlen(str)) <= 0) {
		BIO_free_all(b64);
		return -1;
	}
	BIO_flush(b);

	if ((r = BIO_read(b64, dst, dst_sz)) < dst_sz) {
		BIO_free_all(b64);
		errno = EAGAIN;
		return -1;
	}

	BIO_free_all(b64);
	return r;
}

int
open_wflock(const char *path, int flags, mode_t mode, int lk)
{
	int             fd;
	struct timespec tp = {0, 1000000}, req, rem;  /* 1ms */

	for (;;) {
		if ((fd = open(path, flags, mode)) == -1)
			return -1;

		if (flock(fd, lk|LOCK_NB) == 0)
			return fd;

		if (errno != EWOULDBLOCK)
			break;

		close(fd);
		memcpy(&req, &tp, sizeof(req));
		while (nanosleep(&req, &rem) == -1)
			memcpy(&req, &rem, sizeof(req));
	}
	return -1;
}
