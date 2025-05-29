#include <errno.h>
#include <limits.h>
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

ssize_t
readall(int fd, void *buf, size_t count)
{
        ssize_t r;
        ssize_t n = 0;

        while (n < count) {
                r = read(fd, buf + n, count - n);
                if (r == -1) {
                        if (errno == EINTR)
                                continue;
                        return -1;
                } else if (r == 0) {
                        return n;
                }
                n += r;
        }
        return n;
}

ssize_t
writeall(int fd, const void *buf, size_t count)
{
	ssize_t w;
	ssize_t n = 0;

	while (n < count) {
		w = write(fd, buf + n, count - n);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n += w;
	}
	return n;
}

char **
strlist_add(char **a, const char *str)
{
	int      i, j;
	size_t   sz;
	size_t   len = strlen(str) + 1;
	char    *p, *start;

	if (a == NULL) {
		if ((a = malloc((sizeof(char *) * 2) + len)) == NULL)
			return NULL;
		strlcpy(((char *)a) + (sizeof(char *) * 2), str, len);
		a[0] = ((char *)a) + (sizeof(char *) * 2);
		a[1] = NULL;
		return a;
	}

	for (sz = sizeof(char *), i = 0; a[i] != NULL; i++)
		sz += sizeof(char *) + strlen(a[i]) + 1;

	if ((a = realloc(a, sz + sizeof(char *) + len)) == NULL)
		return NULL;

	memmove(((char *)a) + (sizeof(char *) * (i + 2)),
	    ((char *)a) + (sizeof(char *) * (i + 1)),
	    sz - (sizeof(char *) * (i + 1)));

	for (j = 0, p = ((char *)a) + (sizeof(char *) * (i + 2)), start = p;
	    p - (char *)a < sz + sizeof(char *); p++) {
		if (*p == '\0') {
			a[j++] = start;
			start = p + 1;
		}
	}

	strlcpy(((char *)a) + sz + sizeof(char *), str, len);

	a[i] = ((char *)a) + sz + sizeof(char *);
	a[i + 1] = NULL;

	return a;
}

int
strlist_join(char **strlist, size_t strlist_sz, char **dst)
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
