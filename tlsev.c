#include <openssl/err.h>
#include <openssl/ssl.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include "tlsev.h"

#define TLSEV_STORE_BUCKETS 1000

struct tlsev_store {
	struct tlsev *head[TLSEV_STORE_BUCKETS];
} tlsev_store;

void
tlsev_init()
{
	bzero(&tlsev_store, sizeof(tlsev_store));
}

int
tlsev_create(int fd, SSL_CTX *ctx, struct xerr *e)
{
	struct tlsev *t;

	/* Need to set non-blocking so SSL_accept() does not block */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "fcntl");

	// TODO: set send/receive timeout

	if ((t = malloc(sizeof(struct tlsev))) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	bzero(t, sizeof(struct tlsev));
	t->fd = fd;
	if ((t->r = BIO_new(BIO_s_mem())) == NULL) {
		free(t);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
	}
	if ((t->w = BIO_new(BIO_s_mem())) == NULL) {
		BIO_free(t->r);
		free(t);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
	}

	if ((t->ssl = SSL_new(ctx)) == NULL) {
		BIO_free(t->w);
		BIO_free(t->r);
		free(t);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_new");
	}

	SSL_set_bio(t->ssl, t->r, t->w);
	SSL_set_accept_state(t->ssl);

	t->next = tlsev_store.head[fd % TLSEV_STORE_BUCKETS];
	tlsev_store.head[fd % TLSEV_STORE_BUCKETS] = t;

	return 0;
}

void
tlsev_close(struct tlsev *t)
{
	int           fd = t->fd;
	struct tlsev *prev = NULL;

	for (t = tlsev_store.head[fd % TLSEV_STORE_BUCKETS];
	    t != NULL;
	    prev = t, t = t->next) {
		if (t->fd != fd)
			continue;

		if (prev == NULL)
			tlsev_store.head[fd % TLSEV_STORE_BUCKETS] = t->next;
		else
			prev->next = t->next;
		break;
	}

	// TODO: need to free up "t", anything to shutdown the connection?

	/* This will free up the associated BIOs */
	SSL_free(t->ssl);
	close(t->fd);
	xlog(LOG_INFO, NULL, "closed fd %d", t->fd);
	free(t);
}

struct tlsev *
tlsev_get(int fd)
{
	struct tlsev *t;
	for (t = tlsev_store.head[fd % TLSEV_STORE_BUCKETS]; t != NULL;
	    t = t->next) {
		if (t->fd == fd)
			return t;
	}
	return NULL;
}

int
tlsev_in(struct tlsev *t, struct xerr *e)
{
	char    buf[4096];
	ssize_t n;
	int     r;

	n = read(t->fd, buf, sizeof(buf));
	if (n == -1)
		return XERRF(e, XLOG_ERRNO, errno, "read");
	else if (n == 0)
		// TODO: any case where we'd want to return how many
		// buffered bytes instead of indicating EOF now?
		return XERRF(e, XLOG_APP, XLOG_EOF, "read EOF");

	if ((r = BIO_write(t->r, buf, n)) < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");

	if (r < n)
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "BIO_write short write");

	if (!SSL_is_init_finished(t->ssl)) {
		if ((r = SSL_accept(t->ssl)) <= 0) {
			r = SSL_get_error(t->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return 0;
			default:
				return XERRF(e, XLOG_SSL, r, "SSL_accept: %s",
				    ERR_error_string(r, NULL));
			}
		}
	}

	if (t->in_len == sizeof(t->in_buf))
		return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "cannot fit more bytes; t->in_buf is full");

	if ((r = SSL_read(t->ssl, t->in_buf + t->in_len,
	    sizeof(t->in_buf) - t->in_len)) <= 0) {
		r = SSL_get_error(t->ssl, r);
		switch (r) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_ZERO_RETURN:
			break;
		default:
			return XERRF(e, XLOG_SSL, r, "SSL_read: %s",
			    ERR_error_string(r, NULL));
		}
	}
	t->in_len += r;
	return t->in_len;
}

int
tlsev_out(struct tlsev *t, struct xerr *e)
{
	ssize_t n;
	int     r, to_write, pending;

	if ((pending = BIO_pending(t->w)) < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_pending");

	to_write = (pending > sizeof(t->retry_buf) - t->retry_len)
	    ? sizeof(t->retry_buf) - t->retry_len
	    : pending;
	r = BIO_read(t->w, t->retry_buf, to_write);
	if (r < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	t->retry_len += r;
	pending -= r;

	if (t->retry_len > 0) {
		n = write(t->fd, t->retry_buf, t->retry_len);
		if (n == -1) {
			return XERRF(e, XLOG_ERRNO, errno, "write");
		} else if (n < t->retry_len) {
			t->retry_len -= n;
			memmove(t->retry_buf, t->retry_buf + n, t->retry_len);
		} else
			t->retry_len = 0;
	}

	return pending + t->retry_len;
}

int
tlsev_read(struct tlsev *t, char *buf, int len, struct xerr *e)
{
	// TODO
	int to_copy = (len > t->in_len) ? t->in_len : len;
	memcpy(buf, t->in_buf, to_copy);
	memmove(t->in_buf, t->in_buf + to_copy, t->in_len - to_copy);
	t->in_len -= to_copy;
	return to_copy;
}

int
tlsev_write(struct tlsev *t, const char *buf, int len, struct xerr *e)
{
	// TODO
	int r = SSL_write(t->ssl, buf, len);
	if (r < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	return r;
}

int
tlsev_bio_pending(struct tlsev *t, int *r, int *w, struct xerr *e)
{
	if (r != NULL && (*r = BIO_pending(t->r)) == -1)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_pending on read BIO");
	if (w != NULL && (*w = BIO_pending(t->w)) == -1)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_pending on write BIO");
	return 0;
}
