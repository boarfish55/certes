#include <sys/types.h>
#ifdef __OpenBSD__
#include <sys/event.h>
#include <sys/time.h>
#else
#include <sys/epoll.h>
#endif
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include "tlsev.h"

#define TLSEV_STORE_BUCKETS 1000

static struct tlsev_store {
	struct tlsev *head[TLSEV_STORE_BUCKETS];
} tlsev_store;

static int socket_timeout;
static int tlsev_data_idx;
static int shutdown_triggered = 0;

void
tlsev_init(int ssl_data_idx, int timeout)
{
	socket_timeout = timeout;
	tlsev_data_idx = ssl_data_idx;
	bzero(&tlsev_store, sizeof(tlsev_store));
}

int
tlsev_create(int fd, SSL_CTX *ctx, struct sockaddr_in6 *peer, struct xerr *e)
{
	struct tlsev *t;

	/* Need to set non-blocking so SSL_accept() does not block */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "fcntl");

	if ((t = malloc(sizeof(struct tlsev))) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	bzero(t, sizeof(struct tlsev));
	t->fd = fd;
	memcpy(&t->peer_addr, peer, sizeof(t->peer_addr));
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
	SSL_set_ex_data(t->ssl, tlsev_data_idx, t);
	SSL_set_bio(t->ssl, t->r, t->w);
	SSL_set_accept_state(t->ssl);

	t->next = tlsev_store.head[fd % TLSEV_STORE_BUCKETS];
	tlsev_store.head[fd % TLSEV_STORE_BUCKETS] = t;

	clock_gettime(CLOCK_MONOTONIC, &t->timeout_at);
	t->timeout_at.tv_sec += socket_timeout;

	return 0;
}

int
tlsev_close(struct tlsev *t)
{
	int           fd = t->fd;
	struct tlsev *prev = NULL;
	int           r;

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

	if (t->peer_cert != NULL)
		X509_free(t->peer_cert);

	/* This will free up the associated BIOs */
	SSL_free(t->ssl);

	xlog(LOG_INFO, NULL, "closing fd %d", t->fd);
	if ((r = close(t->fd)) == -1)
		xlog_strerror(LOG_ERR, errno, "close: %d", t->fd);
	free(t);
	return r;
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

	clock_gettime(CLOCK_MONOTONIC, &t->timeout_at);
	t->timeout_at.tv_sec += socket_timeout;

	/* Don't read more if we're already full */
	if (SSL_is_init_finished(t->ssl) &&
	    t->in_len == sizeof(t->in_buf))
		return t->in_len;

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
			case SSL_ERROR_ZERO_RETURN:
				// TODO: test the zero return one...
				return 0;
			case SSL_ERROR_SSL:
				return XERRF(e, XLOG_SSL, r,
				    "SSL_accept: SSL_ERROR_SSL: %s",
				    ERR_error_string(r, NULL));
			default:
				return XERRF(e, XLOG_SSL, r, "SSL_accept: %s",
				    ERR_error_string(r, NULL));
			}
		}
		t->peer_cert = SSL_get_peer_certificate(t->ssl);
	}

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
	} else
		t->in_len += r;
	return t->in_len;
}

int
tlsev_out(struct tlsev *t, struct xerr *e)
{
	ssize_t n;
	int     r, to_write, pending;

	clock_gettime(CLOCK_MONOTONIC, &t->timeout_at);
	t->timeout_at.tv_sec += socket_timeout;

	if ((pending = BIO_pending(t->w)) < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_pending");

	to_write = (pending > sizeof(t->retry_buf) - t->retry_len)
	    ? sizeof(t->retry_buf) - t->retry_len
	    : pending;
	r = BIO_read(t->w, t->retry_buf, to_write);
	if (r < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_read");
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
	int to_copy = (len > t->in_len) ? t->in_len : len;
	memcpy(buf, t->in_buf, to_copy);
	memmove(t->in_buf, t->in_buf + to_copy, t->in_len - to_copy);
	t->in_len -= to_copy;
	return to_copy;
}

int
tlsev_write(struct tlsev *t, const char *buf, int len, struct xerr *e)
{
	int r = SSL_write(t->ssl, buf, len);
	if (r < 0) {
		r = SSL_get_error(t->ssl, r);
		return XERRF(e, XLOG_SSL, r, "SSL_write: %s",
		    ERR_error_string(r, NULL));
	}
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

#ifndef __OpenBSD__
int
del_epoll_fd(int epollfd, int fd)
{
	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_ctl: DEL fd %d", fd);
		return -1;
	}
	return 0;
}
#endif

void
tlsev_run(int lsock, SSL_CTX *ctx, int max_clients)
{
#define TLSEV_NONE   0x00
#define TLSEV_READ   0x01
#define TLSEV_WRITE  0x02
	uint8_t              evtype;
#define MAX_SOCK_EVENTS 128
#ifdef __OpenBSD__
	int                  kq, nev, chn = 0;
	struct kevent        ev[MAX_SOCK_EVENTS], ch[MAX_SOCK_EVENTS * 2];
	struct timespec      timeout = {1, 0};
#else
	int                  epollfd, nev;
	struct epoll_event   ev, events[MAX_SOCK_EVENTS];
#endif
	struct xerr          e;
	int                  fd, evfd;
	int                  n, r, wpending;
	int                  active_clients = 0, accepting = 1;
	struct sockaddr_in6  peer;
	socklen_t            peerlen = sizeof(peer);
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct tlsev        *t;
	struct tlsev         timeout_queue[max_clients];

	bzero(timeout_queue, sizeof(timeout_queue));
#ifdef __OpenBSD__
	if ((kq = kqueue()) == -1) {
		xlog_strerror(LOG_ERR, errno, "kqueue");
		exit(1);
	}
	EV_SET(&ch[chn++], lsock, EVFILT_READ, EV_ADD, 0, 0, 0);
#else
	if ((epollfd = epoll_create1(0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_create");
		exit(1);
	}
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = lsock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, lsock, &ev) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_ctl: lsock");
		exit(1);
	}
#endif
	while (!shutdown_triggered || active_clients > 0) {
		if (!accepting && active_clients < max_clients) {
			xlog(LOG_NOTICE, NULL,
			    "active_clients=%d; "
			    "accepting new connections", active_clients);
			accepting = 1;
#ifdef __OpenBSD__
			EV_SET(&ch[chn++], lsock, EVFILT_READ, EV_ENABLE,
			    0, 0, 0);
#else
			bzero(&ev, sizeof(ev));
			ev.events = EPOLLIN;
			ev.data.fd = lsock;
			if (epoll_ctl(epollfd, EPOLL_CTL_ADD, lsock,
			    &ev) == -1) {
				xlog_strerror(LOG_ERR, errno,
				    "epoll_ctl: lsock");
				shutdown_triggered = 1;
			}
#endif
		}

#ifdef __OpenBSD__
		nev = kevent(kq, ch, chn, ev, MAX_SOCK_EVENTS, &timeout);
		chn = 0;
#else
		nev = epoll_wait(epollfd, events, MAX_SOCK_EVENTS, 1000);
#endif
		if (nev == -1) {
			if (errno != EINTR) {
#ifdef __OpenBSD__
				xlog_strerror(LOG_ERR, errno, "kqueue");
#else
				xlog_strerror(LOG_ERR, errno, "epoll_wait");
#endif
				exit(1);
			}
			if (shutdown_triggered && lsock > -1) {
#ifndef __OpenBSD__
				if (del_epoll_fd(epollfd, lsock) == -1)
					exit(1);
#endif
				close(lsock);
				lsock = -1;
			}
			continue;
		}

		for (n = 0; n < nev; n++) {
#ifdef __OpenBSD__
			evfd = ev[n].ident;
#else
			evfd = events[n].data.fd;
#endif
			if (evfd == lsock) {
				if ((fd = accept(lsock,
				    (struct sockaddr *)&peer,
				    &peerlen)) == -1) {
					xlog_strerror(LOG_ERR, errno, "accept");
					continue;
				}

				if (getnameinfo((struct sockaddr *)&peer,
				    peerlen, hbuf, sizeof(hbuf), sbuf,
				    sizeof(sbuf),
				    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
					 xlog(LOG_INFO, NULL,
					     "new connection from %s:%s",
					     hbuf, sbuf);
				}

				if (tlsev_create(fd, ctx,
				    &peer, xerrz(&e)) == -1) {
					close(fd);
					xlog(LOG_ERR, &e, "tlsev_create");
					continue;
				}

				if (++active_clients >= max_clients) {
					xlog(LOG_WARNING, NULL,
					    "max_clients reached (%d); "
					    "not accepting new connections",
					    active_clients);
					accepting = 0;
#ifdef __OpenBSD__
					EV_SET(&ch[chn++], lsock, EVFILT_READ,
					    EV_DISABLE, 0, 0, 0);
#else
					del_epoll_fd(epollfd, lsock);
#endif
				}

#ifdef __OpenBSD__
				EV_SET(&ch[chn++], fd, EVFILT_READ, EV_ADD,
				    0, 0, 0);
#else
				bzero(&ev, sizeof(ev));
				ev.events = EPOLLIN|EPOLLERR;
				ev.data.fd = fd;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD,
				    fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					close(fd);
					continue;
				}
#endif
				continue;
			}

			t = tlsev_get(evfd);
			if (t == NULL) {
				xlog(LOG_ERR, NULL,
				    "tlsev_get on fd %d not found", evfd);
#ifdef __OpenBSD__
				EV_SET(&ch[chn++], evfd, EVFILT_READ,
				    EV_DELETE, 0, 0, 0);
#else
				if (del_epoll_fd(epollfd, evfd) == -1)
					exit(1);
#endif
				if (close(evfd) == -1)
					xlog_strerror(LOG_ERR, errno, "close");
				else
					active_clients--;
				continue;
			}

			evtype = TLSEV_NONE;
#ifdef __OpenBSD__
			if (ev[n].filter == EVFILT_READ)
				evtype = TLSEV_READ;
			else if (ev[n].filter == EVFILT_WRITE)
				evtype = TLSEV_WRITE;
#else
			if (events[n].events & EPOLLERR)
				/* Not sure when this happens */
				xlog(LOG_WARNING, NULL,
				    "EPOLLERR: fd=%d", t->fd);
			if (events[n].events & EPOLLIN)
				evtype |= TLSEV_READ;
			if (events[n].events & EPOLLOUT)
				evtype |= TLSEV_WRITE;
#endif
			if (evtype & TLSEV_READ){
				r = tlsev_in(t, xerrz(&e));
				if (r == -1) {
					if (xerr_is(&e, XLOG_SSL,
					    SSL_ERROR_SSL)) {
						xlog(LOG_WARNING, &e,
						    "fd=%d", t->fd);
					} else if (!xerr_is(&e, XLOG_APP,
					    XLOG_EOF)) {
						xlog(LOG_ERR, &e,
						    "fd=%d", t->fd);
					}
#ifndef __OpenBSD__
					del_epoll_fd(epollfd, t->fd);
#endif
					if (tlsev_close(t) != -1)
						active_clients--;
					continue;
				}

				if (r > 0) {
					// TODO: here's where we need to process
					// pending read bytes; we should wait
					// until we have a full request
					// buffered; then we block until
					// processed.

					// Just echo...
					char buf[4096];
					r = tlsev_read(t, buf,
					    sizeof(buf),xerrz(&e));
					if (r == -1) {
						xlog(LOG_ERR, &e,
						    "fd=%d", t->fd);
					} else {
						if (tlsev_write(t, buf, r,
						    xerrz(&e)) == -1) {
							xlog(LOG_ERR, &e,
							    "fd=%d", t->fd);
						}
					}
				}

				if ((r = tlsev_bio_pending(t, NULL, &wpending,
				    xerrz(&e))) == -1) {
					// TODO: cleanup a bit
					xlog(LOG_ERR, &e, "fd=%d", t->fd);
#ifndef __OpenBSD__
					del_epoll_fd(epollfd, t->fd);
#endif
					if (tlsev_close(t) != -1)
						active_clients--;
					continue;
				}

#ifdef __OpenBSD__
				if (wpending > 0)
					EV_SET(&ch[chn++], t->fd, EVFILT_WRITE,
					    EV_ADD, 0, 0, 0);
#else
				bzero(&ev, sizeof(ev));
				ev.data.fd = t->fd;
				ev.events = EPOLLERR|EPOLLIN;
				if (wpending > 0)
					ev.events |= EPOLLOUT;
				if (epoll_ctl(epollfd, EPOLL_CTL_MOD,
				    t->fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					del_epoll_fd(epollfd, t->fd);
					if (tlsev_close(t) != -1)
						active_clients--;
					continue;
				}
#endif
			}

			if (evtype & TLSEV_WRITE) {
				r = tlsev_out(t, xerrz(&e));
				if (r == -1) {
					xlog(LOG_ERR, &e, "write on fd %d",
					    t->fd);
					continue;
				}

#ifdef __OpenBSD__
				if (r == 0)
					EV_SET(&ch[chn++], t->fd, EVFILT_WRITE,
					    EV_DELETE, 0, 0, 0);
#else
				ev.data.fd = t->fd;
				ev.events = EPOLLERR|EPOLLIN;
				if (r > 0)
					ev.events |= EPOLLOUT;

				if (epoll_ctl(epollfd, EPOLL_CTL_MOD,
				    t->fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					del_epoll_fd(epollfd, t->fd);
					if (tlsev_close(t) != -1)
						active_clients--;
				}
#endif
			}
		}
	}
	exit(0);
}

void
tlsev_shutdown()
{
	shutdown_triggered = 1;
}
