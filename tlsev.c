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
#include <signal.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include "tlsev.h"
#include "idxheap.h"

static int
tlsev_timeout_cmp(const void *k1, const void *k2)
{
	struct timespec *t1, *t2;

	t1 = &((struct tlsev *)k1)->timeout_at;
	t2 = &((struct tlsev *)k2)->timeout_at;

	if (t1->tv_sec < t2->tv_sec ||
	    (t1->tv_sec == t2->tv_sec && t1->tv_nsec < t2->tv_nsec))
		return -1;

	if (t1->tv_sec > t2->tv_sec ||
	    (t1->tv_sec == t2->tv_sec && t1->tv_nsec > t2->tv_nsec))
		return 1;

	return 0;
}

static int
tlsev_match(const void *k1, const void *k2)
{
	struct tlsev *t1 = (struct tlsev *)k1;
	struct tlsev *t2 = (struct tlsev *)k2;

	return t1->fd == t2->fd;
}

static uint32_t
tlsev_hash(const void *t)
{
	return ((struct tlsev *)t)->fd;
}

static void
tlsev_free(struct tlsev *t)
{
	if (t->peer_cert != NULL)
		X509_free(t->peer_cert);

	/* This will free up the associated BIOs */
	SSL_free(t->ssl);

	free(t);
}

int
tlsev_init(struct tlsev_listener *l, SSL_CTX *ctx, int lsock,
    int socket_timeout, int max_clients, int ssl_data_idx,
    int (*in_cb)(struct tlsev *, const char *, size_t, void *),
    void (*in_cb_data_free)(void *))
{
	l->ctx = ctx;
	l->lsock = lsock;
	l->socket_timeout = socket_timeout;
	l->max_clients = max_clients;
	l->tlsev_data_idx = ssl_data_idx;
	l->next_id = 1;
	l->shutdown_triggered = 0;
	l->tlsev_in_cb = in_cb;
	l->tlsev_in_cb_data_free = in_cb_data_free;

	if (idxheap_init(&l->tlsev_store,
	    (max_clients / 2 < 1) ? 2 : max_clients / 2,
	    &tlsev_timeout_cmp, &tlsev_match,
	    (void(*)(void *))&tlsev_free, &tlsev_hash))
		return -1;

	return 0;
}

X509 *
tlsev_peer_cert(struct tlsev *t)
{
	return t->peer_cert;
}

struct sockaddr_in6 *
tlsev_peer(struct tlsev *t)
{
	return &t->peer_addr;
}

uint64_t
tlsev_id(struct tlsev *t)
{
	return t->id;
}

static int
tlsev_create(struct tlsev_listener *l, int fd, SSL_CTX *ctx,
    struct sockaddr_in6 *peer, struct xerr *e)
{
	struct tlsev *t;

	/* Need to set non-blocking so SSL_accept() does not block */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "fcntl");

	if ((t = malloc(sizeof(struct tlsev))) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	bzero(t, sizeof(struct tlsev));
	t->id = l->next_id++;
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
	if (l->tlsev_data_idx >= 0)
		SSL_set_ex_data(t->ssl, l->tlsev_data_idx, t);
	SSL_set_bio(t->ssl, t->r, t->w);
	SSL_set_accept_state(t->ssl);

	clock_gettime(CLOCK_MONOTONIC, &t->timeout_at);
	t->timeout_at.tv_sec += l->socket_timeout;

	if (idxheap_insert(&l->tlsev_store, t) == -1) {
		tlsev_free(t);
		return XERRF(e, XLOG_ERRNO, errno, "idxheap_insert");
	}

	return 0;
}

static int
tlsev_close(struct tlsev_listener *l, struct tlsev *t)
{
	int r;

	if (l->tlsev_in_cb_data_free != NULL)
		l->tlsev_in_cb_data_free(t->in_cb_data);

	if ((struct tlsev *)idxheap_removek(&l->tlsev_store, t) != t)
		abort();

	xlog(LOG_INFO, NULL, "closing fd %d", t->fd);
	if ((r = close(t->fd)) == -1)
		xlog_strerror(LOG_ERR, errno, "close: %d", t->fd);
	if (t->retry_buf != NULL)
		free(t->retry_buf);
	tlsev_free(t);
	return r;
}

static struct tlsev *
tlsev_get(struct tlsev_listener *l, int fd)
{
	struct tlsev key;
	key.fd = fd;
	return idxheap_lookup(&l->tlsev_store, &key);
}

static int
tlsev_in(struct tlsev_listener *l, struct tlsev *t, struct xerr *e)
{
	char    buf[4096];
	ssize_t n;
	int     r;

	clock_gettime(CLOCK_MONOTONIC, &t->timeout_at);
	t->timeout_at.tv_sec += l->socket_timeout;
	if (idxheap_update(&l->tlsev_store, t) == NULL)
		xlog(LOG_ERR, NULL, "%s: idxheap_update: returned NULL "
		    "for fd %d", __func__, t->fd);

	n = read(t->fd, buf, sizeof(buf));
	if (n == -1)
		return XERRF(e, XLOG_ERRNO, errno, "read");
	else if (n == 0)
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

	if ((r = SSL_read(t->ssl, buf, sizeof(buf))) <= 0) {
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
	} else {
		if ((r = l->tlsev_in_cb(t, buf, r,
		    t->in_cb_data)) == -1) {
			r = SSL_get_error(t->ssl, r);
			return XERRF(e, XLOG_SSL, r, "SSL_write: %s",
			    ERR_error_string(r, NULL));
		}
	}
	return 0;
}

static int
tlsev_out(struct tlsev_listener *l, struct tlsev *t, struct xerr *e)
{
	ssize_t n;
	int     r, pending;
	char    buf[4096];

	clock_gettime(CLOCK_MONOTONIC, &t->timeout_at);
	t->timeout_at.tv_sec += l->socket_timeout;
	if (idxheap_update(&l->tlsev_store, t) == NULL)
		xlog(LOG_ERR, NULL, "%s: idxheap_update: returned NULL "
		    "for fd %d", __func__, t->fd);

	if ((pending = BIO_pending(t->w)) < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_pending");

	if (t->retry_buf != NULL) {
		n = write(t->fd, t->retry_buf, t->retry_len);
		if (n == -1) {
			return XERRF(e, XLOG_ERRNO, errno, "write");
		} else if (n < t->retry_len) {
			t->retry_len -= n;
			memmove(t->retry_buf, t->retry_buf + n, t->retry_len);
			return pending + t->retry_len;
		} else {
			t->retry_len = 0;
			free(t->retry_buf);
			t->retry_buf = NULL;
		}
	}

	r = BIO_read(t->w, buf, (pending > sizeof(buf))
	    ? sizeof(buf)
	    : pending);
	if (r < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_read");
	pending -= r;

	if (r > 0) {
		n = write(t->fd, buf, r);
		if (n == -1) {
			return XERRF(e, XLOG_ERRNO, errno, "write");
		} else if (n < r) {
			if ((t->retry_buf = malloc(r - n)) == NULL)
				return XERRF(e, XLOG_ERRNO, errno, "malloc");
			memcpy(t->retry_buf, buf + n, r - n);
			t->retry_len = r - n;
		}
	}

	return pending + t->retry_len;
}

int
tlsev_reply(struct tlsev *t, const char *buf, int len)
{
	return SSL_write(t->ssl, buf, len);
}

static int
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
tlsev_run(struct tlsev_listener *listener)
{
#define TLSEV_NONE   0x00
#define TLSEV_READ   0x01
#define TLSEV_WRITE  0x02
	uint8_t              evtype;
#ifdef __OpenBSD__
	int                  kq, nev, chn = 0;
	struct kevent        ev[listener->max_clients];
	struct kevent        ch[listener->max_clients * 2];
	struct timespec      timeout = {1, 0};
#else
	int                  epollfd, nev;
	struct epoll_event   ev, events[listener->max_clients];
#endif
	struct xerr          e;
	int                  fd, evfd;
	int                  n, r, wpending;
	int                  active_clients = 0, accepting = 1;
	struct sockaddr_in6  peer;
	socklen_t            peerlen = sizeof(peer);
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct tlsev        *t;
	struct timespec      now;

#ifdef __OpenBSD__
	if ((kq = kqueue()) == -1) {
		xlog_strerror(LOG_ERR, errno, "kqueue");
		exit(1);
	}
	EV_SET(&ch[chn++], listener->lsock, EVFILT_READ, EV_ADD, 0, 0, 0);
#else
	if ((epollfd = epoll_create1(0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_create");
		exit(1);
	}
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = listener->lsock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listener->lsock, &ev) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_ctl: lsock");
		exit(1);
	}
#endif
	while (!listener->shutdown_triggered || active_clients > 0) {
		if (!accepting && active_clients < listener->max_clients) {
			xlog(LOG_NOTICE, NULL,
			    "active_clients=%d; "
			    "accepting new connections", active_clients);
			accepting = 1;
#ifdef __OpenBSD__
			EV_SET(&ch[chn++], listener->lsock, EVFILT_READ,
			    EV_ENABLE, 0, 0, 0);
#else
			bzero(&ev, sizeof(ev));
			ev.events = EPOLLIN;
			ev.data.fd = listener->lsock;
			if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listener->lsock,
			    &ev) == -1) {
				xlog_strerror(LOG_ERR, errno,
				    "epoll_ctl: lsock");
				listener->shutdown_triggered = 1;
			}
#endif
		}

#ifdef __OpenBSD__
		nev = kevent(kq, ch, chn, ev, listener->max_clients, &timeout);
		chn = 0;
#else
		nev = epoll_wait(epollfd, events, listener->max_clients, 1000);
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
			if (listener->shutdown_triggered &&
			    listener->lsock > -1) {
#ifndef __OpenBSD__
				if (accepting &&
				    del_epoll_fd(epollfd,
				    listener->lsock) == -1)
					exit(1);
#endif
				close(listener->lsock);
				listener->lsock = -1;
			}
			continue;
		}

		if (nev == 0) {
			clock_gettime(CLOCK_MONOTONIC, &now);

			t = idxheap_peek(&listener->tlsev_store, 0);
			while (t != NULL) {
				if (now.tv_sec < t->timeout_at.tv_sec ||
				    (now.tv_sec == t->timeout_at.tv_sec &&
				     now.tv_nsec <= t->timeout_at.tv_nsec))
					break;
				xlog(LOG_NOTICE, NULL, "timeout reached for "
				    "fd %d; closing socket", t->fd);
#ifndef __OpenBSD__
				del_epoll_fd(epollfd, t->fd);
#endif
				if (tlsev_close(listener, t) != -1)
					active_clients--;
				t = idxheap_peek(&listener->tlsev_store, 0);
			}
			continue;
		}

		for (n = 0; n < nev; n++) {
#ifdef __OpenBSD__
			evfd = ev[n].ident;
#else
			evfd = events[n].data.fd;
#endif
			if (evfd == listener->lsock) {
				if ((fd = accept(listener->lsock,
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

				if (tlsev_create(listener, fd,
				    listener->ctx, &peer, xerrz(&e)) == -1) {
					close(fd);
					xlog(LOG_ERR, &e, "tlsev_create");
					continue;
				}

				if (++active_clients >= listener->max_clients) {
					xlog(LOG_WARNING, NULL,
					    "max_clients reached (%d); "
					    "not accepting new connections",
					    active_clients);
					accepting = 0;
#ifdef __OpenBSD__
					EV_SET(&ch[chn++], listener->lsock,
					    EVFILT_READ, EV_DISABLE, 0, 0, 0);
#else
					del_epoll_fd(epollfd, listener->lsock);
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

			t = tlsev_get(listener, evfd);
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
				r = tlsev_in(listener, t, xerrz(&e));
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
					if (tlsev_close(listener, t) != -1)
						active_clients--;
					continue;
				}

				if ((r = tlsev_bio_pending(t, NULL, &wpending,
				    xerrz(&e))) == -1) {
					xlog(LOG_ERR, &e, "fd=%d", t->fd);
#ifndef __OpenBSD__
					del_epoll_fd(epollfd, t->fd);
#endif
					if (tlsev_close(listener, t) != -1)
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
					if (tlsev_close(listener, t) != -1)
						active_clients--;
					continue;
				}
#endif
			}

			if (evtype & TLSEV_WRITE) {
				r = tlsev_out(listener, t, xerrz(&e));
				if (r == -1) {
					xlog(LOG_ERR, &e, "write on fd %d",
					    t->fd);
#ifndef __OpenBSD__
					del_epoll_fd(epollfd, t->fd);
#endif
					if (tlsev_close(listener, t) != -1)
						active_clients--;
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
					if (tlsev_close(listener, t) != -1)
						active_clients--;
				}
#endif
			}
		}
	}
}

void
tlsev_shutdown(struct tlsev_listener *l)
{
	l->shutdown_triggered = 1;
}
