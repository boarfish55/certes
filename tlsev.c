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
	/* This will free up the associated BIOs */
	SSL_free(t->ssl);

	free(t);
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

int
tlsev_init(struct tlsev_listener *l, SSL_CTX *ctx, int lsock,
    int socket_timeout, int max_clients, int ssl_data_idx,
    int (*in_cb)(struct tlsev *, const char *, size_t, void **),
    void (*in_cb_data_free)(void *))
{
#ifdef __OpenBSD__
	struct kevent      ch;
#else
	struct epoll_event ev;
#endif
	bzero(l, sizeof(struct tlsev_listener));
	l->ctx = ctx;
	l->lsock = lsock;
	l->socket_timeout = socket_timeout;
	l->tlsev_data_idx = ssl_data_idx;
	l->next_id = 1;
	l->in_cb = in_cb;
	l->in_cb_data_free = in_cb_data_free;

	l->max_clients = max_clients;
	l->accepting = 1;

	if (idxheap_init(&l->tlsev_store,
	    (max_clients / 2 < 1) ? 2 : max_clients / 2,
	    &tlsev_timeout_cmp, &tlsev_match,
	    (void(*)(void *))&tlsev_free, &tlsev_hash))
		return -1;
#ifdef __OpenBSD__
	/*
	 * See tlsev_run() to count how many changes can accumulte and l->ch:
	 *   - Up to one event per filter
	 *   - And 2 more for disabling reads on the listening socket and
	 *     adding the new client, or when reenabling the listening socket.
	 */
	l->max_events = l->max_clients + 2;
	l->ch = malloc(sizeof(struct kevent) * l->max_events);
	if (l->ch == NULL) {
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	l->ev = malloc(sizeof(struct kevent) * l->max_events);
	if (l->ch == NULL) {
		free(l->ch);
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	if ((l->kq = kqueue()) == -1) {
		free(l->ch);
		free(l->ev);
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	EV_SET(&ch, l->lsock, EVFILT_READ, EV_ADD, 0, 0, 0);
	if (kevent(l->kq, &ch, 1, NULL, 0, NULL) == -1) {
		free(l->ch);
		free(l->ev);
		idxheap_free(&l->tlsev_store);
		close(l->kq);
		return -1;
	}
#else
	/* Up to max_clients events, plus listening socket */
	l->max_events = l->max_clients + 1;
	l->events = malloc(sizeof(struct epoll_event) * l->max_events);
	if (l->events == NULL) {
		idxheap_free(&l->tlsev_store);
		return -1;
	}
	if ((l->epollfd = epoll_create1(0)) == -1) {
		idxheap_free(&l->tlsev_store);
		free(l->events);
		return -1;
	}
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = l->lsock;
	if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD, l->lsock, &ev) == -1) {
		idxheap_free(&l->tlsev_store);
		free(l->events);
		close(l->epollfd);
		return -1;
	}
#endif
	return 0;
}

void
tlsev_del_fd_cb(struct tlsev_listener *l, int i)
{
	for (++i; i < l->fd_callbacks_used; i++)
		memcpy(&l->fd_callbacks[i - 1], &l->fd_callbacks[i],
		    sizeof(struct tlsev_fd_cb));
	l->fd_callbacks_used--;
}

int
tlsev_add_fd_cb(struct tlsev_listener *l, struct tlsev_fd_cb *fd_cb)
{
#ifdef __OpenBSD__
	struct kevent       ch;
#else
	struct epoll_event  ev;
#endif
	void               *tmp;

	if (l->fd_callbacks_used >= l->fd_callbacks_sz) {
		tmp = realloc(l->fd_callbacks,
		    sizeof(struct tlsev_fd_cb) * (l->fd_callbacks_sz + 1));
		if (tmp == NULL)
			return -1;
		if (tmp != l->fd_callbacks)
			l->fd_callbacks = (struct tlsev_fd_cb *)tmp;
		l->fd_callbacks_sz++;
		l->max_events++;
#ifdef __OpenBSD__
		tmp = realloc(l->ch, sizeof(struct kevent) * l->max_events);
		if (tmp == NULL)
			return -1;
		if (tmp != l->ch)
			l->ch = (struct kevent *)tmp;

		tmp = realloc(l->events, sizeof(struct kevent) * l->max_events);
		if (tmp == NULL)
			return -1;
		if (tmp != l->events)
			l->events = (struct kevent *)tmp;
#else
		tmp = realloc(l->events, sizeof(struct epoll_event) *
		    l->max_events);
		if (tmp == NULL)
			return -1;
		if (tmp != l->events)
			l->events = (struct epoll_event *)tmp;
#endif
	}

	l->fd_callbacks[l->fd_callbacks_used].fd = fd_cb->fd;
	l->fd_callbacks[l->fd_callbacks_used].cb = fd_cb->cb;
	l->fd_callbacks_used++;
#ifdef __OpenBSD__
	EV_SET(&ch, fd_cb->fd, EVFILT_READ, EV_ADD, 0, 0, 0);
	if (kevent(l->kq, &ch, 1, NULL, 0, NULL) == -1)
		return -1;
#else
	bzero(&ev, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = fd_cb->fd;
	if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD, fd_cb->fd, &ev) == -1)
		return -1;
#endif
	return 0;
}

void
tlsev_destroy(struct tlsev_listener *l)
{
	idxheap_free(&l->tlsev_store);
	if (l->fd_callbacks)
		free(l->fd_callbacks);
	if (l->events)
		free(l->events);
#ifdef __OpenBSD__
	if (l->ch)
		free(l->ch);
	close(l->kq);
#else
	close(l->epollfd);
#endif
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

int
tlsev_fd(struct tlsev *t)
{
	return t->fd;
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
	t->listener = l;
	t->wpending = 0;
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

	if (l->in_cb_data_free != NULL && t->in_cb_data != NULL) {
		l->in_cb_data_free(t->in_cb_data);
		t->in_cb_data = NULL;
	}

	if ((struct tlsev *)idxheap_removek(&l->tlsev_store, t) != t)
		abort();

	xlog(LOG_INFO, NULL, "closing fd %d", t->fd);
	if ((r = close(t->fd)) == -1)
		xlog_strerror(LOG_ERR, errno, "close: %d", t->fd);
	if (t->retry_buf != NULL)
		free(t->retry_buf);
	if (t->peer_cert != NULL)
		X509_free(t->peer_cert);
	tlsev_free(t);
	return r;
}

struct tlsev *
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
		if ((r = l->in_cb(t, buf, r,
		    &t->in_cb_data)) == -1) {
			return XERRF(e, XLOG_APP, XLOG_CALLBACK_ERR,
			    "t->in_cb_data failed");
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
	int                r;
#ifdef __OpenBSD__
	struct kevent      ev;
#else
	struct epoll_event ev;
#endif

	if ((r = SSL_write(t->ssl, buf, len)) <= 0) {
		xlog(LOG_ERR, NULL, "%s: SSL_write: %s", __func__,
		    ERR_error_string(SSL_get_error(t->ssl, r), NULL));
		return -1;
	}

	if (r == 0)
		return 0;

	t->wpending = 1;
#ifdef __OpenBSD__
	EV_SET(&ev, t->fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
	if (kevent(t->listener->kq, &ev, 1, NULL, 0, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "kevent");
		return -1;
	}
#else
	bzero(&ev, sizeof(ev));
	ev.data.fd = t->fd;
	ev.events = EPOLLIN|EPOLLOUT;
	if (epoll_ctl(t->listener->epollfd, EPOLL_CTL_MOD, t->fd, &ev) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_ctl");
		del_epoll_fd(t->listener->epollfd, t->fd);
		if (tlsev_close(t->listener, t) != -1)
			t->listener->active_clients--;
		return -1;
	}
#endif
	return r;
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

int
tlsev_run(struct tlsev_listener *l)
{
#define TLSEV_NONE   0x00
#define TLSEV_READ   0x01
#define TLSEV_WRITE  0x02
	uint8_t              evtype;
	int                  nev;
#ifdef __OpenBSD__
	struct timespec      timeout = {1, 0};
	struct kevent        ch;
#else
	struct epoll_event   ev;
#endif
	struct xerr          e;
	int                  fd, evfd;
	int                  n, r;
	size_t               i;
	struct sockaddr_in6  peer;
	socklen_t            peerlen = sizeof(peer);
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct tlsev        *t;
	struct timespec      now;
	int                  cleanup;

	while (!l->shutdown_triggered || l->active_clients > 0) {
		if (!l->accepting && l->active_clients < l->max_clients) {
			xlog(LOG_NOTICE, NULL,
			    "active_clients=%d; "
			    "accepting new connections", l->active_clients);
			l->accepting = 1;
#ifdef __OpenBSD__
			EV_SET(&ch[l->chn++], l->lsock, EVFILT_READ,
			    EV_ENABLE, 0, 0, 0);
#else
			bzero(&ev, sizeof(ev));
			ev.events = EPOLLIN;
			ev.data.fd = l->lsock;
			if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD, l->lsock,
			    &ev) == -1) {
				xlog_strerror(LOG_ERR, errno,
				    "epoll_ctl: lsock");
				close(l->lsock);
				l->shutdown_triggered = 1;
			}
#endif
		}

#ifdef __OpenBSD__
		nev = kevent(l->kq, l->ch, l->chn,
		    l->events, l->max_events, &timeout);
		l->chn = 0;
#else
		nev = epoll_wait(l->epollfd, l->events, l->max_events, 1000);
#endif
		if (nev == -1) {
			if (errno != EINTR) {
#ifdef __OpenBSD__
				xlog_strerror(LOG_ERR, errno, "kqueue");
#else
				xlog_strerror(LOG_ERR, errno, "epoll_wait");
#endif
				return -1;
			}
			if (l->shutdown_triggered && l->lsock > -1) {
#ifndef __OpenBSD__
				if (l->accepting &&
				    del_epoll_fd(l->epollfd, l->lsock) == -1)
					return -1;
#endif
				close(l->lsock);
				l->lsock = -1;
			}
			continue;
		}

		if (nev == 0) {
			clock_gettime(CLOCK_MONOTONIC, &now);

			t = idxheap_peek(&l->tlsev_store, 0);
			while (t != NULL) {
				if (now.tv_sec < t->timeout_at.tv_sec ||
				    (now.tv_sec == t->timeout_at.tv_sec &&
				     now.tv_nsec <= t->timeout_at.tv_nsec))
					break;
				xlog(LOG_NOTICE, NULL, "timeout reached for "
				    "fd %d; closing socket", t->fd);
#ifndef __OpenBSD__
				del_epoll_fd(l->epollfd, t->fd);
#endif
				if (tlsev_close(l, t) != -1)
					l->active_clients--;
				t = idxheap_peek(&l->tlsev_store, 0);
			}
			continue;
		}

		for (n = 0; n < nev; n++) {
#ifdef __OpenBSD__
			evfd = l->events[n].ident;
#else
			evfd = l->events[n].data.fd;
#endif
			if (evfd == l->lsock) {
				if ((fd = accept(l->lsock,
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

				if (tlsev_create(l, fd, l->ctx, &peer,
				    xerrz(&e)) == -1) {
					close(fd);
					xlog(LOG_ERR, &e, "tlsev_create");
					continue;
				}

				if (l->accepting &&
				    ++l->active_clients >= l->max_clients) {
					xlog(LOG_WARNING, NULL,
					    "max_clients reached (%d); "
					    "not accepting new connections",
					    l->active_clients);
					l->accepting = 0;
#ifdef __OpenBSD__
					EV_SET(&l->ch[l->chn++], l->lsock,
					    EVFILT_READ, EV_DISABLE, 0, 0, 0);
#else
					del_epoll_fd(l->epollfd, l->lsock);
#endif
				}

#ifdef __OpenBSD__
				EV_SET(&l->ch[l->chn++], fd, EVFILT_READ,
				    EV_ADD, 0, 0, 0);
#else
				bzero(&ev, sizeof(ev));
				ev.events = EPOLLIN;
				ev.data.fd = fd;
				if (epoll_ctl(l->epollfd, EPOLL_CTL_ADD,
				    fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					close(fd);
					continue;
				}
#endif
				continue;
			}

			t = tlsev_get(l, evfd);
			if (t == NULL) {
				cleanup = 1;
				for (i = 0; i < l->fd_callbacks_used; i++) {
					if (l->fd_callbacks[i].fd != evfd)
						continue;

					/* Descriptor is valid, don't remove */
					cleanup = 0;
					if (!l->fd_callbacks[i].cb(evfd))
						tlsev_del_fd_cb(l, i);
				}

				if (!cleanup)
					continue;

				xlog(LOG_ERR, NULL,
				    "tlsev_get on fd %d not found", evfd);
#ifndef __OpenBSD__
				if (del_epoll_fd(l->epollfd, evfd) == -1)
					return -1;
#endif
				if (close(evfd) == -1)
					xlog_strerror(LOG_ERR, errno, "close");
				else
					l->active_clients--;
				continue;
			}

			evtype = TLSEV_NONE;
#ifdef __OpenBSD__
			if (l->events[n].filter == EVFILT_READ)
				evtype = TLSEV_READ;
			else if (l->events[n].filter == EVFILT_WRITE)
				evtype = TLSEV_WRITE;
#else
			if (l->events[n].events & EPOLLERR)
				/* Not sure when this happens */
				xlog(LOG_WARNING, NULL,
				    "EPOLLERR: fd=%d", t->fd);
			if (l->events[n].events & EPOLLIN)
				evtype |= TLSEV_READ;
			if (l->events[n].events & EPOLLOUT)
				evtype |= TLSEV_WRITE;
#endif
			if (evtype & TLSEV_READ){
				r = tlsev_in(l, t, xerrz(&e));
				if (r == -1) {
					if (xerr_is(&e, XLOG_APP,
					    XLOG_CALLBACK_ERR)) {
						xlog(LOG_WARNING, &e,
						    "fd=%d", t->fd);
					} else if (!xerr_is(&e, XLOG_APP,
					    XLOG_EOF)) {
						xlog(LOG_ERR, &e,
						    "fd=%d", t->fd);
					}
#ifndef __OpenBSD__
					del_epoll_fd(l->epollfd, t->fd);
#endif
					if (tlsev_close(l, t) != -1)
						l->active_clients--;
					continue;
				}

				if (t->wpending == 0 &&
				    ((r = tlsev_bio_pending(t, NULL,
				    &t->wpending, xerrz(&e))) == -1)) {
					xlog(LOG_ERR, &e, "fd=%d", t->fd);
#ifndef __OpenBSD__
					del_epoll_fd(l->epollfd, t->fd);
#endif
					if (tlsev_close(l, t) != -1)
						l->active_clients--;
					continue;
				}

#ifdef __OpenBSD__
				if (t->wpending > 0)
					EV_SET(&l->ch[l->chn++], t->fd,
					    EVFILT_WRITE, EV_ADD, 0, 0, 0);
#else
				bzero(&ev, sizeof(ev));
				ev.data.fd = t->fd;
				ev.events = EPOLLIN;
				if (t->wpending > 0)
					ev.events |= EPOLLOUT;
				if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD,
				    t->fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					del_epoll_fd(l->epollfd, t->fd);
					if (tlsev_close(l, t) != -1)
						l->active_clients--;
					continue;
				}
#endif
			}

			if (evtype & TLSEV_WRITE) {
				r = tlsev_out(l, t, xerrz(&e));
				if (r == -1) {
					xlog(LOG_ERR, &e, "write on fd %d",
					    t->fd);
#ifndef __OpenBSD__
					del_epoll_fd(l->epollfd, t->fd);
#endif
					if (tlsev_close(l, t) != -1)
						l->active_clients--;
					continue;
				}

				if (r == 0)
					t->wpending = 0;
#ifdef __OpenBSD__
				if (r == 0)
					EV_SET(&l->ch[l->chn++], t->fd,
					    EVFILT_WRITE, EV_DELETE, 0, 0, 0);
#else
				ev.data.fd = t->fd;
				ev.events = EPOLLIN;
				if (r > 0)
					ev.events |= EPOLLOUT;

				if (epoll_ctl(l->epollfd, EPOLL_CTL_MOD,
				    t->fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					del_epoll_fd(l->epollfd, t->fd);
					if (tlsev_close(l, t) != -1)
						l->active_clients--;
				}
#endif
			}
		}
	}
	return 0;
}

void
tlsev_shutdown(struct tlsev_listener *l)
{
	l->shutdown_triggered = 1;
}
