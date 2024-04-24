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

	if (t->peer_cert != NULL)
		X509_free(t->peer_cert);

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
	}
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

#ifdef __OpenBSD__
void
handle_clients_kqueue(int lsock, SSL_CTX *ctx, int max_clients)
{
#define MAX_KQ_EVENTS 128
	struct xerr          e;
	int                  fd;
	int                  kq, nev, n, r, wpending;
	int                  active_clients = 0, accepting = 1;
	struct sockaddr_in6  peer;
	socklen_t            peerlen = sizeof(peer);
	struct kevent        ev[MAX_KQ_EVENTS], ch[MAX_KQ_EVENTS * 2];
	int                  chn = 0;
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct tlsev        *t;
	struct timespec      timeout = {1, 0};

	if ((kq = kqueue()) == -1) {
		xlog_strerror(LOG_ERR, errno, "kqueue");
		exit(1);
	}

	EV_SET(&ch[chn++], lsock, EVFILT_READ, EV_ADD, 0, 0, 0);

	while (!shutdown_triggered || active_clients > 0) {
		if (!accepting && active_clients < max_clients) {
			xlog(LOG_NOTICE, NULL,
			    "active_clients=%d; "
			    "accepting new connections", active_clients);
			EV_SET(&ch[chn++], lsock, EVFILT_READ, EV_ENABLE,
			    0, 0, 0);
			accepting = 1;
		}

		nev = kevent(kq, ch, chn, ev, MAX_KQ_EVENTS, &timeout);
		chn = 0;
		if (nev == -1) {
			if (errno != EINTR) {
				xlog_strerror(LOG_ERR, errno, "kqueue");
				exit(1);
			}
			if (shutdown_triggered && lsock > -1) {
				close(lsock);
				lsock = -1;
			}
			continue;
		}

		for (n = 0; n < nev; n++) {
			if (ev[n].ident == lsock) {
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
					    "max_clients reached; "
					    "not accepting new connections");
					EV_SET(&ch[chn++], lsock, EVFILT_READ,
					    EV_DISABLE, 0, 0, 0);
					accepting = 0;
				}

				EV_SET(&ch[chn++], fd, EVFILT_READ, EV_ADD,
				    0, 0, 0);

				continue;
			}

			t = tlsev_get(ev[n].ident);
			if (t == NULL) {
				xlog(LOG_ERR, NULL,
				    "tlsev_get on fd %d not found",
				    ev[n].ident);
				close(ev[n].ident);
				active_clients--;
				continue;
			}

			if (ev[n].filter == EVFILT_READ) {
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
					active_clients--;
					tlsev_close(t);
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
					active_clients--;
					tlsev_close(t);
					continue;
				}

				if (wpending > 0)
					EV_SET(&ch[chn++], t->fd, EVFILT_WRITE,
					    EV_ADD, 0, 0, 0);
			}

			if (ev[n].filter == EVFILT_WRITE) {
				r = tlsev_out(t, xerrz(&e));
				if (r == -1) {
					xlog(LOG_ERR, &e, "write on fd %d",
					    t->fd);
					continue;
				}

				if (r == 0)
					EV_SET(&ch[chn++], t->fd, EVFILT_WRITE,
					    EV_DELETE, 0, 0, 0);
			}
		}
	}
	exit(0);
}
#else
void
handle_clients_epoll(int lsock, SSL_CTX *ctx, int max_clients)
{
#define MAX_EPOLL_EVENTS 128
	struct xerr          e;
	int                  fd;
	int                  epollfd, nfds, n, r, wpending;
	int                  active_clients = 0, accepting = 0;
	struct sockaddr_in6  peer;
	socklen_t            peerlen = sizeof(peer);
	struct epoll_event   ev, events[MAX_EPOLL_EVENTS];
	char                 hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct tlsev        *t;

	if ((epollfd = epoll_create1(0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "epoll_create");
		exit(1);
	}

	while (!shutdown_triggered || active_clients > 0) {
		if (!accepting && active_clients < max_clients) {
			xlog(LOG_NOTICE, NULL,
			    "active_clients=%d; "
			    "accepting new connections", active_clients);
			ev.events = EPOLLIN;
			ev.data.fd = lsock;
			if (epoll_ctl(epollfd, EPOLL_CTL_ADD, lsock, &ev) == -1) {
				xlog_strerror(LOG_ERR, errno, "epoll_ctl: lsock");
				shutdown_triggered = 1;
			}
			accepting = 1;
		}

		if ((nfds = epoll_wait(epollfd, events,
		    MAX_EPOLL_EVENTS, 1000)) == -1) {
			if (errno != EINTR) {
				xlog_strerror(LOG_ERR, errno, "epoll_wait");
				shutdown_triggered = 1;
			}
			if (shutdown_triggered && lsock > -1) {
				if (del_epoll_fd(epollfd, lsock) == -1)
					exit(1);
				close(lsock);
				lsock = -1;
			}
			continue;
		}

		for (n = 0; n < nfds; n++) {
			if (events[n].data.fd == lsock) {
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

				ev.events = EPOLLIN|EPOLLERR;
				ev.data.fd = fd;
				if (epoll_ctl(epollfd, EPOLL_CTL_ADD,
				    fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					close(fd);
					continue;
				}
				active_clients++;

				if (tlsev_create(fd, ctx,
				    &peer, xerrz(&e)) == -1) {
					if (del_epoll_fd(epollfd, fd) == -1)
						exit(1);
					active_clients--;
					close(fd);
					xlog(LOG_ERR, &e, "tlsev_create");
				}

				if (active_clients >= max_clients) {
					xlog(LOG_WARNING, NULL,
					    "max_clients reached; "
					    "not accepting new connections");
					del_epoll_fd(epollfd, lsock);
					accepting = 0;
				}

				continue;
			}

			t = tlsev_get(events[n].data.fd);
			if (t == NULL) {
				xlog(LOG_ERR, NULL,
				    "tlsev_get on fd %d not found",
				    events[n].data.fd);
				if (del_epoll_fd(epollfd,
				    events[n].data.fd) == -1)
					exit(1);
				active_clients--;
				close(events[n].data.fd);
				continue;
			}

			if (events[n].events & EPOLLERR)
				/* Not sure when this happens */
				xlog(LOG_WARNING, NULL,
				    "EPOLLERR: fd=%d", t->fd);

			if (events[n].events & EPOLLIN){
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
					del_epoll_fd(epollfd, t->fd);
					active_clients--;
					tlsev_close(t);
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
					del_epoll_fd(epollfd, t->fd);
					active_clients--;
					tlsev_close(t);
					continue;
				}

				ev.data.fd = t->fd;
				ev.events = EPOLLERR|EPOLLIN;
				if (wpending > 0)
					ev.events |= EPOLLOUT;

				if (epoll_ctl(epollfd, EPOLL_CTL_MOD,
				    t->fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					del_epoll_fd(epollfd, t->fd);
					active_clients--;
					tlsev_close(t);
					continue;
				}
			}

			if (events[n].events & EPOLLOUT) {
				r = tlsev_out(t, xerrz(&e));
				if (r == -1) {
					xlog(LOG_ERR, &e, "write on fd %d",
					    events[n].data.fd);
					continue;
				}

				ev.data.fd = t->fd;
				ev.events = EPOLLERR|EPOLLIN;
				if (r > 0)
					ev.events |= EPOLLOUT;

				if (epoll_ctl(epollfd, EPOLL_CTL_MOD,
				    t->fd, &ev) == -1) {
					xlog_strerror(LOG_ERR, errno,
					    "epoll_ctl");
					del_epoll_fd(epollfd, t->fd);
					active_clients--;
					tlsev_close(t);
				}
			}
		}

		// TODO: purge old sockets; very slow, need a heap or something

		// TODO: look at this for example of non-blocking polled sockets
		// using BIO_s_mem:
		//  https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca
		// With this we can implement a daemon that forks X children 
		// to kqueue() on accept and all its active conns (to a point; it
		// no longer accepts once it reaches a certain size), creating a
		// BIO_s_mem() buffer and filling it with data (up to a limit) as it
		// comes in, in one structure per client. It uses SSL_pending() to
		// see if it can get actual bytes and gradually builds up a complete
		// request.
		// Once the request is complete and we no longer need any bytes from
		// the client, it dispatches the request to a worker via a pipe. The
		// worker doesn't deal with encryption but may still need to know
		// details from the client (like its cert).
		// Drawback is if spammy clients all land on the same process
		// (because OS decides which accept() returns), then we may start
		// stalling all requests going to that child.
		//
		// Or with pthread for better load distribution?
		// In which case we'd start filling up a BIO_s_mem inside one struct
		// per client putting it on a queue, where a worker thread can
		// call SSL_pending() and start constructing the buffer if there's
		// data available. It puts it back on a pending queue if more data
		// is needed where the listener thread can then add more to it, or
		// destroy it after waiting for a certain time.
		// This means the listener thread doesn't do encryption/decryption
		// and only need to shuffle bytes around and do kqueue(), pretty
		// lightweight.
		// Workers do the heavy lifting, but if they're all busy we're not
		// timing out new clients who can still start sending bytes.
		//
		// We can also set cipher preference on server:
		// look for SSL_OP_CIPHER_SERVER_PREFERENCE
		// This is nice because we can pick AES256 which may have CPU
		// offload thus better performance.

	}
	exit(0);
}
#endif

void
tlsev_run(int lsock, SSL_CTX *ctx, int max_clients)
{
#ifdef __OpenBSD__
	handle_clients_kqueue(lsock, ctx, max_clients);
#else
	handle_clients_epoll(lsock, ctx, max_clients);
#endif
}

void
tlsev_shutdown()
{
	shutdown_triggered = 1;
}
