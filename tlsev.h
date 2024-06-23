#ifndef TLSEV_H
#define TLSEV_H

#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <netdb.h>
#include "idxheap.h"
#include "xlog.h"

struct tlsev;

struct tlsev_fd_cb {
	int  fd;
	int  (*cb)(int fd);
};

struct tlsev_listener {
	SSL_CTX               *ctx;
	int                   *lsock;
	size_t                 lsock_len;
	int                    socket_timeout;
	int                    tlsev_data_idx;
	uint64_t               next_id;
	struct idxheap         tlsev_store;
	volatile sig_atomic_t  shutdown_triggered;

	int                    active_clients;
	int                    accepting;
	int                    max_clients;

#ifdef __OpenBSD__
	int                    kq;
	/*
	 * This needs to be here so we can resize it when we add new
	 * fd callbacks.
	 */
	struct kevent         *events;
	struct kevent         *ch;
	int                    chn;
#else
	int                    epollfd;
	struct epoll_event    *events;
#endif
	int                    max_events;

	int  (*in_cb)(struct tlsev *, const char *, size_t, void **);
	void (*in_cb_data_free)(void *);

	struct tlsev_fd_cb    *fd_callbacks;
	size_t                 fd_callbacks_sz;
	size_t                 fd_callbacks_used;
};

struct tlsev {
	struct tlsev_listener *listener;
	uint64_t               id;
	int                    fd;
	SSL                   *ssl;
	BIO                   *r;
	BIO                   *w;
	int                    wpending;
	struct timespec        timeout_at;

	struct sockaddr_in6    peer_addr;
	X509                  *peer_cert;

	char                  *retry_buf;
	int                    retry_len;

	void                  *in_cb_data;
};

int                  tlsev_init(struct tlsev_listener *, SSL_CTX *, int *,
                         size_t, int, int, int,
			 int (*in_cb)(struct tlsev *, const char *,
			 size_t, void **),
			 void (*in_cb_data_free)(void *));
int                  tlsev_add_fd_cb(struct tlsev_listener *,
                         struct tlsev_fd_cb *);
void                 tlsev_destroy(struct tlsev_listener *);
int                  tlsev_run(struct tlsev_listener *);
void                 tlsev_shutdown(struct tlsev_listener *);
X509                *tlsev_peer_cert(struct tlsev *);
struct sockaddr_in6 *tlsev_peer(struct tlsev *);
int                  tlsev_reply(struct tlsev *, const char *, int);
uint64_t             tlsev_id(struct tlsev *);
int                  tlsev_fd(struct tlsev *);
struct tlsev *       tlsev_get(struct tlsev_listener *, int);

#endif
