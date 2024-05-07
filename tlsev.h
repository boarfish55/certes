#ifndef TLSEV_H
#define TLSEV_H

#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <netdb.h>
#include "idxheap.h"
#include "xlog.h"

struct tlsev_listener;

struct tlsev {
	uint64_t             id;
	int                  fd;
	SSL                 *ssl;
	BIO                 *r;
	BIO                 *w;
	struct timespec      timeout_at;

	struct sockaddr_in6  peer_addr;
	X509                *peer_cert;

	char                *retry_buf;
	int                  retry_len;

	void                *in_cb_data;
};

struct tlsev_listener {
	SSL_CTX               *ctx;
	int                    lsock;
	int                    socket_timeout;
	int                    max_clients;
	int                    tlsev_data_idx;
	uint64_t               next_id;
	struct idxheap         tlsev_store;
	volatile sig_atomic_t  shutdown_triggered;

	int  (*tlsev_in_cb)(struct tlsev *, const char *, size_t, void *);
	void (*tlsev_in_cb_data_free)(void *);
};

int                  tlsev_init(struct tlsev_listener *, SSL_CTX *, int,
                         int, int, int,
			 int (*in_cb)(struct tlsev *, const char *,
			 size_t, void *),
			 void (*in_cb_data_free)(void *));
void                 tlsev_run(struct tlsev_listener *);
void                 tlsev_shutdown(struct tlsev_listener *);
X509                *tlsev_peer_cert(struct tlsev *);
struct sockaddr_in6 *tlsev_peer(struct tlsev *);
int                  tlsev_reply(struct tlsev *, const char *, int);
uint64_t             tlsev_id(struct tlsev *);

#endif
