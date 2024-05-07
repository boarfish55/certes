#ifndef TLSEV_H
#define TLSEV_H

#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <netdb.h>
#include "xlog.h"

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

void                 tlsev_init(int, int,
                         int (*)(struct tlsev *, const char *, size_t, void *),
                         void (*)(void *));
void                 tlsev_run(int, SSL_CTX *, int);
void                 tlsev_shutdown();
X509                *tlsev_peer_cert(struct tlsev *);
struct sockaddr_in6 *tlsev_peer(struct tlsev *);
int                  tlsev_reply(struct tlsev *, const char *, int);

#endif
