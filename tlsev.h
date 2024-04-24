#ifndef TLSEV_H
#define TLSEV_H

#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <netdb.h>
#include "xlog.h"

struct tlsev {
	int                  fd;
	SSL                 *ssl;
	BIO                 *r;
	BIO                 *w;
	struct timespec      timeout_at;

	struct sockaddr_in6  peer_addr;
	X509                *peer_cert;

	char                 retry_buf[4096];
	int                  retry_len;

	char                 in_buf[4096];
	int                  in_len;

	struct tlsev        *next;

	// TODO: maybe a read queue and a write queue?
};

void          tlsev_init(int, int);
int           tlsev_create(int, SSL_CTX *,
                  struct sockaddr_in6 *, struct xerr *);
void          tlsev_close(struct tlsev *);
struct tlsev *tlsev_get(int);
int           tlsev_in(struct tlsev *, struct xerr *);
int           tlsev_out(struct tlsev *, struct xerr *);
int           tlsev_read(struct tlsev *, char *, int, struct xerr *);
int           tlsev_write(struct tlsev *, const char *, int, struct xerr *);
int           tlsev_bio_pending(struct tlsev *, int *, int *, struct xerr *);
void          tlsev_run(int, SSL_CTX *, int);
void          tlsev_shutdown();

#endif
