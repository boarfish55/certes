#ifndef TLSEV_H
#define TLSEV_H

#include <openssl/bio.h>
#include "xlog.h"

struct tlsev {
	int           fd;
	SSL          *ssl;
	BIO          *r;
	BIO          *w;

	// TODO: store cert here? and peer name?

	char          retry_buf[4096];
	int           retry_len;

	char          in_buf[4096];
	int           in_len;

	struct tlsev *next;
};

void          tlsev_init();
int           tlsev_create(int, SSL_CTX *, struct xerr *);
void          tlsev_close(struct tlsev *);
struct tlsev *tlsev_get(int);
int           tlsev_in(struct tlsev *, struct xerr *);
int           tlsev_out(struct tlsev *, struct xerr *);
int           tlsev_read(struct tlsev *, char *, int, struct xerr *);
int           tlsev_write(struct tlsev *, const char *, int, struct xerr *);
int           tlsev_bio_pending(struct tlsev *, int *, int *, struct xerr *);

#endif
