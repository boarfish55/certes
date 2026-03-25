#ifndef MDR_MDRD_H
#define MDR_MDRD_H

#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include "mdr.h"

/* Backend response flags */
#define MDRD_BEOUT_FNONE  0x00000000
#define MDRD_BEOUT_FCLOSE 0x00000001  /* Client connection should be closed */

__BEGIN_DECLS

struct mdrd_besession
{
	uint64_t                     id;
	int                          fd;
	int                          is_new;
	X509                        *cert;
	struct sockaddr_in6          peer;
	socklen_t                    peer_len;
	void                        *data;
	void                         (*free_data)(void *);
	SPLAY_ENTRY(mdrd_besession)  entries;
};

ptrdiff_t mdrd_recv(struct umdr *, void *, size_t, size_t, uint64_t,
              uint32_t, struct mdrd_besession **);
void      mdrd_besession_set_data(struct mdrd_besession *, void *,
              void(*)(void *));

int mdrd_unpack_beclose(struct umdr *, uint64_t *);
int mdrd_unpack_bein(struct umdr *, uint64_t *, int *, struct sockaddr *,
        socklen_t *, struct umdr *, X509 **);
int mdrd_unpack_besesserr(struct umdr *, uint64_t *);
int mdrd_beout_error(struct mdrd_besession *, uint32_t, uint32_t,
        const char *);
int mdrd_beout_ok(struct mdrd_besession *, uint32_t);
int mdrd_beout(struct mdrd_besession *, uint32_t, const struct pmdr *);

__END_DECLS

#endif
