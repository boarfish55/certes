#ifndef MDR_MDRD_H
#define MDR_MDRD_H

#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include "mdr.h"

/* Backend response flags */
#define MDRD_BERESP_FNONE  0x00000000
#define MDRD_BERESP_FCLOSE 0x00000001  /* Client connection should be closed */

__BEGIN_DECLS

int mdrd_unpack_beclose(struct umdr *, uint64_t *);
int mdrd_unpack_bereq(struct umdr *, uint64_t *, int *, struct sockaddr *,
        socklen_t *, struct umdr *, X509 **);
int mdrd_unpack_besesserr(struct umdr *, uint64_t *);
int mdrd_pack_error(struct pmdr *, uint64_t, int, uint32_t flags,
        uint32_t, const char *);

__END_DECLS

#endif
