#ifndef MDR_MDRD_H
#define MDR_MDRD_H

#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include "mdr.h"

/* Backend errors with no session information */
#define MDRD_ERROR_OS        1

/* Backend response statuses */
#define MDRD_BERESP_OK       0
#define MDRD_BERESP_DENIED   1  /* Client is denied this operation */
#define MDRD_BERESP_CERTFAIL 2  /* Client certificate verification failed */
#define MDRD_BERESP_NOCERT   3  /* Client certificate is missing */
#define MDRD_BERESP_BEFAIL   4  /* A failure on the backend prevented successful
			           completion */
#define MDRD_BERESP_BADMSG   5  /* Bad message format, or unsupported message */

/* Backend response flags */
#define MDRD_BERESP_FNONE  0x00000000
#define MDRD_BERESP_FCLOSE 0x00000001  /* Client connection should be closed */

__BEGIN_DECLS

int mdrd_unpack_beclose(struct umdr *, uint64_t *);
int mdrd_unpack_bereq(struct umdr *, uint64_t *, int *, struct sockaddr *,
        socklen_t *, struct umdr *, X509 **);
int mdrd_unpack_error(struct umdr *, uint32_t *, const char **, uint64_t *);

__END_DECLS

#endif
