#ifndef MDR_MDRD_H
#define MDR_MDRD_H

#include <openssl/x509.h>
#include <stdint.h>
#include "mdr.h"

/* Backend response statuses */
#define MDRD_ST_OK       0
#define MDRD_ST_DENIED   1  /* Client is denied this operation */
#define MDRD_ST_CERTFAIL 2  /* Client certificate verification failed */

/* Backend response flags */
#define MDRD_BERESP_F_NONE  0x00000000
#define MDRD_BERESP_F_CLOSE 0x00000001  /* Client connection should be closed */

int mdrd_unpack_beclose(struct mdr *, uint64_t *);
int mdrd_unpack_bereq(struct mdr *, uint64_t *, int *, struct mdr *, X509 **);
int mdrd_unpack_error(struct mdr *, uint32_t *, const char **, uint64_t *);

#endif
