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
#define MDRD_BERESP_F_MSG   0x00000002  /* Response contains a message */

int mdrd_unpack_beclose(struct mdr *, uint64_t *);
int mdrd_unpack_bereq(struct mdr *, uint64_t *, int *, struct mdr *,
        char *, size_t, X509 **);
int mdrd_unpack_bereq_ref(struct mdr *, uint64_t *, int *, struct mdr *,
        X509 **);
int mdrd_pack_beresp(struct mdr *, char *, size_t, uint64_t, int,
        uint32_t, uint32_t, struct mdr *);
int mdrd_pack_error(struct mdr *, char *, size_t, uint32_t, const char *);
int mdrd_unpack_error(struct mdr *, uint32_t *, char *, uint64_t *);

#endif
