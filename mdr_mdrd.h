#ifndef MDR_MDRD_H
#define MDR_MDRD_H

#include <openssl/x509.h>
#include <stdint.h>
#include "mdr.h"

int mdr_unpack_bemsg(struct mdr *, uint64_t *, int *, struct mdr *,
        char *, uint64_t *, X509 **);

#endif
