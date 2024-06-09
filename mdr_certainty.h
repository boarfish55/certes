#ifndef MDR_CERTAINTY_H
#define MDR_CERTAINTY_H

#include "mdr.h"

#define MDR_NS_CERTAINTY 0x00000002

#define MDR_ID_CERTAINTY_BOOTSTRAP 0x0001
#define MDR_ID_CERTAINTY_BEMSG     0x0002

int pack_bemsg(struct mdr *, uint64_t, int, struct mdr *, X509 *);

#endif
