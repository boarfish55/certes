#ifndef COORDINATOR_H
#define COORDINATOR_H

#include "mdr.h"
#include "xlog.h"

int coordinator_send(struct pmdr *, struct xerr *);
int coordinator_recv(void *, size_t, struct xerr *);

#endif
