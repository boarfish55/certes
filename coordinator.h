#ifndef COORDINATOR_H
#define COORDINATOR_H

#include "mdr.h"
#include "xlog.h"

int coordinator_send(struct mdr *, struct xerr *);
int coordinator_recv(struct mdr *, char *, size_t, struct xerr *);

#endif
