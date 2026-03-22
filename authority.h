#ifndef AUTHORITY_H
#define AUTHORITY_H

#include "certdb.h"
#include "mdr.h"
#include "xlog.h"

int  authority_bootstrap_setup(uint64_t, int, struct umdr *, struct xerr *);
int  authority_bootstrap_dialin(uint64_t, int, struct umdr *, struct xerr *);
int  authority_bootstrap_req(uint64_t, int, struct umdr *, struct xerr *);

#endif
