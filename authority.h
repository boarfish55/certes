#ifndef AUTHORITY_H
#define AUTHORITY_H

#include "certdb.h"
#include "mdr.h"
#include "xlog.h"

int  authority_bootstrap_setup(const char *, const char **, size_t,
         const char **, size_t, uint32_t, uint32_t, uint32_t, struct xerr *);
int  authority_bootstrap_setup_msg(struct umdr *, struct xerr *);
int  authority_bootstrap_setup_cli(int, char **, struct xerr *);
int  authority_challenge(struct bootstrap_entry *, const char *,
         const uint8_t *, struct xerr *);
int  authority_bootstrap_dialin(struct umdr *, struct xerr *);
int  authority_bootstrap_req(struct umdr *, struct xerr *);

#endif
