#ifndef AUTHORITY_H
#define AUTHORITY_H

#include "certdb.h"
#include "mdr.h"
#include "mdrd.h"
#include "xlog.h"

int  authority_bootstrap_setup(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_bootstrap_dialin(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_bootstrap_answer(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_cert_renewal_inquiry(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_cert_renew_answer(struct mdrd_besession *, struct umdr *,
         struct xerr *);

#endif
