/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifndef AUTHORITY_H
#define AUTHORITY_H

#include <mdr/mdr.h>
#include <mdr/mdrd.h>
#include <mdr/xlog.h>
#include "certdb.h"

int  authority_bootstrap_setup(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_revoke(struct mdrd_besession *, struct umdr *, struct xerr *);
int  authority_bootstrap_dialin(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_bootstrap_answer(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_cert_renewal_inquiry(struct mdrd_besession *, struct umdr *,
         struct xerr *);
int  authority_cert_renew_answer(struct mdrd_besession *, struct umdr *,
         struct xerr *);

#endif
