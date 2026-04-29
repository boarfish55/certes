/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifndef AGENT_H
#define AGENT_H

#include <stdio.h>
#include <openssl/x509.h>
#include <mdr/mdr.h>
#include <mdr/xlog.h>

struct loaded_crls {
	uint32_t   count;
	char     **issuers;
	uint64_t  *last_updates;
	X509_CRL **crls;
};

int         agent_load_keys(struct xerr *);
int         agent_is_authority();
void        agent_cleanup();
X509       *agent_cert();
EVP_PKEY   *agent_key();
X509_STORE *agent_cert_store();
X509_STORE *agent_cert_store();
int         agent_init(struct xerr *);
int         agent_start(struct xerr *);
void        agent_cli_bootstrap_setup(int, char **);
void        agent_cli_revoke(int, char **);
int         agent_send(const void *, size_t, struct xerr *);
int         agent_recv(void *, size_t, struct xerr *);
int         agent_reload_crls(struct xerr *);
int         agent_get_crl(const char *, const X509_CRL **, uint64_t *);

const struct loaded_crls *agent_get_loaded_crls();

#endif
