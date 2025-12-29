#ifndef AGENT_H
#define AGENT_H

#include <stdio.h>
#include <openssl/x509.h>
#include "xlog.h"

int         agent_load_keys(struct xerr *);
int         agent_is_authority();
void        agent_cleanup();
X509       *agent_cert();
EVP_PKEY   *agent_key();
X509_STORE *agent_cert_store();
int         agent_init(struct xerr *);

#endif
