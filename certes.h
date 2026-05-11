/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifndef CERTES_H
#define CERTES_H

#include <limits.h>
#include <mdr/xlog.h>
#include "mdr_certes.h"

#define MAX_HEX_SERIAL_LENGTH 32
#define MAX_ACTIVE_CHALLENGES 32

#define CERTES_PROGNAME "certes"
#define CERTES_AGENT_PROGNAME "certes-agent"

#define CERTES_AGENT_PORT 9790

#define CERTES_BOOTSTRAP_KEY_LENGTH_B64 64
#define CERTES_BOOTSTRAP_KEY_LENGTH     48
#define CERTES_MAX_MSG_SIZE             16384

#define CERTES_CHALLENGE_LENGTH         32
#define CERTES_AUTHOP_ID_LENGTH         64 /* 3x 64-bit uints to string, so ~50 */

#define CERTES_MAX_SUBJET_LENGTH 1024
#define CERTES_MAX_SAN_LENGTH    512
#define CERTES_MAX_SANS          16
#define CERTES_MAX_ROLE_LENGTH   64
#define CERTES_MAX_ROLES         256

#define CERTES_SHM "/certes"

/* Built-in roles */
#define ROLE_AUTHORITY "authority"  /* Can issue certs */
#define ROLE_CAPROXY   "caproxy"    /* Can be trusted to be a frontend for
				       an authority */
#define ROLE_BOOTSTRAP "bootstrap"  /* Can create bootstrap entries */
#define ROLE_CERTADMIN "certadmin"  /* Can lookup and revoke certs */
#define ROLE_AGENT     "agent"      /* Agent that handles automatic cert
				       renewals */

struct certes_flatconf {
	// TODO: enable_coredumps is not used, and maybe not useful since
	// it is a child of mdrd
	int        enable_coredumps;
	uint64_t   agent_bootstrap_port;
	char       authority_fqdn[256];
	uint64_t   authority_port;
	char     **peer_authorities;
	char       certdb_path[PATH_MAX];
	char       certdb_backup_path[PATH_MAX];
	uint64_t   certdb_backup_interval_seconds;
	uint64_t   certdb_backup_pages_per_step;
	uint64_t   agent_send_timeout_ms;
	uint64_t   agent_recv_timeout_ms;
	char       bootstrap_key[CERTES_BOOTSTRAP_KEY_LENGTH_B64 + 1];
	uint64_t   challenge_timeout_seconds;
	char       root_cert_file[PATH_MAX];
	char       crl_path[PATH_MAX];
	uint64_t   crl_reload_interval_seconds;
	char       key_file[PATH_MAX];
	char       cert_file[PATH_MAX];
	char       lock_file[PATH_MAX];
	char       agent_sock_path[PATH_MAX];
	uint64_t   max_cert_size;
	uint64_t   cert_min_lifetime_seconds;
	uint64_t   cert_renew_lifetime_seconds;
	uint64_t   cert_check_interval_seconds;
	uint64_t   cert_expired_retention_seconds;
	char       cert_org[256];
	char       cert_email[512];
	char       roles_oid[64];

	/* Leave space for "0x" and terminating zero */
	char       min_serial[MAX_HEX_SERIAL_LENGTH + 3];
	char       max_serial[MAX_HEX_SERIAL_LENGTH + 3];
};

struct certes_session {
	int       verified;

	/* Used for dialin/req request */
	uint8_t  *challenge;
	uint8_t  *bootstrap_key;
	X509_REQ *req;
};

char *certes_client_name(struct mdrd_besession *, char *, size_t,
      struct xerr *);

#endif
