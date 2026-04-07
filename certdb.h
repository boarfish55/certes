/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#ifndef CERTDB_H
#define CERTDB_H

#include <stdint.h>
#include <time.h>
#include <mdr/xlog.h>
#include "certes.h"

#define CERTDB_BOOTSTRAP_FLAG_NONE  0x00000000
#define CERTDB_BOOTSTRAP_FLAG_SETCN 0x00000001

#define CERTDB_FLAG_NONE    0x00000000
#define CERTDB_FLAG_REVOKED 0x00000001
#define CERTDB_FLAG_ALL     0xFFFFFFFF

struct bootstrap_entry {
	char     bootstrap_key[CERTES_BOOTSTRAP_KEY_LENGTH];
	time_t   valid_until_sec;
	char    *subject;
	char   **sans;
	size_t   sans_sz;
	char   **roles;
	size_t   roles_sz;
	uint32_t flags;
	time_t   not_before_sec;
	time_t   not_after_sec;
};

struct cert_entry {
	char      *serial;
	char      *subject;
	char     **sans;
	size_t     sans_sz;
	char     **roles;
	size_t     roles_sz;
	time_t     not_before_sec;
	time_t     not_after_sec;
	uint32_t   flags;
	uint8_t   *der;
	size_t     der_sz;
};

int  certdb_init(const char *, struct xerr *);
void certdb_shutdown();
int  certdb_backup(const char *, int, struct xerr *);

struct bootstrap_entry *certdb_get_bootstrap(const uint8_t *, size_t,
                            struct xerr *);
void                    certdb_bootstrap_free(struct bootstrap_entry *);
int                     certdb_put_bootstrap(const struct bootstrap_entry *,
                            struct xerr *);
int                     certdb_del_bootstrap(const struct bootstrap_entry *,
                            struct xerr *);
int                     certdb_clean_expired_bootstraps(struct xerr *);

struct cert_entry *certdb_get_cert(const char *, struct xerr *);
void               certdb_cert_free(struct cert_entry *);
int                certdb_put_cert(const struct cert_entry *, struct xerr *);
int                certdb_clean_expired_certs(struct xerr *);

#endif
