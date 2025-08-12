#ifndef CERTDB_H
#define CERTDB_H

#include <stdint.h>
#include <time.h>
#include "xlog.h"

#define CERTDB_FLAG_NONE    0x00000000
#define CERTDB_FLAG_REVOKED 0x00000001
#define CERTDB_FLAG_ALL     0xFFFFFFFF

#define CERTDB_BOOTSTRAP_KEY_LENGTH_B64 64
#define CERTDB_BOOTSTRAP_KEY_LENGTH     48

struct bootstrap_entry {
	char     bootstrap_key[CERTDB_BOOTSTRAP_KEY_LENGTH];
	time_t   valid_until_sec;
	char    *subject;
	char   **sans;
	size_t   sans_sz;
	char   **roles;
	size_t   roles_sz;
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
};

int  certdb_init(const char *, struct xerr *);
void certdb_shutdown();

int  certdb_put_bootstrap(const struct bootstrap_entry *, struct xerr *);
int  certdb_get_bootstrap(struct bootstrap_entry *, const char *,
         struct xerr *);
int  certdb_put_cert(const struct cert_entry *, struct xerr *);
int  certdb_get_cert(struct cert_entry *, const char *, struct xerr *);

#endif
