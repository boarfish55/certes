#ifndef CERTDB_H
#define CERTDB_H

#include <stdint.h>
#include <time.h>
#include "xlog.h"

#define CERTDB_FLAG_NONE    0x00000000
#define CERTDB_FLAG_REVOKED 0x00000001
#define CERTDB_FLAG_ALL     0xFFFFFFFF

struct bootstrap_entry {
	char     one_time_key[32];
	time_t   valid_until_sec;
	char    *subject;
	char   **sans;
	char     sans_sz;
	char    *roles;
	time_t   not_before_sec;
	time_t   not_after_sec;
};

struct cert_entry {
	char      *serial;
	char      *subject;
	char     **sans;
	char       sans_sz;
	char      *roles;
	time_t     not_before_sec;
	time_t     not_after_sec;
	uint32_t   flags;
};

int  certdb_init(const char *, struct xerr *);
void certdb_shutdown();

int  certdb_put_bootstrap(const struct bootstrap_entry *, struct xerr *);

#endif
