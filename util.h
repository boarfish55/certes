#ifndef UTIL_H
#define UTIL_H

#include "xlog.h"

int is_hex_str(const char *);
int daemonize(const char *, const char *, int, int, struct xerr *);
int drop_privileges(const char *, const char *, struct xerr *);

#endif
