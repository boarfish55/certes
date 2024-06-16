#ifndef UTIL_H
#define UTIL_H

#include "xlog.h"

int is_hex_str(const char *);
int daemonize(const char *, const char *, int, int, struct xerr *);
int drop_privileges(const char *, const char *, struct xerr *);

ssize_t writeall(int, const void *, size_t);

#define CLOSE_X(fd) close_x(fd, #fd, __func__, __LINE__)
void   close_x(int, const char *, const char *, int);
int    spawn(char *const[], int *, int *, const char *,
           const char *, struct xerr *);
char **cmdargv(char *);

#endif
