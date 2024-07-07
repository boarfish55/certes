#ifndef UTIL_H
#define UTIL_H

int     is_hex_str(const char *);
ssize_t readall(int, void *, size_t);
ssize_t writeall(int, const void *, size_t);

#endif
