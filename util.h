#ifndef UTIL_H
#define UTIL_H

int    is_hex_str(const char *);
char **strlist_add(char **, const char *);
int    strlist_join(char **, size_t, char **);
int    strlist_split(char ***, const char *, size_t);
int    b64enc(char *, size_t, const uint8_t *, size_t);
int    b64dec(uint8_t *, size_t, const char *);
int    open_wflock(const char *, int, mode_t, int);

#endif
