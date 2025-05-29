#ifndef UTIL_H
#define UTIL_H

int       is_hex_str(const char *);
ssize_t   readall(int, void *, size_t);
ssize_t   writeall(int, const void *, size_t);
char    **strlist_add(char **, const char *);
int       strlist_join(char **, size_t, char **);
int       strlist_split(char ***, const char *, size_t);

#endif
