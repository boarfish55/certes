#ifndef FLATCONF_H
#define FLATCONF_H

#include <stdint.h>

enum flatconf_var_type {
	FLATCONF_NONE = 0,
	FLATCONF_STRING,
	FLATCONF_ALLOCSTRING,
	FLATCONF_ALLOCSTRINGLIST,
	FLATCONF_ALLOCULONGLIST,
	FLATCONF_BOOLINT,
	FLATCONF_LONG,
	FLATCONF_ULONG
};

#define FLATCONF_LAST        { "", 0, NULL, 0 }
#define FLATCONF_VAR_MAX_LEN 255

struct flatconf {
	char                    name[FLATCONF_VAR_MAX_LEN + 1];
	enum flatconf_var_type  t;
	void                   *dst;
	size_t                  dst_sz;
};

int  flatconf_read(const char *, struct flatconf *, void(*)(const char *));
void flatconf_free(struct flatconf *);

#endif
