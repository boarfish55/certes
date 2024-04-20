#ifndef CONFIG_VARS_H
#define CONFIG_VARS_H

enum config_vars_type {
	CONFIG_VARS_NONE = 0,
	CONFIG_VARS_STRING,
	CONFIG_VARS_BOOLINT,
	CONFIG_VARS_ULONG,
	CONFIG_VARS_PWNAM,
	CONFIG_VARS_GRNAM
};

#define CONFIG_VARS_LAST { "", 0, NULL, 0 }

struct config_vars {
	char                   name[256];
	enum config_vars_type  t;
	void                  *dst;
	size_t                 dst_sz;
};

int  config_vars_read(const char *, struct config_vars *);
void config_vars_free(struct config_vars *);

#endif
