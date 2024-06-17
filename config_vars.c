#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "config_vars.h"
#include "xlog.h"

static int
config_vars_get_ulong(void *dst, size_t sz, const char *v, struct xerr *e)
{
	unsigned long  ul;
	const char    *p;
	int            end_found = 0;

	for (p = v; *p != '\0'; p++) {
		/*
		 * Garbage after trailing spaces
		 */
		if (end_found && !isspace(*p))
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "garbage after trailing spaces");

		if (isdigit(*p))
			continue;

		if (isspace(*p)) {
			end_found = 1;
			continue;
		}

		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "non-numeric characters in numeric value");
	}

	if (sz < sizeof(unsigned long))
		return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "variable too small for unsigned long");

	if ((ul = strtoul(v, NULL, 10)) == ULONG_MAX)
		return XERRF(e, XLOG_ERRNO, errno,
		    "strtoul returned ULONG_MAX");

	*((unsigned long *)dst) = ul;
	return 0;
}

static int
config_vars_get_allocstring(void *dst, size_t sz, const char *v, struct xerr *e)
{
	char **pdst = (char **)dst;

	if (strlen(v) >= sz)
		return XERRF(e, XLOG_APP, XLOG_RANGE,
		    "variable length greater than limit");

	if ((*pdst = malloc(sz)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	if (strlcpy(*pdst, v, sz) >= sz)
		return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "value too large to fit in variable");

	return 0;
}

static int
config_vars_get_string(void *dst, size_t sz, const char *v, struct xerr *e)
{
	if (strlen(v) >= sz)
		return XERRF(e, XLOG_APP, XLOG_RANGE,
		    "variable length greater than limit");

	if (strlcpy((char *)dst, v, sz) >= sz)
		return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "value too large to fit in variable");

	return 0;
}

static int
config_vars_get_boolint(void *dst, size_t sz, const char *v, struct xerr *e)
{
	if (strcmp(v, "yes") == 0 || strcmp(v, "true") == 0) {
		*((int *)dst) = 1;
	} else if (strcmp(v, "no") == 0 || strcmp(v, "false") == 0) {
		*((int *)dst) = 0;
	} else {
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "value is not a valid boolean");
	}
	return 0;
}

int
config_vars_read(const char *cfg_path, struct config_vars *cfg_vars)
{
        char                buf[PATH_MAX + 32];
        char               *line;
        int                 line_n = 0;
	char               *p, *v;
        FILE               *cfg;
	struct config_vars *cv;
	int                 r, known;
	struct xerr         e;
	long                pwnam_sz;
	long                grnam_sz;

	if ((pwnam_sz = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
		xlog(LOG_WARNING, NULL,
		    "sysconf(_SC_GETPW_R_SIZE_MAX)) failed; "
		    "defaulting to 16384");
		pwnam_sz = 16384;
	}
	if ((grnam_sz = sysconf(_SC_GETGR_R_SIZE_MAX)) == -1) {
		xlog(LOG_WARNING, NULL,
		    "sysconf(_SC_GETGR_R_SIZE_MAX)) failed; "
		    "defaulting to 16384");
		grnam_sz = 16384;
	}

	if ((cfg = fopen(cfg_path, "r")) == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), cfg)) {
		line_n++;
		line = buf;

		while (*line == ' ')
			line++;

		if (*line == '#' || *line == '\n' || *line == '\0')
			continue;

		p = strtok(line, ":");
		if (p == NULL) {
			xlog(LOG_WARNING, NULL,
			    "invalid line in configuration: %d", line_n);
			continue;
		}

		v = strtok(NULL, "\n");
		if (v == NULL) {
			xlog(LOG_WARNING, NULL,
			    "invalid line in configuration; no value: %d",
			    line_n);
			continue;
		}

		while (*v == ' ')
			v++;

		known = 0;
		for (cv = cfg_vars; cv->t != CONFIG_VARS_NONE; cv++) {
			if (strcmp(cv->name, p) != 0)
				continue;

			known = 1;
			r = 0;
			switch (cv->t) {
			case CONFIG_VARS_STRING:
				r = config_vars_get_string(cv->dst,
				    cv->dst_sz, v, xerrz(&e));
				break;
			case CONFIG_VARS_ULONG:
				r = config_vars_get_ulong(cv->dst,
				    cv->dst_sz, v, xerrz(&e));
				break;
			case CONFIG_VARS_BOOLINT:
				r = config_vars_get_boolint(cv->dst,
				    cv->dst_sz, v, xerrz(&e));
				break;
			case CONFIG_VARS_PWNAM:
				cv->dst_sz = pwnam_sz;
				r = config_vars_get_allocstring(cv->dst,
				    pwnam_sz, v, xerrz(&e));
				break;
			case CONFIG_VARS_GRNAM:
				cv->dst_sz = grnam_sz;
				r = config_vars_get_allocstring(cv->dst,
				    cv->dst_sz, v, xerrz(&e));
				break;
			default:
				xlog(LOG_WARNING, NULL,
				    "failed to parse value for "
				    "%s at line %d; undefined type",
				    p, line_n);
			}
			if (r == -1) {
				xlog(LOG_WARNING, &e,
				    "failed to parse value for "
				    "%s at line %d", p, line_n);
			}
			break;
		}
		if (!known) {
			xlog(LOG_WARNING, NULL,
			    "unknown configuration parameter "
			    "%s at line %d; undefined type",
			    p, line_n);
		}
	}
	fclose(cfg);
	return 0;
}

void
config_vars_free(struct config_vars *cfg_vars)
{
	struct config_vars *cv;

	for (cv = cfg_vars; cv->t != CONFIG_VARS_NONE; cv++) {
		switch (cv->t) {
		case CONFIG_VARS_STRING:
		case CONFIG_VARS_ULONG:
		case CONFIG_VARS_BOOLINT:
			/* Nothing allocated */
			break;
		case CONFIG_VARS_PWNAM:
		case CONFIG_VARS_GRNAM:
			/* Only free if we actually allocated this variable */
			if (cv->dst_sz > 0)
				free(*((char **)cv->dst));
			break;
		default:
			xlog(LOG_ERR, NULL, "unknown var %s", cv->name);
		}
	}
}
