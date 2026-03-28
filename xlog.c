#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "xlog.h"

const struct module_dbg_map_entry module_dbg_map[] = {
	{ "all",       XLOG_ALL },
	{ "",          0x0000 }
};

static xlog_mask_t  debug_mask = 0;
FILE               *log_file = NULL;
static int          log_level = LOG_INFO;

struct xerr *
xerrz(struct xerr *e)
{
	if (e == NULL)
		return NULL;

	e->sp = 0;
	e->code = 0;
	e->msg[0] = '\0';
	return e;
}

int
xerrf(struct xerr *e, int space, int code, const char *fmt, ...)
{
	va_list  ap;
	int      written;
	int      status = (space || code) ? -1 : 0;

	if (e == NULL)
		return status;

	e->sp = space;
	e->code = code;
	e->msg[0] = '\0';

	if (fmt == NULL)
		return status;

	va_start(ap, fmt);
	written = vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
	va_end(ap);

	if (written >= sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';

	return status;
}

int
xerrfn(struct xerr *e, int space, int code, const char *fn,
    const char *fmt, ...)
{
	va_list  ap;
	int      written;
	int      status = (space || code) ? -1 : 0;
	char     pfmt[LINE_MAX];

	if (e == NULL)
		return status;

	e->sp = space;
	e->code = code;
	e->msg[0] = '\0';

	if (fmt == NULL)
		return status;

	written = snprintf(pfmt, sizeof(pfmt), "%s: %s", fn, fmt);
	if (written >= sizeof(pfmt))
		pfmt[sizeof(pfmt) - 2] = '*';
	va_start(ap, fmt);
	written = vsnprintf(e->msg, sizeof(e->msg), pfmt, ap);
	va_end(ap);

	if (written >= sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';

	return status;
}

int
xerr_fail(const struct xerr *e)
{
	if (e == NULL)
		return 0;

	return (e->sp || e->code) ? -1 : 0;
}

int
xerr_is(const struct xerr *e, int code, int subcode)
{
	if (e == NULL)
		return 0;

	if (e->sp == code && e->code == subcode)
		return subcode;

	return 0;
}

static void
xlog_fprintf(const char *fmt, ...)
{
	va_list   ap;
	char      msg[LINE_MAX], t_str[64];
	struct tm tm;
	time_t    t;

	if (log_file == NULL)
		return;

	t = time(NULL);
	if (localtime_r(&t, &tm) == NULL)
		return;

	strftime(t_str, sizeof(t_str), "%FT%R:%S%z", &tm);

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	fprintf(log_file, "%s/%d: %s\n", t_str, getpid(), msg);
	fflush(log_file);
}

int
xlog_init(const char *progname, const char *dbg_spec, const char *logf,
    int perror)
{
	char                              *dbg, *module, *save;
	const struct module_dbg_map_entry *map;
	int                                opt = LOG_PID;

	if (perror)
		opt |= LOG_PERROR;

	if (logf != NULL && logf[0] != '\0' && log_file == NULL)
		if ((log_file = fopen(logf, "a")) == NULL)
			warn("fopen");

	openlog(progname, opt, LOG_USER);
	if (dbg_spec == NULL || *dbg_spec == '\0') {
		setlogmask(LOG_UPTO(LOG_INFO));
		return 0;
	}

	dbg = strdup(dbg_spec);
	if (dbg == NULL)
		return -1;

	log_level = LOG_DEBUG;
	setlogmask(LOG_UPTO(LOG_DEBUG));
	for ((module = strtok_r(dbg, ",", &save)); module;
	    (module = strtok_r(NULL, ",", &save))) {
		for (map = module_dbg_map; *map->name; map++) {
			if (strcmp(map->name, module) == 0) {
				debug_mask |= map->flag;
				syslog(LOG_DEBUG, "enabling %s debug logging",
				    map->name);
				xlog_fprintf("enabling %s debug logging",
				    map->name);
			}
		}
	}
	free(dbg);

	return 0;
}

void
xlog_dbg(xlog_mask_t module, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];

	if (fmt == NULL || (module & debug_mask) == 0)
		return;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	syslog(LOG_DEBUG, "%s", msg);
	xlog_fprintf("%s", msg);
}

void
xlog(int priority, const struct xerr *e, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];
	char    errmsg[256] = "";
	size_t  written;

	if (priority > log_level)
		return;

	if (e == NULL) {
		if (fmt != NULL) {
			va_start(ap, fmt);
			vsnprintf(msg, sizeof(msg), fmt, ap);
			va_end(ap);
			syslog(priority, "%s", msg);
			xlog_fprintf("%s", msg);
		}
		return;
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		written = vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);

		if (written >= sizeof(msg))
			msg[sizeof(e->msg) - 2] = '*';
	}

	if (e->sp == XLOG_ERRNO && e->code != 0) {
		strerror_r(e->code, errmsg, sizeof(errmsg));
		if (fmt) {
			syslog(priority, "[sp=%d, code=%lld]: %s: %s: %s",
			    e->sp, e->code, msg, e->msg, errmsg);
			xlog_fprintf("[sp=%d, code=%lld]: %s: %s: %s",
			    e->sp, e->code, msg, e->msg, errmsg);
		} else {
			syslog(priority, "[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, e->msg, errmsg);
			xlog_fprintf("[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, e->msg, errmsg);
		}
	} else if (e->sp == XLOG_EAI && e->code != 0) {
		if (fmt) {
			syslog(priority, "[sp=%d, code=%lld]: %s: %s: %s",
			    e->sp, e->code, msg, e->msg, gai_strerror(e->code));
			xlog_fprintf("[sp=%d, code=%lld]: %s: %s: %s",
			    e->sp, e->code, msg, e->msg, gai_strerror(e->code));
		} else {
			syslog(priority, "[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, e->msg, gai_strerror(e->code));
			xlog_fprintf("[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, e->msg, gai_strerror(e->code));
		}
	} else if (e->sp == XLOG_SSL && e->code != 0) {
		ERR_error_string_n(e->code, errmsg, sizeof(errmsg));
		if (fmt) {
			syslog(priority, "[sp=%d, code=%lld]: %s: %s: %s",
			    e->sp, e->code, msg, e->msg, errmsg);
			xlog_fprintf("[sp=%d, code=%lld]: %s: %s: %s",
			    e->sp, e->code, msg, e->msg, errmsg);
		} else {
			syslog(priority, "[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, e->msg, errmsg);
			xlog_fprintf("[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, e->msg, errmsg);
		}
	} else {
		if (fmt) {
			syslog(priority, "[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, msg, e->msg);
			xlog_fprintf("[sp=%d, code=%lld]: %s: %s",
			    e->sp, e->code, msg, e->msg);
		} else {
			syslog(priority, "[sp=%d, code=%lld]: %s",
			    e->sp, e->code, e->msg);
			xlog_fprintf("[sp=%d, code=%lld]: %s",
			    e->sp, e->code, e->msg);
		}
	}
}

void
xlog_strerror(int priority, int err, const char *fmt, ...)
{
	va_list ap;
	char    msg[LINE_MAX];
	char    errmsg[256] = "";

	if (priority > log_level)
		return;
	if (fmt == NULL)
		return;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	strerror_r(err, errmsg, sizeof(errmsg));
	syslog(priority, "%s: %s", msg, errmsg);
	xlog_fprintf("%s: %s", msg, errmsg);
}

void
xerr_print(const struct xerr *e)
{
	char errmsg[256] = "";

	if (e == NULL)
		return;

	if (e->sp == XLOG_ERRNO && e->code != 0) {
		strerror_r(e->code, errmsg, sizeof(errmsg));
		warnx("[sp=%d, code=%lld]: %s: %s",
		    e->sp, e->code, e->msg, errmsg);
	} else if (e->sp == XLOG_EAI && e->code != 0) {
		warnx("[sp=%d, code=%lld]: %s: %s",
		    e->sp, e->code, e->msg, gai_strerror(e->code));
	} else if (e->sp == XLOG_SSL && e->code != 0) {
		ERR_error_string_n(e->code, errmsg, sizeof(errmsg));
		warnx("[sp=%d, code=%lld]: %s: %s",
		    e->sp, e->code, e->msg, errmsg);
	} else
		warnx("[sp=%d, code=%lld]: %s", e->sp, e->code, e->msg);
}

int
xerr_prepend(struct xerr *e, const char *prefix)
{
	char msg[LINE_MAX];

	if (e == NULL)
		return 0;

	strlcpy(msg, e->msg, sizeof(msg));
	if (snprintf(e->msg, sizeof(e->msg), "%s: %s", prefix, msg) >=
	    sizeof(e->msg))
		e->msg[sizeof(e->msg) - 2] = '*';
	return xerr_fail(e);
}
