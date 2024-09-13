%{
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "flatconf.h"

static int yyparse();

static long      pwnam_sz;
static int       lineno = 1;
static FILE     *cfg;
static char      buf[PATH_MAX + 1];
static char     *bufp = buf;

static enum {
	ST_NONE,
	ST_WORD,
	ST_NUMBER,
	ST_STRING,
	ST_COMMENT
} state = ST_NONE;

static struct flatconf *cfg_vars;

static struct flatconf_value {
	int                    type;
	void                  *value;
	struct flatconf_value *next;
} *flatconf_values;

static void
flatconf_error_default(const char *msg) {
	fprintf(stderr, "%s\n", msg);
}

static void (*flatconf_error)(const char *) = flatconf_error_default;
%}

%union {
	char     word[PATH_MAX + 1];
	char     string[PATH_MAX + 1];
	uint64_t positive_int;
	int64_t  negative_int;
}

%token ERROR ';' '=' STRING WORD NUMBER NL
%token <word>         WORD
%token <string>       STRING
%token <positive_int> POSITIVE_INT
%token <negative_int> NEGATIVE_INT
%start flatconf
%%

flatconf :
	statements
	;
statements :
	stmt statements
	|
	;
stmt :
	WORD '=' value { if (!flatconf_set_var($1)) YYERROR; } NL
	| WORD '=' '[' values ']' { if (!flatconf_set_var($1)) YYERROR; } NL
	| NL
	| ERROR
	{ YYABORT; }
	;
value :
	WORD
	{ if (!flatconf_append_value(WORD)) YYERROR; }
	| POSITIVE_INT
	{ if(!flatconf_append_value(POSITIVE_INT)) YYERROR; }
	| NEGATIVE_INT
	{ if (!flatconf_append_value(NEGATIVE_INT)) YYERROR; }
	| STRING
	{ if (!flatconf_append_value(STRING)) YYERROR; }
	;
values :
	value values
	| NL values
	|
	;
%%

static int
yyerror(const char *fmt, ...)
{
	char    linefmt[LINE_MAX];
	char    msg[LINE_MAX];
	va_list ap;

	snprintf(linefmt, sizeof(linefmt), "flatconf: %s at line %d",
	    fmt, lineno);
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), linefmt, ap);
	va_end(ap);
	flatconf_error(msg);
	return 0;
}

int
yylex()
{
	int   c;
	char *endptr;
read:
	if ((c = getc(cfg)) == EOF)
		return (ferror(cfg)) ? ERROR : 0;

	switch (state) {
	case ST_COMMENT:
		if (c == '\n') {
			if (ungetc(c, cfg) == EOF)
				return (ferror(cfg)) ? ERROR : 0;
			state = ST_NONE;
		}
		goto read;
	case ST_WORD:
		if (isspace(c)) {
			*bufp = '\0';
			if (strlcpy(yylval.word, buf, sizeof(yylval.word)) >=
			    sizeof(yylval.word)) {
				yyerror("word exceeds %lu characters",
				    sizeof(yylval.word) - 1);
				return ERROR;
			}
			bufp = buf;
			state = ST_NONE;
			if (ungetc(c, cfg) == EOF)
				return (ferror(cfg)) ? ERROR : 0;
			return WORD;
		}

		if (!isalnum(c) && c != '_') {
			yyerror("invalid character in word");
			return ERROR;
		}

		*bufp++ = c;
		goto read;
	case ST_STRING:
		if (c != '"') {
			*bufp++ = c;
			goto read;
		}
		*bufp = '\0';
		if (strlcpy(yylval.string, buf, sizeof(yylval.string)) >=
		    sizeof(yylval.string)) {
			yyerror("string exceeds %lu characters",
			    sizeof(yylval.string) - 1);
			return ERROR;
		}
		bufp = buf;
		state = ST_NONE;
		return STRING;
	case ST_NUMBER:
		if (isspace(c)) {
			state = ST_NONE;
			if (ungetc(c, cfg) == EOF)
				return (ferror(cfg)) ? ERROR : 0;
			*bufp = '\0';
			if (*buf == '-') {
				errno = 0;
				yylval.negative_int = strtol(buf, &endptr, 10);
				if (errno || *endptr != '\0') {
					yyerror("invalid int64");
					return ERROR;
				}
				bufp = buf;
				return NEGATIVE_INT;
			} else {
				errno = 0;
				yylval.positive_int = strtoul(buf, &endptr, 10);
				if (errno || *endptr != '\0') {
					yyerror("invalid uint64");
					return ERROR;
				}
				bufp = buf;
				return POSITIVE_INT;
			}
		}

		if (!isdigit(c)) {
			if (c == '-' && bufp == buf) {
				/*
				 * A '-' in at the start of buf is acceptable
				 * for negative numbers.
				 */
				*bufp++ = c;
				goto read;
			}
			yyerror("invalid character in number");
			return ERROR;
		}

		*bufp++ = c;
		goto read;
	case ST_NONE:
	default:
		if (c == '\n') {
			lineno++;
			return NL;
		}

		if (isspace(c))
			goto read;

		if (c == '=' || c == '[' || c == ']')
			return c;

		if (c == '#') {
			state = ST_COMMENT;
			goto read;
		}

		if (c == '"') {
			state = ST_STRING;
			goto read;
		}

		if (isalpha(c)) {
			state = ST_WORD;
			if (ungetc(c, cfg) == EOF)
				return (ferror(cfg)) ? ERROR : 0;
			goto read;
		}

		if (c == '-' || isdigit(c)) {
			state = ST_NUMBER;
			if (ungetc(c, cfg) == EOF)
				return (ferror(cfg)) ? ERROR : 0;
			goto read;
		}

		return ERROR;
		yyerror("unknown parser state");
	}
	return 0;
}

static int
flatconf_append_value(int type)
{
	struct flatconf_value *v = malloc(sizeof(struct flatconf_value));

	if (v == NULL) {
		yyerror("malloc failed");
		return 0;
	}
	bzero(v, sizeof(struct flatconf_value));

	v->type = type;
	switch (type) {
	case STRING:
		if ((v->value = strdup(yylval.string)) == NULL) {
			yyerror("strdup failed");
			return 0;
		}
		break;
	case WORD:
		if ((v->value = strdup(yylval.word)) == NULL) {
			yyerror("strdup failed");
			return 0;
		}
		break;
	case NEGATIVE_INT:
		if ((v->value = malloc(sizeof(int64_t))) == NULL) {
			yyerror("malloc failed");
			return 0;
		}
		*(int64_t *)v->value = yylval.negative_int;
		break;
	case POSITIVE_INT:
		if ((v->value = malloc(sizeof(uint64_t))) == NULL) {
			yyerror("malloc failed");
			return 0;
		}
		*(uint64_t *)v->value = yylval.positive_int;
		break;
	default:
		yyerror("unknown value type: %d", type);
		return 0;
	}
	v->next = flatconf_values;
	flatconf_values = v;
	return 1;
}

static void
flatconf_free_values()
{
	struct flatconf_value *v, *next;

	for (v = flatconf_values; v != NULL; v = next) {
		next = v->next;
		free(v->value);
		free(v);
	}
	flatconf_values = NULL;
}

static int
flatconf_get_ulong(void *dst, size_t sz)
{
	if (sz < sizeof(uint64_t)) {
		yyerror("no enough storage space in destination variable");
		return 0;
	}

	if (flatconf_values->type != POSITIVE_INT) {
		yyerror("expected unsigned integer value");
		return 0;
	}
	*((uint64_t *)dst) = *((uint64_t *)flatconf_values->value);
	return 1;
}

static int
flatconf_get_long(void *dst, size_t sz)
{
	if (sz < sizeof(int64_t)) {
		yyerror("no enough storage space in destination variable");
		return 0;
	}

	switch (flatconf_values->type) {
	case POSITIVE_INT:
		if (*((uint64_t *)flatconf_values->value) > INT64_MAX) {
			yyerror("integer value too large for int64");
			return 0;
		}
	case NEGATIVE_INT:
		*((int64_t *)dst) = *((int64_t *)flatconf_values->value);
		break;
	default:
		yyerror("expected integer value");
		return 0;
	}
	return 1;
}

static int
flatconf_get_allocstring(void *dst, size_t *sz)
{
	char       **pdst = (char **)dst;
	const char  *v = (const char *)flatconf_values->value;

	if (flatconf_values->type != STRING &&
	    flatconf_values->type != WORD) {
		yyerror("expected string value");
		return 0;
	}

	if ((*pdst = strdup(v)) == NULL) {
		yyerror("strdup failed");
		return 0;
	}
	*sz = strlen(*pdst);

	return 1;
}

static int
flatconf_get_allocstringlist(void *dst, size_t *sz)
{
	char                  ***pdst = (char ***)dst;
	char                    *p;
	struct flatconf_value   *v;
	int                      i, n, len;
	size_t                   sum = 0;

	for (n = 0, v = flatconf_values; v != NULL; v = v->next, n++) {
		if (v->type != STRING && v->type != WORD) {
			yyerror("expected string value in list");
			return 0;
		}
		sum += strlen(v->value) + 1;
	}

	if (n == 0)
		return 1;

	sum += (n + 1) * sizeof(char *);

	*pdst = malloc(sum);
	if (*pdst == NULL) {
		yyerror("malloc failed");
		return 0;
	}
	*sz = sum;

	(*pdst)[n] = NULL;
	p = (char *)(*pdst) + (sizeof(char *) * (n + 1));

	for (i = n - 1, v = flatconf_values; v != NULL; v = v->next, i--) {
		(*pdst)[i] = p;
		len = strlen((char *)v->value);
		memcpy(p, v->value, len);
		p += len;
		*p++ = '\0';
	}

	return 1;
}

static int
flatconf_get_alloculonglist(void *dst, size_t *sz)
{
	uint64_t              ***pdst = (uint64_t ***)dst;
	uint64_t                *p;
	struct flatconf_value   *v;
	int                      i, n;
	size_t                   sum = 0;

	for (n = 0, v = flatconf_values; v != NULL; v = v->next, n++) {
		if (v->type != POSITIVE_INT) {
			yyerror("expected positive integer value in list");
			return 0;
		}
		sum += sizeof(uint64_t);
	}

	if (n == 0)
		return 1;

	sum += (n + 1) * sizeof(uint64_t *);

	*pdst = malloc(sum);
	if (*pdst == NULL) {
		yyerror("malloc failed");
		return 0;
	}
	*sz = sum;

	(*pdst)[n] = NULL;
	p = (uint64_t *)((char *)(*pdst) + (sizeof(uint64_t *) * (n + 1)));

	for (i = n - 1, v = flatconf_values; v != NULL; v = v->next, i--) {
		(*pdst)[i] = p;
		*p++ = *(uint64_t *)v->value;
	}

	return 1;
}

static int
flatconf_get_string(void *dst, size_t sz)
{
	if (flatconf_values->type != STRING &&
	    flatconf_values->type != WORD) {
		yyerror("expected string value");
		return 0;
	}

	if (strlcpy((char *)dst, (const char *)flatconf_values->value,
	    sz) >= sz) {
		yyerror("no enough storage space in destination variable");
		return 0;
	}
	return 1;
}

static int
flatconf_get_boolint(void *dst, size_t sz)
{
	const char *v;

	if (sz < sizeof(int)) {
		yyerror("no enough storage space in destination variable");
		return 0;
	}

	if (flatconf_values->type != WORD) {
		yyerror("expected WORD value");
		return 0;
	}

	v = (const char *)flatconf_values->value;

	if (strcmp(v, "yes") == 0 || strcmp(v, "true") == 0) {
		*((int *)dst) = 1;
	} else if (strcmp(v, "no") == 0 || strcmp(v, "false") == 0) {
		*((int *)dst) = 0;
	} else {
		yyerror("value is not a valid boolean");
		return 0;
	}
	return 1;
}

static int
flatconf_set_var(const char *var) {
	struct flatconf *cv;
	int              r;

	for (cv = cfg_vars; cv->t != FLATCONF_NONE; cv++) {
		if (strcmp(cv->name, var) != 0)
			continue;

		switch (cv->t) {
		case FLATCONF_STRING:
			r = flatconf_get_string(cv->dst, cv->dst_sz);
			break;
		case FLATCONF_LONG:
			r = flatconf_get_long(cv->dst, cv->dst_sz);
			break;
		case FLATCONF_ULONG:
			r = flatconf_get_ulong(cv->dst, cv->dst_sz);
			break;
		case FLATCONF_BOOLINT:
			r = flatconf_get_boolint(cv->dst, cv->dst_sz);
			break;
		case FLATCONF_ALLOCSTRING:
			r = flatconf_get_allocstring(cv->dst, &cv->dst_sz);
			break;
		case FLATCONF_ALLOCSTRINGLIST:
			r = flatconf_get_allocstringlist(cv->dst, &cv->dst_sz);
			break;
		case FLATCONF_ALLOCULONGLIST:
			r = flatconf_get_alloculonglist(cv->dst, &cv->dst_sz);
			break;
		default:
			yyerror("failed to parse value for %s"
			    "; undefined type", var);
			return 0;
		}
		flatconf_free_values();
		return r;
	}
	return 1;
}

int
flatconf_read(const char *cfg_path, struct flatconf *vars,
    void(*errfn)(const char *))
{
	int r;

	if ((pwnam_sz = sysconf(_SC_LOGIN_NAME_MAX)) == -1)
		pwnam_sz = 256;

	if (errfn != NULL)
		flatconf_error = errfn;

	if ((cfg = fopen(cfg_path, "r")) == NULL) {
		flatconf_free_values();
		return -1;
	}
	cfg_vars = vars;
	r = yyparse();
	flatconf_free_values();
	fclose(cfg);
	return r;
}

void
flatconf_free(struct flatconf *vars)
{
	struct flatconf *cv;

	for (cv = vars; cv->t != FLATCONF_NONE; cv++) {
		switch (cv->t) {
		case FLATCONF_ALLOCSTRING:
			/* Only free if we actually allocated this variable */
			if (cv->dst_sz > 0) {
				free(*(char **)cv->dst);
				cv->dst = NULL;
				cv->dst_sz = 0;
			}
			break;
		case FLATCONF_ALLOCSTRINGLIST:
			/* Only free if we actually allocated this variable */
			if (cv->dst_sz > 0) {
				free(*(char ***)cv->dst);
				cv->dst = NULL;
				cv->dst_sz = 0;
			}
			break;
		default:
			/* Nothing allocated */
			break;
		}
	}
}
