#include <errno.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include "certdb.h"
#include "util.h"

static sqlite3 *db;

const int qry_busy_timeout = 1000;

/*
 * The bootstrap table allows a client with a one-time key to request their
 * first certificate. The entry is created by an administrator who decides
 * the certificate's:
 *   - subject
 *   - subject alternate names
 *   - validity period
 *   - roles
 * The bootstrap entry is valid only for a short duration, also chosen by the
 * administrator. Once the entry is used, it should be deleted.
 *
 * During the bootstrap process, we will send the subject, SANs, roles and
 * validity to the client, which they will include in their CSR.
 */
const char *qry_create_bootstrap_table = "create table if not exists bootstrap("
                "bootstrap_key blob not null, "
		"valid_until_sec int not null, "
		"subject text not null, "
		"sans blob, "
		"roles blob, "
		"flags int not null, "
		"not_before_sec int not null, "
		"not_after_sec int not null, "
                "primary key(bootstrap_key))";

const char *qry_create_certs_table = "create table if not exists certs("
                "serial blob not null, "
		"subject text not null, "
		"sans blob, "
		"roles blob, "
		"not_before_sec int not null, "
		"not_after_sec int not null, "
		"flags int not null, "
                "primary key(serial))";

const char *qry_create_certs_index = "create index if not exists "
                "by_serial_flags on certs (flags, serial desc)";

struct {
        sqlite3_stmt *stmt;
        char         *sql;
        int           i_bootstrap_key;
        int           i_valid_until_sec;
        int           i_subject;
        int           i_sans;
        int           i_roles;
        int           i_flags;
        int           i_not_before_sec;
        int           i_not_after_sec;
} qry_bootstrap_put = {
        NULL,
        "insert or replace into bootstrap(bootstrap_key, valid_until_sec, "
	    "subject, sans, roles, flags, not_before_sec, not_after_sec) "
            "values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        1, 2, 3, 4, 5, 6, 7, 8
};

struct {
        sqlite3_stmt *stmt;
        char         *sql;
        int           i_bootstrap_key;
        int           o_valid_until_sec;
        int           o_subject;
        int           o_sans;
        int           o_roles;
        int           o_flags;
        int           o_not_before_sec;
        int           o_not_after_sec;
} qry_bootstrap_get = {
        NULL,
        "select valid_until_sec, subject, sans, roles, flags, not_before_sec, "
	    "not_after_sec from bootstrap where bootstrap_key = ?1",
        1, 0, 1, 2, 3, 4, 5, 6
};

struct {
        sqlite3_stmt *stmt;
        char         *sql;
        int           i_serial;
        int           i_subject;
        int           i_sans;
        int           i_roles;
        int           i_not_before_sec;
        int           i_not_after_sec;
        int           i_flags;
} qry_cert_put = {
        NULL,
        "insert or replace into certs(serial, subject, "
	    "sans, roles, not_before_sec, not_after_sec, flags) "
            "values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        1, 2, 3, 4, 5, 6, 7
};

struct {
        sqlite3_stmt *stmt;
        char         *sql;
        int           i_serial;
        int           o_subject;
        int           o_sans;
        int           o_roles;
        int           o_not_before_sec;
        int           o_not_after_sec;
        int           o_flags;
} qry_cert_get = {
        NULL,
        "select subject, sans, roles, not_before_sec, not_after_sec, flags "
            "from certs where serial = ?1",
        1, 0, 1, 2, 3, 4, 5
};

static int
certdb_qry_cleanup(sqlite3_stmt *stmt, struct xerr *e)
{
	int r;
	if ((r = sqlite3_reset(stmt)))
		return XERRF(e, XLOG_DB, r,
		    "sqlite3_reset: %s", sqlite3_errmsg(db));
	if ((r = sqlite3_clear_bindings(stmt)))
		return XERRF(e, XLOG_DB, r,
		    "sqlite3_clear_bindings: %s (%d)", sqlite3_errmsg(db), r);
	return 0;
}

int
certdb_get_bootstrap(struct bootstrap_entry *dst, const char *bootstrap_key,
    struct xerr *e)
{
	int          r;
	struct xerr  e2;
	char        *sans = NULL;
	int          sans_len;
	char        *roles = NULL;
	int          roles_len;
	int          subject_len;

	if ((r = sqlite3_bind_blob(qry_bootstrap_get.stmt,
	    qry_bootstrap_put.i_bootstrap_key, bootstrap_key,
	    strlen(bootstrap_key), SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	bzero(dst, sizeof(struct bootstrap_entry));
	switch ((r = sqlite3_step(qry_bootstrap_get.stmt))) {
	case SQLITE_ROW:
                break;
        case SQLITE_DONE:
                XERRF(e, XLOG_APP, XLOG_NOENT,
                    "sqlite3_step: entry not found, bootstrap_key=%s",
		    bootstrap_key);
                goto fail;
        case SQLITE_BUSY:
                XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
                goto fail;
        case SQLITE_MISUSE:
        case SQLITE_ERROR:
        default:
                XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
                    sqlite3_errmsg(db), r);
                goto fail;
        }

	dst->flags = (uint32_t)sqlite3_column_int(
	    qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_flags);

	dst->valid_until_sec = (uint64_t)sqlite3_column_int64(
	    qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_valid_until_sec);

	subject_len = sqlite3_column_bytes(
	    qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_subject) + 1;
	if ((dst->subject = malloc(subject_len)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	strlcpy(dst->subject,
	    sqlite3_column_blob(qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_subject), subject_len);

	sans_len = sqlite3_column_bytes(
	    qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_sans);
	if (sans_len > 0) {
		if ((sans = malloc(sans_len)) == NULL) {
			free(dst->subject);
			XERRF(e, XLOG_ERRNO, errno, "malloc");
			goto fail;
		}
		memcpy(sans,
		    sqlite3_column_blob(qry_bootstrap_get.stmt,
		    qry_bootstrap_get.o_sans), sans_len);
		if ((dst->sans_sz = strlist_split(&dst->sans,
		    sans, sans_len)) == -1) {
			free(dst->subject);
			free(sans);
			free(roles);
			XERRF(e, XLOG_ERRNO, errno, "malloc");
			goto fail;
		}
	}

	roles_len = sqlite3_column_bytes(
	    qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_roles);
	if (roles_len > 0) {
		if ((roles = malloc(roles_len)) == NULL) {
			free(dst->subject);
			free(sans);
			XERRF(e, XLOG_ERRNO, errno, "malloc");
			goto fail;
		}
		memcpy(roles,
		    sqlite3_column_blob(qry_bootstrap_get.stmt,
		    qry_bootstrap_get.o_roles), roles_len);
		if ((dst->roles_sz = strlist_split(&dst->roles,
		    roles, roles_len)) == -1) {
			free(dst->sans);
			free(dst->subject);
			free(sans);
			free(roles);
			XERRF(e, XLOG_ERRNO, errno, "malloc");
			goto fail;
		}
	}

	dst->not_before_sec = (uint64_t)sqlite3_column_int64(
	    qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_not_before_sec);
	dst->not_after_sec = (uint64_t)sqlite3_column_int64(
	    qry_bootstrap_get.stmt,
	    qry_bootstrap_get.o_not_after_sec);

	free(sans);
	free(roles);

	return certdb_qry_cleanup(qry_bootstrap_get.stmt, e);
fail:
	free(sans);
	free(roles);
	if (certdb_qry_cleanup(qry_bootstrap_get.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
certdb_get_cert(struct cert_entry *dst, const char *serial, struct xerr *e)
{
	int          r;
	struct xerr  e2;
	char        *sans = NULL;
	int          sans_len;
	char        *roles = NULL;
	int          roles_len;
	int          subject_len;

	if ((r = sqlite3_bind_blob(qry_cert_get.stmt,
	    qry_cert_put.i_serial, serial, strlen(serial), SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	bzero(dst, sizeof(struct cert_entry));
	switch ((r = sqlite3_step(qry_cert_get.stmt))) {
	case SQLITE_ROW:
		break;
        case SQLITE_DONE:
                XERRF(e, XLOG_APP, XLOG_NOENT,
                    "sqlite3_step: entry not found, serial=%s", serial);
                goto fail;
        case SQLITE_BUSY:
                XERRF(e, XLOG_APP, XLOG_BUSY, "sqlite3_step");
                goto fail;
        case SQLITE_MISUSE:
        case SQLITE_ERROR:
        default:
                XERRF(e, XLOG_DB, r, "sqlite3_step: %s (%d)",
                    sqlite3_errmsg(db), r);
                goto fail;
        }

	subject_len = sqlite3_column_bytes(
	    qry_cert_get.stmt,
	    qry_cert_get.o_subject);
	if ((dst->subject = malloc(subject_len)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	strlcpy(dst->subject,
	    sqlite3_column_blob(qry_cert_get.stmt,
	    qry_cert_get.o_subject), subject_len);

	sans_len = sqlite3_column_bytes(
	    qry_cert_get.stmt,
	    qry_cert_get.o_sans);
	if ((sans = malloc(sans_len)) == NULL) {
		free(dst->subject);
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	memcpy(sans,
	    sqlite3_column_blob(qry_cert_get.stmt,
	    qry_cert_get.o_subject), sans_len);

	roles_len = sqlite3_column_bytes(
	    qry_cert_get.stmt,
	    qry_cert_get.o_roles);
	if ((roles = malloc(roles_len)) == NULL) {
		free(dst->subject);
		free(sans);
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	memcpy(roles,
	    sqlite3_column_blob(qry_cert_get.stmt,
	    qry_cert_get.o_subject), roles_len);


	dst->not_before_sec = (uint64_t)sqlite3_column_int64(
	    qry_cert_get.stmt,
	    qry_cert_get.o_not_before_sec);
	dst->not_after_sec = (uint64_t)sqlite3_column_int64(
	    qry_cert_get.stmt,
	    qry_cert_get.o_not_after_sec);
	dst->flags = (uint32_t)sqlite3_column_int(
	    qry_cert_get.stmt,
	    qry_cert_get.o_flags);

	if ((dst->sans_sz = strlist_split(&dst->sans,
	    sans, sans_len)) == -1) {
		free(dst->subject);
		free(sans);
		free(roles);
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	if ((dst->roles_sz = strlist_split(&dst->roles,
	    roles, roles_len)) == -1) {
		free(dst->sans);
		free(dst->subject);
		free(sans);
		free(roles);
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	free(sans);
	free(roles);
	return certdb_qry_cleanup(qry_cert_get.stmt, e);
fail:
	free(sans);
	free(roles);
	if (certdb_qry_cleanup(qry_cert_get.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
certdb_put_bootstrap(const struct bootstrap_entry *entry, struct xerr *e)
{
	int          r;
	struct xerr  e2;
	char        *sans = NULL;
	int          sans_sz;
	char        *roles = NULL;
	int          roles_sz;

	if ((r = sqlite3_bind_blob(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_bootstrap_key, entry->bootstrap_key,
	    sizeof(entry->bootstrap_key), SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_bind_text(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_subject, entry->subject,
	    strlen(entry->subject), SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_text: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((sans_sz = strlist_join(entry->sans, entry->sans_sz,
	    &sans)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "strlist_join");
		goto fail;
	}
	if ((r = sqlite3_bind_blob(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_sans, sans, sans_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((roles_sz = strlist_join(entry->roles, entry->roles_sz,
	    &roles)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "strlist_join");
		goto fail;
	}
	if ((r = sqlite3_bind_blob(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_roles, roles, roles_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_bind_int64(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_valid_until_sec, entry->valid_until_sec)) ||
	    (r = sqlite3_bind_int(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_flags, entry->flags)) ||
	    (r = sqlite3_bind_int64(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_not_before_sec, entry->not_before_sec)) ||
	    (r = sqlite3_bind_int64(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_not_after_sec, entry->not_after_sec))) {
		XERRF(e, XLOG_DB, r,
		    "sqlite3_bind_int/int64: %s", sqlite3_errmsg(db));
		goto fail;
	}

	switch (sqlite3_step(qry_bootstrap_put.stmt)) {
	case SQLITE_DONE:
		/* Nothing */
		break;
	case SQLITE_BUSY:
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	free(sans);
	free(roles);

	return certdb_qry_cleanup(qry_bootstrap_put.stmt, e);
fail:
	free(sans);
	free(roles);
	if (certdb_qry_cleanup(qry_bootstrap_put.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
certdb_put_cert(const struct cert_entry *entry, struct xerr *e)
{
	int          r;
	struct xerr  e2;
	char        *sans = NULL;
	int          sans_sz;
	char        *roles = NULL;
	int          roles_sz;

	if ((r = sqlite3_bind_blob(qry_cert_put.stmt,
	    qry_cert_put.i_serial, entry->serial,
	    sizeof(entry->serial), SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_bind_text(qry_cert_put.stmt,
	    qry_cert_put.i_subject, entry->subject,
	    strlen(entry->subject), SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_text: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((sans_sz = strlist_join(entry->sans, entry->sans_sz,
	    &sans)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "strlist_join");
		goto fail;
	}
	if ((r = sqlite3_bind_text(qry_cert_put.stmt,
	    qry_cert_put.i_sans, sans, sans_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_text: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((roles_sz = strlist_join(entry->roles, entry->roles_sz,
	    &roles)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "strlist_join");
		goto fail;
	}
	if ((r = sqlite3_bind_blob(qry_cert_put.stmt,
	    qry_cert_put.i_roles, roles, roles_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_bind_int64(qry_cert_put.stmt,
	    qry_cert_put.i_not_before_sec, entry->not_before_sec)) ||
	    (r = sqlite3_bind_int64(qry_cert_put.stmt,
	    qry_cert_put.i_not_after_sec, entry->not_after_sec))) {
		XERRF(e, XLOG_DB, r,
		    "sqlite3_bind_int/int64: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_bind_int(qry_cert_put.stmt,
	    qry_cert_put.i_flags, entry->flags))) {
		XERRF(e, XLOG_DB, r,
		    "sqlite3_bind_int: %s", sqlite3_errmsg(db));
		goto fail;
	}

	switch ((r = sqlite3_step(qry_cert_put.stmt))) {
	case SQLITE_DONE:
		/* Nothing */
		break;
	case SQLITE_BUSY:
	case SQLITE_MISUSE:
	case SQLITE_ERROR:
	default:
		XERRF(e, XLOG_DB, r, "sqlite3_step: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	free(sans);
	free(roles);

	return certdb_qry_cleanup(qry_cert_put.stmt, e);
fail:
	free(sans);
	free(roles);
	if (certdb_qry_cleanup(qry_cert_put.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
certdb_init(const char *path, struct xerr *e)
{
	int r;

	if ((r = sqlite3_open(path, &db)))
		return XERRF(e, XLOG_DB, r, "sqlite3_open: %s",
		    sqlite3_errmsg(db));

	if ((r = sqlite3_busy_timeout(db, qry_busy_timeout))) {
		XERRF(e, XLOG_DB, r, "sqlite3_busy_timeout: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_exec(db, qry_create_bootstrap_table,
	    NULL, NULL, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_exec: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_exec(db, qry_create_certs_table, NULL, NULL, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_exec: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_exec(db, qry_create_certs_index, NULL, NULL, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_exec: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_bootstrap_put.sql, -1,
	    &qry_bootstrap_put.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: "
		    "qry_bootstrap_put: %s", sqlite3_errmsg(db));
		goto fail;
	}
	if ((r = sqlite3_prepare_v2(db, qry_bootstrap_get.sql, -1,
	    &qry_bootstrap_get.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: "
		    "qry_bootstrap_get: %s", sqlite3_errmsg(db));
		goto fail;
	}

	if ((r = sqlite3_prepare_v2(db, qry_cert_put.sql, -1,
	    &qry_cert_put.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: "
		    "qry_cert_put: %s", sqlite3_errmsg(db));
		goto fail;
	}
	if ((r = sqlite3_prepare_v2(db, qry_cert_get.sql, -1,
	    &qry_cert_get.stmt, NULL))) {
		XERRF(e, XLOG_DB, r, "sqlite3_prepare_v2: "
		    "qry_cert_get: %s", sqlite3_errmsg(db));
		goto fail;
	}

	return 0;
fail:
	sqlite3_close(db);
	return -1;
}

void
certdb_shutdown()
{
	if (sqlite3_finalize(qry_bootstrap_put.stmt))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_bootstrap_put: %s",
		    __func__, sqlite3_errmsg(db));
	if (sqlite3_finalize(qry_bootstrap_get.stmt))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_bootstrap_get: %s",
		    __func__, sqlite3_errmsg(db));

	if (sqlite3_finalize(qry_cert_put.stmt))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_cert_put: %s",
		    __func__, sqlite3_errmsg(db));
	if (sqlite3_finalize(qry_cert_get.stmt))
		xlog(LOG_WARNING, NULL,
		    "%s: sqlite3_finalize: qry_cert_get: %s",
		    __func__, sqlite3_errmsg(db));

	if (sqlite3_close(db) != SQLITE_OK)
		xlog(LOG_ERR, NULL,
		    "%s: sqlite3_close: %s", __func__, sqlite3_errmsg(db));
}
