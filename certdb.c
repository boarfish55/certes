#include <errno.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include "certdb.h"

static sqlite3 *db;

const int   qry_busy_timeout = 1000;

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
                "one_time_key blob not null, "
		"valid_until_sec int not null, "
		"subject text not null, "
		"sans blob not null, "
		"roles blob not null, "
		"not_before_sec int not null, "
		"not_after_sec int not null, "
                "primary key(one_time_key))";

const char *qry_create_certs_table = "create table if not exists certs("
                "serial blob not null, "
		"subject text not null, "
		"sans blob not null, "
		"roles blob not null, "
		"not_before_sec int not null, "
		"not_after_sec int not null, "
		"flags int not null, "
                "primary key(serial))";

const char *qry_create_certs_index = "create index if not exists "
                "by_serial_flags on certs (flags, serial desc)";

struct {
        sqlite3_stmt *stmt;
        char         *sql;
        int           i_one_time_key;
        int           i_valid_until_sec;
        int           i_subject;
        int           i_sans;
        int           i_roles;
        int           i_not_before_sec;
        int           i_not_after_sec;
} qry_bootstrap_put = {
        NULL,
        "insert or replace into bootstrap(one_time_key, valid_until_sec, "
	    "subject, sans, roles, not_before_sec, not_after_sec) "
            "values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        1, 2, 3, 4, 5, 6, 7
};

struct {
        sqlite3_stmt *stmt;
        char         *sql;
        int           i_one_time_key;
        int           o_valid_ntil_sec;
        int           o_subject;
        int           o_sans;
        int           o_roles;
        int           o_not_before_sec;
        int           o_not_after_sec;
} qry_bootstrap_get = {
        NULL,
        "select subject, sans, roles, not_before_sec, not_after_sec "
            "from bootstrap where one_time_key = ?1",
        1, 0, 1, 2, 3, 4, 5
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

static int
certdb_join_strlist(char **strlist, size_t strlist_sz, char **dst)
{
	int   i;
	int   sz = 0;
	char *sans_p;

	for (i = 0; i < strlist_sz; i++)
		// TODO: check int boundary
		sz += strlen(strlist[i]) + 1;

	if ((*dst = malloc(sz)) == NULL)
		return -1;

	for (i = 0, sans_p = *dst; i < strlist_sz; i++)
		sans_p += strlcpy(sans_p, strlist[i], strlen(strlist[i]) + 1);

	return sz;
}

int
certdb_put_bootstrap(const struct bootstrap_entry *entry, struct xerr *e)
{
	int          r;
	struct xerr  e2;
	char        *sans;
	int          sans_sz;
	char        *roles;
	int          roles_sz;

	if ((r = sqlite3_bind_blob(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_one_time_key, entry->one_time_key,
	    sizeof(entry->one_time_key), SQLITE_STATIC))) {
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

	if ((sans_sz = certdb_join_strlist(entry->sans, entry->sans_sz,
	    &sans)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "certdb_join_strlist");
		goto fail;
	}
	if ((r = sqlite3_bind_blob(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_sans, sans, sans_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}
	free(sans);

	if ((roles_sz = certdb_join_strlist(entry->roles, entry->roles_sz,
	    &roles)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "certdb_join_strlist");
		goto fail;
	}
	if ((r = sqlite3_bind_blob(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_roles, roles, roles_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}
	free(roles);

	if ((r = sqlite3_bind_int64(qry_bootstrap_put.stmt,
	    qry_bootstrap_put.i_valid_until_sec, entry->valid_until_sec)) ||
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

	return certdb_qry_cleanup(qry_bootstrap_put.stmt, e);
fail:
	if (certdb_qry_cleanup(qry_bootstrap_put.stmt, xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, "%s", __func__);
	return -1;
}

int
certdb_put_cert(const struct cert_entry *entry, struct xerr *e)
{
	int          r;
	struct xerr  e2;
	char        *sans;
	int          sans_sz;
	char        *roles;
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

	if ((sans_sz = certdb_join_strlist(entry->sans, entry->sans_sz,
	    &sans)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "certdb_join_strlist");
		goto fail;
	}
	if ((r = sqlite3_bind_text(qry_cert_put.stmt,
	    qry_cert_put.i_sans, sans, sans_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_text: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}
	free(sans);

	if ((roles_sz = certdb_join_strlist(entry->roles, entry->roles_sz,
	    &roles)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "certdb_join_strlist");
		goto fail;
	}
	if ((r = sqlite3_bind_blob(qry_cert_put.stmt,
	    qry_cert_put.i_roles, roles, roles_sz, SQLITE_STATIC))) {
		XERRF(e, XLOG_DB, r, "sqlite3_bind_blob: %s",
		    sqlite3_errmsg(db));
		goto fail;
	}
	free(roles);

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

	switch (sqlite3_step(qry_cert_put.stmt)) {
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

	return certdb_qry_cleanup(qry_cert_put.stmt, e);
fail:
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
