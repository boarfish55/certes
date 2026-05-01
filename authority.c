/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/param.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <mdr/mdrd.h>
#include <mdr/util.h>
#include "authority.h"
#include "agent.h"
#include "cert.h"

extern struct certes_flatconf certes_conf;

/*
 * Create a bootstrap entry with certificate parameters and a challenge key
 * to be used when an agent connects with a DIALIN call.
 * This will populate and save a bootstrap_entry in the certdb.
 */
static int
authority_make_bootstrap(const char *cn, const char **sans,
    size_t sans_sz, const char **roles, size_t roles_sz, uint32_t cert_expiry,
    uint32_t timeout, uint32_t flags, struct xerr *e)
{
	int                    i, j, len, c;
	char                   subject[CERTES_MAX_SUBJET_LENGTH] = "";
	struct bootstrap_entry be;
	struct timespec        tp;

	if (flags & CERTDB_BOOTSTRAP_FLAG_SETCN) {
		if (snprintf(subject, sizeof(subject),
		    "/O=%s/CN=%s/emailAddress=%s", certes_conf.cert_org,
		    cn, certes_conf.cert_email) >= sizeof(subject))
			return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "resulting subject name is too long "
			    "for commonName %s", cn);
	}

	arc4random_buf(be.bootstrap_key, sizeof(be.bootstrap_key));

	clock_gettime(CLOCK_REALTIME, &tp);

	be.valid_until_sec = tp.tv_sec + timeout;
	be.not_before_sec = tp.tv_sec;
	be.not_after_sec = tp.tv_sec + cert_expiry;
	be.subject = subject;
	be.flags = flags;

	for (i = 0; i < roles_sz; i++) {
		if (strlen(roles[i]) > CERTES_MAX_ROLE_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "role name %s longer than limit of %d",
			    roles[i], CERTES_MAX_ROLE_LENGTH);
		len = strlen(roles[i]);
		for (j = 0; j < len; j++)
			if (!isalnum(roles[i][j]))
				return XERRF(e, XLOG_APP, XLOG_INVALID,
				    "role name may only contain letters or "
				    "digits");
	}

	for (i = 0; i < sans_sz; i++) {
		if (strlen(sans[i]) > CERTES_MAX_SAN_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "SAN name %s longer than limit of %d",
			    sans[i], CERTES_MAX_SAN_LENGTH);
		len = strlen(sans[i]);
		for (j = 0; j < len; j++) {
			c = sans[i][j];
			if (isspace(c) || c == ',')
				return XERRF(e, XLOG_APP, XLOG_INVALID,
				    "SAN may not contain spaces or commas");
		}
	}

	be.roles = (char **)roles;
	be.roles_sz = roles_sz;
	be.sans = (char **)sans;
	be.sans_sz = sans_sz;

	return certdb_put_bootstrap(&be, e);
}

int
authority_bootstrap_setup(struct mdrd_besession *sess, struct umdr *m,
    struct xerr *e)
{
	const char       *subject;
	const char      **roles = NULL;
	int32_t           roles_sz;
	const char      **sans = NULL;
	int32_t           sans_sz;
	uint32_t          cert_expiry, timeout, flags;
	struct umdr_vec   uv[6];

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (!agent_is_authority()) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_BOOTSTRAP, xerrz(e))) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_DENIED, ROLE_BOOTSTRAP " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_BOOTSTRAP " role required");
	}

	if (umdr_unpack(m, msg_bootstrap_setup, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}

	subject = uv[0].v.s.bytes;
	sans_sz = umdr_vec_alen(&uv[1].v.as);
	roles_sz = umdr_vec_alen(&uv[2].v.as);
	cert_expiry = uv[3].v.u32;
	timeout = uv[4].v.u32;
	flags = uv[5].v.u32;

	if ((sans = malloc(sizeof(char *) * (sans_sz + 1))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	if ((roles = malloc(sizeof(char *) * (roles_sz + 1))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	if (umdr_vec_as(&uv[1].v.as, sans, sans_sz + 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}
	if (umdr_vec_as(&uv[2].v.as, roles, roles_sz + 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}

	if (authority_make_bootstrap(subject, sans, sans_sz, roles,
	    roles_sz, cert_expiry, timeout, flags, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	free(sans);
	free(roles);

	if (mdrd_beout_ok(sess, MDRD_BEOUT_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout_ok");
		return -1;
	}

	return 0;
fail:
	free(sans);
	free(roles);
	mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failure");
	return -1;
}

int
authority_role_san_mod(int role, struct mdrd_besession *sess, struct umdr *m,
    struct xerr *e)
{
	struct umdr_vec     uv[3];
	struct xerr         e2;
	struct cert_entry  *ce = NULL;
	const char         *serial;
	char              **res = NULL;
	size_t              res_sz = 0;
	const char        **add = NULL;
	size_t              add_sz;
	const char        **del = NULL;
	size_t              del_sz;
	char              **tmp;
	int                 i, j, r, len;
	int                 in_txn = 0;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (!agent_is_authority()) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_CERTADMIN, xerrz(e))) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_DENIED, ROLE_CERTADMIN " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_CERTADMIN " role required");
	}

	if (umdr_unpack(m, (role) ? msg_cert_mod_roles : msg_cert_mod_sans,
	    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}
	serial = uv[0].v.s.bytes;
	add_sz = umdr_vec_alen(&uv[1].v.as);
	del_sz = umdr_vec_alen(&uv[2].v.as);
	if ((add = malloc(sizeof(char *) * (add_sz + 1))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	if ((del = malloc(sizeof(char *) * (del_sz + 1))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	if (umdr_vec_as(&uv[1].v.as, add, add_sz + 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}
	if (umdr_vec_as(&uv[2].v.as, del, del_sz + 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}

	if (certdb_begin_txn(xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}
	in_txn = 1;

	if ((ce = certdb_get_cert(serial, xerrz(e))) == NULL) {
		if (xerr_is(e, XLOG_APP, XLOG_NOTFOUND)) {
			mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
			    MDR_ERR_FAIL, "no such serial");
			XERR_PREPENDFN(e);
			goto fail_no_reply;
		}
		XERR_PREPENDFN(e);
		goto fail;
	}

	for (i = 0; i < del_sz; i++) {
		len = strlen(del[i]);
		for (j = 0; j < len; j++) {
			if (role) {
				if (!isalnum(del[i][j])) {
					mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
					    MDR_ERR_FAIL,
					    "role name may only contain letters"
					    "or digits");
					XERRF(e, XLOG_APP, XLOG_INVALID,
					    "role name may only contain letters"
					    "or digits");
					goto fail_no_reply;
				}
			} else {
				if (isspace(del[i][j]) || del[i][j] == ',') {
					mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
					    MDR_ERR_FAIL,
					    "SAN may not contain spaces or "
					    "commas");
					XERRF(e, XLOG_APP, XLOG_INVALID,
					    "SAN may not contain spaces or "
					    "commas");
					goto fail_no_reply;
				}
			}
		}
	}

	for (i = 0; i < ((role) ? ce->roles_sz : ce->sans_sz); i++) {
		for (j = 0; j < del_sz; j++)
			if (strcmp((role) ? ce->roles[i] : ce->sans[i],
			    del[j]) == 0)
				break;
		if (j >= del_sz) {
			tmp = strarray_add(res,
			    (role) ? ce->roles[i] : ce->sans[i]);
			if (tmp == NULL) {
				XERRF(e, XLOG_ERRNO, errno, "strarray_add");
				goto fail;
			}
			res = tmp;
			res_sz++;
		}
	}
	free(del);
	del = NULL;

	for (i = 0; i < add_sz; i++) {
		len = strlen(add[i]);
		if (role) {
			if (len > CERTES_MAX_ROLE_LENGTH) {
				mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
				    MDR_ERR_FAIL, "role name over limit");
				XERRF(e, XLOG_APP, XLOG_OVERFLOW,
				    "role name %s longer than limit of %d",
				    add[i], CERTES_MAX_ROLE_LENGTH);
				goto fail_no_reply;
			}
			for (j = 0; j < len; j++) {
				if (!isalnum(add[i][j])) {
					mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
					    MDR_ERR_FAIL, "role name may only "
					    "contain  letters or digits");
					XERRF(e, XLOG_APP, XLOG_INVALID,
					    "role name may only contain letters"
					    "or digits");
					goto fail_no_reply;
				}
			}
		} else {
			if (len > CERTES_MAX_SAN_LENGTH) {
				mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
				    MDR_ERR_FAIL, "SAN name longer than limit");
				XERRF(e, XLOG_APP, XLOG_OVERFLOW,
				    "SAN name %s longer than limit of %d",
				    add[i], CERTES_MAX_SAN_LENGTH);
				goto fail_no_reply;
			}
			for (j = 0; j < len; j++) {
				if (isspace(add[i][j]) || add[i][j] == ',') {
					mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
					    MDR_ERR_FAIL, "SAN may not "
					    "contain spaces or commas");
					XERRF(e, XLOG_APP, XLOG_INVALID,
					    "SAN may not contain spaces or "
					    "commas");
					goto fail_no_reply;
				}
			}
		}
		for (j = 0; j < ((role) ? ce->roles_sz : ce->sans_sz); j++)
			if (strcmp((role) ? ce->roles[j] : ce->sans[j],
			    add[i]) == 0)
				break;
		if (j >= ((role) ? ce->roles_sz : ce->sans_sz)) {
			tmp = strarray_add(res, add[i]);
			if (tmp == NULL) {
				XERRF(e, XLOG_ERRNO, errno, "strarray_add");
				goto fail;
			}
			res = tmp;
			res_sz++;
		}
	}
	free(add);
	add = NULL;

	if (role)
		r = certdb_mod_roles(serial, (const char **)res,
		    res_sz, xerrz(e));
	else
		r = certdb_mod_sans(serial, (const char **)res,
		    res_sz, xerrz(e));
	if (r == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	free(res);
	res = NULL;
	certdb_cert_free(ce);
	ce = NULL;

	if (certdb_commit_txn(xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (mdrd_beout_ok(sess, MDRD_BEOUT_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout_ok");
		return -1;
	}

	return 0;
fail:
	mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failure");
fail_no_reply:
	if (in_txn)
		if (certdb_rollback_txn(xerrz(&e2)) == -1)
			xlog(LOG_ERR, &e2, __func__);
	certdb_cert_free(ce);
	free(res);
	free(add);
	free(del);
	return -1;
}

int
authority_revoke(struct mdrd_besession *sess, struct umdr *m, struct xerr *e)
{
	struct umdr_vec    uv[1];
	struct pmdr        pm;
	char               pbuf[mdr_spec_base_sz(msg_reload_crls, 0)];
	struct xerr        e2;
	struct cert_entry *ce;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (!agent_is_authority()) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_CERTADMIN, xerrz(e))) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_DENIED, ROLE_CERTADMIN " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_CERTADMIN " role required");
	}

	if (umdr_unpack(m, msg_revoke, uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}

	if (certdb_begin_txn(xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if ((ce = certdb_get_cert(uv[0].v.s.bytes, xerrz(e))) == NULL) {
		if (certdb_rollback_txn(xerrz(&e2)) == -1)
			xlog(LOG_ERR, &e2, __func__);
		if (xerr_is(e, XLOG_APP, XLOG_NOTFOUND)) {
			mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
			    MDR_ERR_FAIL, "no such serial");
			return XERR_PREPENDFN(e);
		}
		XERR_PREPENDFN(e);
		goto fail;
	}
	certdb_cert_free(ce);
	if (certdb_revoke_cert(uv[0].v.s.bytes, xerrz(e)) == -1) {
		if (certdb_rollback_txn(xerrz(&e2)) == -1)
			xlog(LOG_ERR, &e2, __func__);
		XERR_PREPENDFN(e);
		goto fail;
	}
	if (certdb_commit_txn(xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	if (pmdr_pack(&pm, msg_reload_crls, NULL, 0) == MDR_FAIL)
		abort();

	if (agent_send(pmdr_buf(&pm), pmdr_size(&pm), xerrz(e)) == -1)
		xlog(LOG_ERR, e, "%s", __func__);

	if (mdrd_beout_ok(sess, MDRD_BEOUT_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout_ok");
		return -1;
	}

	return 0;
fail:
	mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failure");
	return -1;
}

int
authority_cert_get(struct mdrd_besession *sess, struct umdr *m, struct xerr *e)
{
	struct umdr_vec    uv[1];
	struct pmdr        pm;
	struct pmdr_vec    pv[3];
	struct cert_entry *ce = NULL;
	char               pbuf[mdr_spec_base_sz(msg_cert_get_answer,
	    certes_conf.max_cert_size)];

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (!agent_is_authority()) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_CERTADMIN, xerrz(e))) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_DENIED, ROLE_CERTADMIN " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_CERTADMIN " role required");
	}

	if (umdr_unpack(m, msg_cert_get, uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}

	if ((ce = certdb_get_cert(uv[0].v.s.bytes, xerrz(e))) == NULL) {
		if (xerr_is(e, XLOG_APP, XLOG_NOTFOUND)) {
			mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
			    MDR_ERR_FAIL, "no such serial");
			return 0;
		}
		XERR_PREPENDFN(e);
		goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_B;
	pv[0].v.b.bytes = ce->der;
	pv[0].v.b.sz = ce->der_sz;
	pv[1].type = MDR_U64;
	pv[1].v.u64 = ce->revoked_at_sec;
	pv[2].type = MDR_U32;
	pv[2].v.u32 = ce->flags;
	if (pmdr_pack(&pm, msg_cert_get_answer, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		abort();
	certdb_cert_free(ce);

	if (mdrd_beout(sess, MDRD_BEOUT_FNONE, &pm) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout");
		goto fail;
	}

	return 0;
fail:
	mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failure");
	return -1;
}

struct find_certs_args {
	char     **serials;
	char     **subjects;
	uint32_t  *flags;
	int        count;
	int        error;
};

static int
find_certs(const struct cert_entry *ce, void *args)
{
	struct find_certs_args  *a = (struct find_certs_args *)args;
	char                   **tmp;
	uint32_t                *tmpflags;

	if ((tmp = strarray_add(a->serials, ce->serial)) == NULL)
		goto fail;
	a->serials = tmp;
	if ((tmp = strarray_add(a->subjects, ce->subject)) == NULL)
		goto fail;
	a->subjects = tmp;
	if ((tmpflags = reallocarray(a->flags, a->count + 1,
	    sizeof(uint32_t))) == NULL)
		goto fail;
	a->flags = tmpflags;
	a->flags[a->count] = ce->flags;
	a->count++;
	return 1;
fail:
	free(a->serials);
	free(a->subjects);
	free(a->flags);
	a->error = 1;
	return 0;
}

int
authority_cert_find(struct mdrd_besession *sess, struct umdr *m, struct xerr *e)
{
	struct umdr_vec        uv[1];
	struct pmdr            pm;
	struct pmdr_vec        pv[3];
	char                   pbuf[CERTES_MAX_MSG_SIZE];
	struct find_certs_args a = { NULL, NULL, NULL, 0, 0 };

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (!agent_is_authority()) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_CERTADMIN, xerrz(e))) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_DENIED, ROLE_CERTADMIN " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_CERTADMIN " role required");
	}

	if (umdr_unpack(m, msg_cert_find, uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}

	if (certdb_find_certs(uv[0].v.s.bytes, &find_certs, &a,
	    xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (a.error) {
		XERRF(e, XLOG_ERRNO, ENOMEM, "find_certs");
		goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_AS;   /* matching serials */
	pv[0].v.as.items = (const char **)a.serials;
	pv[0].v.as.length = a.count;
	pv[1].type = MDR_AS;   /* matching subjects */
	pv[1].v.as.items = (const char **)a.subjects;
	pv[1].v.as.length = a.count;
	pv[2].type = MDR_AU32; /* matching flags */
	pv[2].v.au32.items = a.flags;
	pv[2].v.au32.length = a.count;
	if (pmdr_pack(&pm, msg_cert_find_answer, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL)
		abort();

	free(a.serials);
	free(a.subjects);
	free(a.flags);

	if (mdrd_beout(sess, MDRD_BEOUT_FNONE, &pm) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout");
		goto fail;
	}

	return 0;
fail:
	mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failure");
	return -1;
}

/*
 * We establish a connection to the commonName in the bootstrap
 * entry to send a challenge. The agent currently connected to us
 * for bootstrap should receive it if it's really who it claims to
 * be and send it back to us.
 */
static int
authority_challenge(struct mdrd_besession *sess, const char *op_id,
    uint64_t dcv, const char *challenge_host, struct xerr *e)
{
	char                   port[6];
	int                    fd;
	struct timeval         timeout;
	SSL_CTX               *ctx = NULL;
	SSL                   *ssl = NULL;
	BIO                   *bio = NULL;
	struct pmdr            pm;
	char                   pbuf[256];
	struct pmdr_vec        pv[2];
	int                    r, status = 0;
	struct certes_session *cs = (struct certes_session *)sess->data;

	if ((cs->challenge = malloc(CERTES_CHALLENGE_LENGTH)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto befail;
	}
	arc4random_buf(cs->challenge, CERTES_CHALLENGE_LENGTH);

	if (snprintf(port, sizeof(port), "%u", CERTES_AGENT_PORT) >=
	    sizeof(port)) {
		XERRF(e, XLOG_APP, XLOG_INVALID,
		    "failed to convert agent port");
		goto befail;
	}

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
		goto befail;
	}

	SSL_CTX_set_security_level(ctx, 3);

	if (SSL_CTX_use_PrivateKey(ctx, agent_key()) != 1) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_CTX_use_PrivateKey");
		goto befail;
	}

	if (SSL_CTX_use_certificate(ctx, agent_cert()) != 1) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_CTX_use_certificate");
		goto befail;
	}

	if ((bio = BIO_new_ssl_connect(ctx)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new_ssl_connect");
		goto befail;
	}

	BIO_get_ssl(bio, &ssl);
	if (ssl == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_get_ssl");
		goto befail;
	}

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(bio, challenge_host);
	BIO_set_conn_port(bio, port);

	if (BIO_do_connect(bio) <= 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "dialback failed");
		BIO_free(bio);
		SSL_CTX_free(ctx);
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_do_connect: %s", challenge_host);
	}

	timeout.tv_sec = certes_conf.agent_send_timeout_ms / 1000;
	timeout.tv_usec = certes_conf.agent_send_timeout_ms % 1000;
	fd = BIO_get_fd(bio, NULL);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
	    &timeout, sizeof(timeout)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "setsockopt");
		goto befail;
	}

	timeout.tv_sec = certes_conf.agent_recv_timeout_ms / 1000;
	timeout.tv_usec = certes_conf.agent_recv_timeout_ms % 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
	    &timeout, sizeof(timeout)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "setsockopt");
		goto befail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op_id;
	pv[1].type = MDR_B;
	pv[1].v.b.bytes = cs->challenge;
	pv[1].v.b.sz = sizeof(cs->challenge);
	if (pmdr_pack(&pm,
	    (dcv == MDR_DCV_CERTES_BOOTSTRAP_DIALBACK)
	    ? msg_bootstrap_dialback
	    : msg_cert_renew_dialback,
	    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		status = -1;
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/dialback");
	} else if ((r = BIO_write(bio, pmdr_buf(&pm), pmdr_size(&pm))) == -1) {
		status = -1;
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "error during dialback write");
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	} else if (r < pmdr_size(&pm)) {
		status = -1;
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "short write during dialback");
		XERRF(e, XLOG_APP, XLOG_SHORTIO, "BIO_write");
	}

	BIO_flush(bio);
	BIO_free_all(bio);
	SSL_CTX_free(ctx);
	return status;
befail:
	if (bio != NULL)
		BIO_free(bio);
	if (ctx != NULL)
		SSL_CTX_free(ctx);
	beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failed");
	return -1;
}

/*
 * Incoming bootstrap request from agent. They provide a bootstrap key,
 * which we'll then use to lookup information to challenge them and issue
 * a certificate.
 */
int
authority_bootstrap_dialin(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct bootstrap_entry *be = NULL;
	struct umdr_vec         uv[3];
	struct timespec         now;
	struct certes_session  *cs = (struct certes_session *)sess->data;
	const char             *op_id;
	char                    challenge_host[256];
	X509_NAME              *subject;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (umdr_unpack(msg, msg_bootstrap_dialin, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno,
		    "umdr_unpack/msg_bootstrap_dialin");

	op_id = uv[0].v.s.bytes;

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (uv[1].v.b.sz != CERTES_BOOTSTRAP_KEY_LENGTH) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BADMSG,
		    "bootstrap key received from client has incorrect length");
		return XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap key received from client has incorrect length");
	}

	if ((be = certdb_get_bootstrap(uv[1].v.b.bytes, uv[1].v.b.sz, e))
	    == NULL) {
		/*
		 * We never report an error if the bootstrap key is not
		 * found to mitigate enumeration attacks.
		 */
		beout_ok(sess, op_id, MDRD_BEOUT_FNONE);
		return XERR_PREPENDFN(e);
	}

	cs->req = d2i_X509_REQ(NULL, (const unsigned char **)&uv[2].v.b.bytes,
	    uv[2].v.b.sz);
	if (cs->req == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "failed to decode REQ");
		XERRF(e, XLOG_SSL, ERR_get_error(), "d2i_X509_REQ");
		goto fail;
	}

	if (be->flags & CERTDB_BOOTSTRAP_FLAG_SETCN) {
		if (cert_subject_cn(be->subject, challenge_host,
		    sizeof(challenge_host), e) == -1) {
			XERR_PREPENDFN(e);
			goto fail;
		}
	} else {
		subject = X509_REQ_get_subject_name(cs->req);
		if (subject == NULL) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_REQ_get_subject_name");
			goto fail;
		}
		if (X509_NAME_get_text_by_NID(subject, NID_commonName,
		    challenge_host, sizeof(challenge_host)) == -1) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_NAME_get_text_by_NID");
			goto fail;
		}
	}

	/*
	 * Make sure the key has not expired.
	 */
	clock_gettime(CLOCK_REALTIME, &now);
	if (now.tv_sec > be->valid_until_sec) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "bootstrap key is expired");
		XERRF(e, XLOG_APP, XLOG_TIMEOUT,
		    "bootstrap key is expired");
		goto fail;
	}

	if ((cs->bootstrap_key = malloc(CERTES_BOOTSTRAP_KEY_LENGTH))
	    == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	memcpy(cs->bootstrap_key, uv[1].v.b.bytes,
	    CERTES_BOOTSTRAP_KEY_LENGTH);

	/*
	 * Then we challenge the client by connecting to its CommonName
	 * as per our DB.
	 */
	if (authority_challenge(sess, op_id,
	    MDR_DCV_CERTES_BOOTSTRAP_DIALBACK, challenge_host, e) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}
	certdb_bootstrap_free(be);
	beout_ok(sess, op_id, MDRD_BEOUT_FNONE);
	return 0;
fail:
	certdb_bootstrap_free(be);
	return -1;
}

#ifdef __linux__
static int
pack_intermediates(X509 *crt, uint8_t **der_chain, size_t *chain_sz,
    struct xerr *e)
{
	STACK_OF(X509) *chain = NULL;
	X509           *c;
	int             i, status = 0;
	int             sz;
	uint8_t        *p, *der;

	*der_chain = NULL;
	*chain_sz = 0;

	chain = X509_build_chain(crt, NULL, agent_cert_store(), 0, NULL, NULL);
	if (chain == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "X509_build_chain");

	if (sk_X509_num(chain) < 2) {
		XERRF(e, XLOG_APP, XLOG_FAIL, "not intermediate cert?");
		goto end;
	}

	/*
	 * We start at index 1 because we already send the cert itself.
	 * We only want intermediates.
	 */
	for (i = 1; i < sk_X509_num(chain); i++) {
		c = sk_X509_value(chain, i);
		sz = i2d_X509(c, NULL);
		if (sz < 0) {
			status = XERRF(e, XLOG_SSL, ERR_get_error(),
			    "i2d_X509");
			goto end;
		}
		*chain_sz += sz + sizeof(uint32_t);
	}

	if ((*der_chain = malloc(*chain_sz)) == NULL) {
		status = XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto end;
	}
	p = *der_chain;

	for (i = 1; i < sk_X509_num(chain); i++) {
		c = sk_X509_value(chain, i);
		der = NULL;
		sz = i2d_X509(c, &der);
		if (sz < 0) {
			free(*der_chain);
			status = XERRF(e, XLOG_SSL, ERR_get_error(),
			    "i2d_X509");
			goto end;
		}
		*((uint32_t *)p) = htobe32(sz);
		p += sizeof(uint32_t);
		memcpy(p, der, sz);
		p += sz;
		free(der);
	}
end:
	sk_X509_pop_free(chain, X509_free);
	return status;
}
#else
static int
pack_intermediates(X509 *crt, uint8_t **der_chain, size_t *chain_sz,
    struct xerr *e)
{
	int      sz;
	uint8_t *p, *der;

	*der_chain = NULL;
	*chain_sz = 0;

	/*
	 * X509_build_chain does not exist on OpenBSD, but really
	 * we should normally only have to pack this authority's
	 * cert and nothing else, so that should suffice.
	 */
	sz = i2d_X509(agent_cert(), NULL);
	if (sz < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
	*chain_sz += sz + sizeof(uint32_t);

	if ((*der_chain = malloc(*chain_sz)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");
	p = *der_chain;

	der = NULL;
	sz = i2d_X509(agent_cert(), &der);
	if (sz < 0) {
		free(*der_chain);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
	}

	*((uint32_t *)p) = htobe32(sz);
	p += sizeof(uint32_t);
	memcpy(p, der, sz);
	free(der);

	return 0;
}
#endif

static int
authority_send_cert(struct mdrd_besession *sess, const char *op_id,
    X509 *crt, const uint8_t *crt_buf, int crt_len, struct xerr *e)
{
	uint8_t         *der_chain = NULL;
	size_t           der_sz;
	struct pmdr      pm;
	struct pmdr_vec  pv[3];
	char             pbuf[mdr_spec_base_sz(msg_send_cert,
	    certes_conf.max_cert_size * 2)];

	if (pack_intermediates(crt, &der_chain, &der_sz, xerrz(e)) == -1) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
                goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S; /* Op ID */
	pv[0].v.s = op_id;
	pv[1].type = MDR_B; /* cert */
	pv[1].v.b.bytes = crt_buf;
	pv[1].v.b.sz = crt_len;
	pv[2].type = MDR_B; /* intermediates */
	pv[2].v.b.bytes = der_chain;
	pv[2].v.b.sz = der_sz;
	if (pmdr_pack(&pm, msg_send_cert, pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/msg_send_cert");
		goto fail;
	}

	if (mdrd_beout(sess, MDRD_BEOUT_FNONE, &pm) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout");
		goto fail;
	}

	free(der_chain);
	return 0;
fail:
	free(der_chain);
	return -1;
}

int
authority_bootstrap_answer(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct bootstrap_entry *be = NULL;
	struct cert_entry       ce;
	struct umdr_vec         uv[2];
	struct certes_session  *cs = (struct certes_session *)sess->data;
	X509                   *crt = NULL;
	const char             *op_id;
	struct tm               tm;
	unsigned char          *crt_buf = NULL;
	int                     crt_len;

	if (umdr_unpack(msg, msg_bootstrap_answer, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_bootstrap_answer");

	op_id = uv[0].v.s.bytes;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s, op_id=%s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (cs->challenge == NULL || cs->req == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "failed challenge");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    "client failed challenge");
	}

	if (memcmp(cs->challenge, uv[1].v.b.bytes,
	    MIN(sizeof(cs->challenge), uv[1].v.b.sz)) != 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "failed challenge");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    "client failed challenge");
	}

	if ((be = certdb_get_bootstrap(cs->bootstrap_key,
	    CERTES_BOOTSTRAP_KEY_LENGTH, e)) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "no such bootstrap entry");
		return XERR_PREPENDFN(e);
	}

	crt = cert_sign_req(cs->req, be, xerrz(e));
	if (crt == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}

	crt_len = i2d_X509(crt, &crt_buf);
	if (crt_len < 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
                XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
		goto fail;
	}

	bzero(&ce, sizeof(ce));
	if ((ce.serial = cert_serial_to_hex(crt, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	if ((ce.subject = cert_subject_oneline(crt, xerrz(e))) == NULL) {
		free(ce.serial);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	ce.sans = be->sans;
	ce.sans_sz = be->sans_sz;
	ce.roles = be->roles;
	ce.roles_sz = be->roles_sz;
	ASN1_TIME_to_tm(X509_get_notBefore(crt), &tm);
	ce.not_before_sec = timegm(&tm);
	ASN1_TIME_to_tm(X509_get_notAfter(crt), &tm);
	ce.not_after_sec = timegm(&tm);
	ce.flags = CERTDB_FLAG_NONE;
	ce.der = crt_buf;
	ce.der_sz = crt_len;
	if (certdb_put_cert(&ce, xerrz(e)) == -1) {
		free(ce.serial);
		free(ce.subject);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	xlog(LOG_NOTICE, NULL, "%s: cert serial %s issued for subject %s",
	    __func__, ce.serial, ce.subject);
	free(ce.serial);
	free(ce.subject);

	if (authority_send_cert(sess, op_id, crt, crt_buf, crt_len,
	    xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (certdb_del_bootstrap(be, xerrz(e)) == -1)
		xlog(LOG_ERR, e, "%s", __func__);

	xlog(LOG_NOTICE, NULL, "%s: op_id %s completed", __func__, op_id);

	free(crt_buf);
	X509_free(crt);
	certdb_bootstrap_free(be);
	return 0;
fail:
	certdb_bootstrap_free(be);
	free(crt_buf);
	if (crt != NULL)
		X509_free(crt);
	return -1;
}

int
authority_cert_renew_answer(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct cert_entry     *ce = NULL;
	struct umdr_vec        uv[2];
	struct certes_session *cs = (struct certes_session *)sess->data;
	X509                  *crt = NULL;
	const char            *op_id;
	struct tm              tm;
	char                  *serial;
	int                    der_sz;

	if (umdr_unpack(msg, msg_cert_renew_answer, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_bootstrap_answer");

	op_id = uv[0].v.s.bytes;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s, op_id=%s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (cs->challenge == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "failed challenge");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    "client failed challenge");
	}

	if (memcmp(cs->challenge, uv[1].v.b.bytes,
	    MIN(sizeof(cs->challenge), uv[1].v.b.sz)) != 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "failed challenge");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    "client failed challenge");
	}

	if ((serial = cert_serial_to_hex(sess->cert, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		return XERR_PREPENDFN(e);
	}
	if ((ce = certdb_get_cert(serial, xerrz(e))) == NULL) {
		free(serial);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failure");
		return XERR_PREPENDFN(e);
	}
	free(serial);

	crt = cert_sign(sess->cert, agent_cert(), ce, xerrz(e));
	if (crt == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}

	/*
	 * Get the new cert serial
	 */
	if ((serial = cert_serial_to_hex(crt, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	free(ce->serial);
	ce->serial = serial;

	/*
	 * We can reuse 'ce' and simply modify the fields to update. But
	 * since ce->der is dynamically allocated, free it first.
	 */
	free(ce->der);
	ce->der = NULL;
	der_sz = i2d_X509(crt, &ce->der);
	if (der_sz < 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
                XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
                goto fail;
	}
	ce->der_sz = der_sz;

	ASN1_TIME_to_tm(X509_get_notBefore(crt), &tm);
	ce->not_before_sec = timegm(&tm);
	ASN1_TIME_to_tm(X509_get_notAfter(crt), &tm);
	ce->not_after_sec = timegm(&tm);

	/*
	 * We'll just write the new cert and let the old one expire.
	 * This also gives services using it time to load the new one.
	 */
	if (certdb_put_cert(ce, xerrz(e)) == -1) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (authority_send_cert(sess, op_id, crt, ce->der,
	    ce->der_sz, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	xlog(LOG_NOTICE, NULL, "%s: cert serial %s issued for subject %s",
	    __func__, ce->serial, ce->subject);
	xlog(LOG_NOTICE, NULL, "%s: op_id %s completed", __func__, op_id);

	certdb_cert_free(ce);
	X509_free(crt);
	return 0;
fail:
	certdb_cert_free(ce);
	if (crt != NULL)
		X509_free(crt);
	return -1;
}

int
authority_cert_renewal_inquiry(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct umdr_vec    uv[2];
	const char        *op_id;
	char              *serial;
	struct cert_entry *ce;
	char               challenge_host[256];
	struct pmdr        pm;
	char               pbuf[1024];
	struct pmdr_vec    pv[1];

	if (umdr_unpack(msg, msg_cert_renewal_inquiry, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_cert_renewal_inquiry");

	op_id = uv[0].v.s.bytes;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s, op_id=%s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_AGENT, xerrz(e))) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    ROLE_AGENT " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_AGENT " role required");
	}

	if ((serial = cert_serial_to_hex(sess->cert, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		return XERR_PREPENDFN(e);
	}
	if ((ce = certdb_get_cert(serial, xerrz(e))) == NULL) {
		free(serial);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		return XERR_PREPENDFN(e);
	}
	free(serial);

	switch (cert_must_renew(sess->cert, ce, xerrz(e))) {
	case -1:
		XERR_PREPENDFN(e);
		goto fail;
	case 0:
		/*
		 * Cert is already up-to-date, no need to
		 * do anything
		 */
		certdb_cert_free(ce);
		beout_ok(sess, op_id, MDRD_BEOUT_FNONE);
		xlog(LOG_INFO, NULL, "%s: cert is already up-to-date "
		    "for %s, op_id=%s", __func__,
		    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);
		return 0;
	default:
		/* We have to renew */
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_S;
		pv[0].v.s = op_id;
		if (pmdr_pack(&pm, msg_cert_renewal_required,
		    pv, PMDRVECLEN(pv)) == MDR_FAIL)
			abort();
		if (mdrd_beout(sess, MDRD_BEOUT_FNONE, &pm) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "mdrd_beout");
			goto fail;
		}
		break;
	}

	if (cert_subject_cn(ce->subject, challenge_host,
	    sizeof(challenge_host), e) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (authority_challenge(sess, op_id,
	    MDR_DCV_CERTES_CERT_RENEW_DIALBACK, challenge_host, e) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	certdb_cert_free(ce);
	return 0;
fail:
	certdb_cert_free(ce);
	beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failed");
	return -1;
}

int
authority_fetch_outdated_crls(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct umdr_vec           uv[3];
	const char               *op_id;
	struct pmdr               pm;
	char                      pbuf[CERTES_MAX_MSG_SIZE];
	uint8_t                   crl_buf[CERTES_MAX_MSG_SIZE];
	uint8_t                  *p;
	int                       der_sz;
	struct pmdr_vec           pv[3];
	uint32_t                  crl_count;
	const char              **issuers = NULL;
	uint64_t                 *last_updates = NULL;
	const char              **upd_issuers = NULL;
	uint32_t                 *upd_crl_sizes = NULL;
	int                       i, j, k, update;
	const struct loaded_crls *loaded_crls = agent_get_loaded_crls();

	if (umdr_unpack(msg, msg_fetch_outdated_crls, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_fetch_crls_updated_after");

	op_id = uv[0].v.s.bytes;

	xlog(LOG_INFO, NULL, "%s: handling for %s, op_id=%s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	crl_count = umdr_vec_alen(&uv[1].v.as);
	if (umdr_vec_alen(&uv[2].v.au64) != crl_count) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "count of issuers and last update is not the same");
		goto fail;
	}
	if (crl_count > INT_MAX) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW, "too many CRLs in payload");
		goto fail;
	}

	if ((issuers = malloc(sizeof(char *) * crl_count)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	if ((last_updates = malloc(sizeof(uint64_t) * crl_count)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	if ((upd_issuers = malloc(sizeof(char *) * crl_count)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	if ((upd_crl_sizes = malloc(sizeof(uint32_t) * crl_count)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	if (umdr_vec_as(&uv[1].v.as, issuers, crl_count) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}
	if (umdr_vec_au64(&uv[2].v.au64, last_updates, crl_count) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op_id;
	pv[1].type = MDR_AU32; /* CRL byte sizes */
	pv[1].v.au32.items = upd_crl_sizes;
	pv[2].type = MDR_B;    /* CRL bytes */
	pv[2].v.b.bytes = crl_buf;
	pv[2].v.b.sz = 0;
	for (p = crl_buf, i = 0, k = 0; i < loaded_crls->count; i++) {
		update = 1;
		for (j = 0; j < crl_count; j++) {
			if (strcmp(loaded_crls->issuers[i], issuers[j]) != 0)
				continue;
			if (last_updates[j] < loaded_crls->last_updates[i])
				continue;
			update = 0;
		}

		if (!update)
			continue;

		der_sz = i2d_X509_CRL(loaded_crls->crls[i], NULL);
		if ((p - crl_buf) + der_sz > sizeof(crl_buf)) {
			XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "CRL data too large to fit in MDR");
			goto fail;
		}
		if (der_sz < i2d_X509_CRL(loaded_crls->crls[i], &p)) {
			XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509_CRL");
			goto fail;
		}

		xlog(LOG_INFO, NULL, "%s: sending CRL with issuer %s to "
		    "client (size=%d)",
		    __func__, loaded_crls->issuers[i], der_sz);

		upd_issuers[k] = loaded_crls->issuers[i];
		upd_crl_sizes[k] = der_sz;
		pv[2].v.b.sz += der_sz;
		k++;
	}
	pv[1].v.au32.length = k;

	if (pmdr_pack(&pm, msg_send_updated_crls,
	    pv, PMDRVECLEN(pv)) == MDR_FAIL)
		abort();
	if (mdrd_beout(sess, MDRD_BEOUT_FNONE, &pm) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout");
		goto fail;
	}

	free(issuers);
	free(upd_issuers);
	free(upd_crl_sizes);
	free(last_updates);

	return 0;
fail:
	if (last_updates != NULL)
		free(last_updates);
	if (issuers != NULL)
		free(issuers);
	if (upd_issuers != NULL)
		free(upd_issuers);
	if (upd_crl_sizes != NULL)
		free(upd_crl_sizes);
	beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failed");
	return -1;
}
