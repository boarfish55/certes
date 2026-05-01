/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <err.h>
#include "mdr_certes.h"

struct mdr_def msgdef_error = {
	MDR_DCV_CERTES_ERROR,
	"certes.error",
	{
		MDR_S,   /* Operation identifier */
		MDR_U32, /* Error code */
		MDR_S,   /* Message */
		MDR_LAST
	}
};
const struct mdr_spec *msg_error;

/* Generic OK message */
struct mdr_def msgdef_ok = {
	MDR_DCV_CERTES_OK,
	"certes.ok",
	{
		MDR_S,   /* Operation identifier */
		MDR_LAST
	}
};
const struct mdr_spec *msg_ok;

struct mdr_def msgdef_bootstrap_setup = {
	MDR_DCV_CERTES_BOOTSTRAP_SETUP,
	"certes.bootstrap_setup",
	{
		MDR_S,   /* cert commonName */
		MDR_AS,  /* cert subjectAltNames */
		MDR_AS,  /* cert roles */
		MDR_U32, /* cert expiry (lifetime) in seconds */
		MDR_U32, /* bootstrap entry timeout */
		MDR_U32, /* flags */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_setup;

struct mdr_def msgdef_revoke = {
	MDR_DCV_CERTES_REVOKE,
	"certes.revoke",
	{
		MDR_S,   /* cert serial */
		MDR_LAST
	}
};
const struct mdr_spec *msg_revoke;

struct mdr_def msgdef_bootstrap_dialin = {
	MDR_DCV_CERTES_BOOTSTRAP_DIALIN,
	"certes.bootstrap_dialin",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Bootstrap key */
		MDR_B,   /* X509_REQ */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_dialin;

struct mdr_def msgdef_bootstrap_dialback = {
	MDR_DCV_CERTES_BOOTSTRAP_DIALBACK,
	"certes.bootstrap_dialback",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_dialback;

struct mdr_def msgdef_bootstrap_answer = {
	MDR_DCV_CERTES_BOOTSTRAP_ANSWER,
	"certes.bootstrap_req",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_answer;

struct mdr_def msgdef_send_cert = {
	MDR_DCV_CERTES_SEND_CERT,
	"certes.bootstrap_send_cert",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* X509 cert (DER) */
		MDR_B,   /* X509 intermediate certs (DER, with size) */
		MDR_LAST
	}
};
const struct mdr_spec *msg_send_cert;

struct mdr_def msgdef_cert_renewal_inquiry = {
	MDR_DCV_CERTES_CERT_RENEWAL_INQUIRY,
	"certes.cert_renewal_inquiry",
	{
		MDR_S,   /* Operation identifier */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renewal_inquiry;

struct mdr_def msgdef_cert_renewal_required = {
	MDR_DCV_CERTES_CERT_RENEWAL_REQUIRED,
	"certes.cert_renewal_required",
	{
		MDR_S,   /* Operation identifier */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renewal_required;

struct mdr_def msgdef_cert_renew_dialback = {
	MDR_DCV_CERTES_CERT_RENEW_DIALBACK,
	"certes.cert_renew_dialback",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renew_dialback;

struct mdr_def msgdef_cert_renew_answer = {
	MDR_DCV_CERTES_CERT_RENEW_ANSWER,
	"certes.cert_renew_answer",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renew_answer;

struct mdr_def msgdef_reload_crls = {
	MDR_DCV_CERTES_RELOAD_CRLS,
	"certes.reload_crls",
	{
		MDR_LAST
	}
};
const struct mdr_spec *msg_reload_crls;

struct mdr_def msgdef_poll_crls_gen = {
	MDR_DCV_CERTES_POLL_CRLS_GEN,
	"certes.poll_crls_gen",
	{
		MDR_LAST
	}
};
const struct mdr_spec *msg_poll_crls_gen;

struct mdr_def msgdef_crls_gen = {
	MDR_DCV_CERTES_CRLS_GEN,
	"certes.crls_gen",
	{
		MDR_U64,  /* CRLs generation (i.e. how many times did we
			     reload them */
		MDR_LAST
	}
};
const struct mdr_spec *msg_crls_gen;

struct mdr_def msgdef_fetch_outdated_crls = {
	MDR_DCV_CERTES_FETCH_OUTDATED_CRLS,
	"certes.fetch_outdated_crls",
	{
		MDR_S,    /* Operation identifier */
		MDR_AS,   /* Authorities (CN) for which we have a CRL */
		MDR_AU64, /* Last update field for each CRL (same order) */
		MDR_LAST
	}
};
const struct mdr_spec *msg_fetch_outdated_crls;

struct mdr_def msgdef_send_updated_crls = {
	MDR_DCV_CERTES_SEND_UPDATED_CRLS,
	"certes.send_updated_crls",
	{
		MDR_S,     /* Operation identifier */
		MDR_AU32,  /* How many CRLs are in the payload and how
			      many bytes for each */
		MDR_B,     /* The DER-encoded CRLs */
		MDR_LAST
	}
};
const struct mdr_spec *msg_send_updated_crls;

struct mdr_def msgdef_cert_get = {
	MDR_DCV_CERTES_CERT_GET,
	"certes.cert_get",
	{
		MDR_S,   /* cert serial */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_get;

struct mdr_def msgdef_cert_get_answer = {
	MDR_DCV_CERTES_CERT_GET_ANSWER,
	"certes.cert_get_answer",
	{
		MDR_B,    /* DER-encoded cert */
		MDR_U64,  /* certdb revoked_at_sec */
		MDR_U32,  /* certdb flags */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_get_answer;

struct mdr_def msgdef_cert_find = {
	MDR_DCV_CERTES_CERT_FIND,
	"certes.cert_find",
	{
		MDR_S,   /* cert pattern */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_find;

struct mdr_def msgdef_cert_find_answer = {
	MDR_DCV_CERTES_CERT_FIND_ANSWER,
	"certes.cert_find_answer",
	{
		MDR_AS,   /* matching serials */
		MDR_AS,   /* matching subjects */
		MDR_AU32, /* matching flags */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_find_answer;

/*
 * Edit certificate roles/SANs
 */
struct mdr_def msgdef_cert_mod_roles = {
	MDR_DCV_CERTES_CERT_MOD_ROLES,
	"certes.cert_mod_roles",
	{
		MDR_S,    /* cert serial */
		MDR_AS,   /* add roles */
		MDR_AS,   /* del roles */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_mod_roles;
struct mdr_def msgdef_cert_mod_sans = {
	MDR_DCV_CERTES_CERT_MOD_SANS,
	"certes.cert_mod_sans",
	{
		MDR_S,    /* cert serial */
		MDR_AS,   /* add SANs */
		MDR_AS,   /* del SANs */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_mod_sans;

int
beout_ok(struct mdrd_besession *sess, const char *op_id, uint32_t beout_flags)
{
	struct pmdr     pm;
	char            pbuf[1024];
	struct pmdr_vec pv[1];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op_id;
	if (pmdr_pack(&pm, msg_ok, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		abort();

	return mdrd_beout(sess, beout_flags, &pm);
}

int
beout_error(struct mdrd_besession *sess, const char *op_id,
    uint32_t beout_flags, uint32_t errcode, const char *errdesc)
{
	struct pmdr     pm;
	char            pbuf[1024];
	struct pmdr_vec pv[3];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op_id;
	pv[1].type = MDR_U32;
	pv[1].v.u32 = errcode;
	pv[2].type = MDR_S;
	pv[2].v.s = errdesc;
	if (pmdr_pack(&pm, msg_error, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		abort();

	return mdrd_beout(sess, beout_flags, &pm);
}

void
load_mdr_defs()
{
	/*
	 * Built-in messages.
	 */
	if (mdr_register_builtin_specs() == MDR_FAIL)
		err(1, "mdr_register_builtin_specs");

	/*
	 * Agent/Authority messages.
	 */
	if ((msg_ok = mdr_register_spec(&msgdef_ok)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_error = mdr_register_spec(&msgdef_error)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_setup =
	    mdr_register_spec(&msgdef_bootstrap_setup)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_revoke = mdr_register_spec(&msgdef_revoke)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_dialin =
	    mdr_register_spec(&msgdef_bootstrap_dialin)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_dialback =
	    mdr_register_spec(&msgdef_bootstrap_dialback)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_answer =
	    mdr_register_spec(&msgdef_bootstrap_answer)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_send_cert =
	    mdr_register_spec(&msgdef_send_cert)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_renewal_inquiry =
	    mdr_register_spec(&msgdef_cert_renewal_inquiry)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_renewal_required =
	    mdr_register_spec(&msgdef_cert_renewal_required)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_renew_dialback =
	    mdr_register_spec(&msgdef_cert_renew_dialback)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_renew_answer =
	    mdr_register_spec(&msgdef_cert_renew_answer)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_reload_crls =
	    mdr_register_spec(&msgdef_reload_crls)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_poll_crls_gen =
	    mdr_register_spec(&msgdef_poll_crls_gen)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_crls_gen =
	    mdr_register_spec(&msgdef_crls_gen)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_fetch_outdated_crls =
	    mdr_register_spec(&msgdef_fetch_outdated_crls)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_send_updated_crls =
	    mdr_register_spec(&msgdef_send_updated_crls)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_get =
	    mdr_register_spec(&msgdef_cert_get)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_get_answer =
	    mdr_register_spec(&msgdef_cert_get_answer)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_find =
	    mdr_register_spec(&msgdef_cert_find)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_find_answer =
	    mdr_register_spec(&msgdef_cert_find_answer)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_mod_roles =
	    mdr_register_spec(&msgdef_cert_mod_roles)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_cert_mod_sans =
	    mdr_register_spec(&msgdef_cert_mod_sans)) == NULL)
		errx(1, "mdr_register_spec");
}
