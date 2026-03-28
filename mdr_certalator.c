#include <err.h>
#include "mdr_certalator.h"

struct mdr_def msgdef_error = {
	MDR_DCV_CERTALATOR_ERROR,
	"certalator.error",
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
	MDR_DCV_CERTALATOR_OK,
	"certalator.ok",
	{
		MDR_S,   /* Operation identifier */
		MDR_LAST
	}
};
const struct mdr_spec *msg_ok;

struct mdr_def msgdef_bootstrap_setup = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP,
	"certalator.bootstrap_setup",
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

struct mdr_def msgdef_bootstrap_dialin = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN,
	"certalator.bootstrap_dialin",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Bootstrap key */
		MDR_B,   /* X509_REQ */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_dialin;

struct mdr_def msgdef_bootstrap_dialback = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK,
	"certalator.bootstrap_dialback",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_dialback;

struct mdr_def msgdef_bootstrap_answer = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_ANSWER,
	"certalator.bootstrap_req",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_answer;

struct mdr_def msgdef_send_cert = {
	MDR_DCV_CERTALATOR_SEND_CERT,
	"certalator.bootstrap_send_cert",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* X509 cert (DER) */
		MDR_B,   /* X509 intermediate certs (DER, with size) */
		MDR_LAST
	}
};
const struct mdr_spec *msg_send_cert;

struct mdr_def msgdef_cert_renewal_inquiry = {
	MDR_DCV_CERTALATOR_CERT_RENEWAL_INQUIRY,
	"certalator.cert_renewal_inquiry",
	{
		MDR_S,   /* Operation identifier */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renewal_inquiry;

struct mdr_def msgdef_cert_renewal_required = {
	MDR_DCV_CERTALATOR_CERT_RENEWAL_REQUIRED,
	"certalator.cert_renewal_required",
	{
		MDR_S,   /* Operation identifier */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renewal_required;

struct mdr_def msgdef_cert_renew_dialback = {
	MDR_DCV_CERTALATOR_CERT_RENEW_DIALBACK,
	"certalator.cert_renew_dialback",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renew_dialback;

struct mdr_def msgdef_cert_renew_answer = {
	MDR_DCV_CERTALATOR_CERT_RENEW_ANSWER,
	"certalator.cert_renew_answer",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_LAST
	}
};
const struct mdr_spec *msg_cert_renew_answer;

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
}
