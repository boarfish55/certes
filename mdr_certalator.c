#include <err.h>
#include "mdr_certalator.h"

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

struct mdr_def msgdef_bootstrap_req = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_REQ,
	"certalator.bootstrap_req",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* Challenge answer */
		MDR_B,   /* X509_REQ */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_req;

struct mdr_def msgdef_bootstrap_req_failed = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_FAILED,
	"certalator.bootstrap_req_failed",
	{
		MDR_S,   /* Operation identifier */
		MDR_S,   /* Message */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_req_failed;

struct mdr_def msgdef_bootstrap_send_cert = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_SEND_CERT,
	"certalator.bootstrap_send_cert",
	{
		MDR_S,   /* Operation identifier */
		MDR_B,   /* X509 */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_send_cert;

/* Built-ins */
const struct mdr_spec *msg_pack_beresp;

void
load_mdr_defs()
{
	/*
	 * Built-in messages.
	 */
	if (mdr_register_builtin_specs() == MDR_FAIL)
		err(1, "mdr_register_builtin_specs");
	if ((msg_pack_beresp = mdr_registry_get(MDR_DCV_MDRD_BERESP)) == NULL)
		err(1, "mdr_registry_get");

	/*
	 * Agent/Authority messages.
	 */
	if ((msg_bootstrap_setup =
	    mdr_register_spec(&msgdef_bootstrap_setup)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_dialin =
	    mdr_register_spec(&msgdef_bootstrap_dialin)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_dialback =
	    mdr_register_spec(&msgdef_bootstrap_dialback)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_req =
	    mdr_register_spec(&msgdef_bootstrap_req)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_req_failed =
	    mdr_register_spec(&msgdef_bootstrap_req_failed)) == NULL)
		errx(1, "mdr_register_spec");
	if ((msg_bootstrap_send_cert =
	    mdr_register_spec(&msgdef_bootstrap_send_cert)) == NULL)
		errx(1, "mdr_register_spec");
}
