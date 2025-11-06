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
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_setup;

struct mdr_def msgdef_bootstrap_dialin = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN,
	"certalator.bootstrap_dialin",
	{
		MDR_S,   /* Bootstrap identifier, used by the agent to
			    easily find the challenge later. */
		MDR_S,   /* Bootstrap key */
		MDR_LAST
	}
};
const struct mdr_spec *msg_bootstrap_dialin;

struct mdr_def msgdef_answer_challenge = {
	MDR_DCV_CERTALATOR_ANSWER_CHALLENGE,
	"certalator.answer_challenge",
	{
		MDR_B,   /* Challenge */
		MDR_LAST
	}
};
const struct mdr_spec *msg_answer_challenge;

struct mdr_def msgdef_coord_save_cert_challenge = {
	MDR_DCV_CERTALATOR_COORD_SAVE_CERT_CHALLENGE,
	"certalator.coord_save_cert_challenge",
	{
		MDR_S,   /* Request ID */
		MDR_B,   /* Challenge */
		MDR_LAST
	}
};
const struct mdr_spec *msg_coord_save_cert_challenge;

struct mdr_def msgdef_coord_get_cert_challenge = {
	MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE,
	"certalator.coord_get_cert_challenge",
	{
		MDR_S,   /* Request ID */
		MDR_LAST
	}
};
const struct mdr_spec *msg_coord_get_cert_challenge;

struct mdr_def msgdef_coord_get_cert_challenge_resp = {
	MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP,
	"certalator.coord_get_cert_challenge_resp",
	{
		MDR_B,   /* Challenge */
		MDR_LAST
	}
};
const struct mdr_spec *msg_coord_get_cert_challenge_resp;

struct mdr_def msgdef_coord_get_cert_challenge_notfound = {
	MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP_NOTFOUND,
	"certalator.coord_get_cert_challenge_notfound",
	{
		MDR_LAST
	}
};
const struct mdr_spec *msg_coord_get_cert_challenge_resp_notfound;

/* Built-ins */
const struct mdr_spec *msg_pack_beresp;
const struct mdr_spec *msg_pack_beresp_wmsg;

void
load_mdr_defs()
{
	if (mdr_register_builtin_specs() == MDR_FAIL)
		err(1, "mdr_register_builtin_specs");

	if ((msg_bootstrap_setup =
	    mdr_register_spec(&msgdef_bootstrap_setup)) == NULL)
		err(1, "mdr_register_spec");

	if ((msg_bootstrap_dialin =
	    mdr_register_spec(&msgdef_bootstrap_dialin)) == NULL)
		err(1, "mdr_register_spec");

	if ((msg_answer_challenge =
	    mdr_register_spec(&msgdef_answer_challenge)) == NULL)
		err(1, "mdr_register_spec");

	if ((msg_coord_save_cert_challenge =
	    mdr_register_spec(&msgdef_coord_save_cert_challenge)) == NULL)
		err(1, "mdr_register_spec");

	if ((msg_coord_get_cert_challenge =
	    mdr_register_spec(&msgdef_coord_get_cert_challenge)) == NULL)
		err(1, "mdr_register_spec");

	if ((msg_coord_get_cert_challenge_resp =
	    mdr_register_spec(&msgdef_coord_get_cert_challenge_resp)) == NULL)
		err(1, "mdr_register_spec");

	if ((msg_coord_get_cert_challenge_resp_notfound =
	    mdr_register_spec(&msgdef_coord_get_cert_challenge_notfound))
	    == NULL)
		err(1, "mdr_register_spec");

	if ((msg_pack_beresp = mdr_registry_get(MDR_DCV_MDRD_BERESP)) == NULL)
		err(1, "mdr_registry_get");

	if ((msg_pack_beresp_wmsg =
	    mdr_registry_get(MDR_DCV_MDRD_BERESP_WMSG)) == NULL)
		err(1, "mdr_registry_get");
}
