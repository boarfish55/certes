#ifndef MDR_CERTALATOR_H
#define MDR_CERTALATOR_H

#include "mdr.h"

/*
 * Creates a bootstrap entry for a client in the database.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP \
    MDR_DCV(0x00000002, 0x0001, 0x0000)
extern const struct mdr_spec *msg_bootstrap_setup;

/*
 * A client (agent) contacts its authority to initiate the bootstrap
 * process, providing a bootstrap one-time-key.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN \
    MDR_DCV(0x00000002, 0x0002, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialin;

/*
 * A client (agent) sends echoes back the challenge issued by the authority,
 * proving that it lives at the address it's supposed to.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_ANSWER_CHALLENGE \
    MDR_DCV(0x00000002, 0x0003, 0x0000)
extern const struct mdr_spec *msg_bootstrap_answer_challenge;

/*
 * The authority replies with the certificate parameters so the agent
 * can create its certificate request.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN_RESP \
    MDR_DCV(0x00000002, 0x0004, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialin_resp;
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN_RESP_FAILED \
    MDR_DCV(0x00000002, 0x0004, 0x0001)
extern const struct mdr_spec *msg_bootstrap_dialin_resp_failed;

/*
 * The authority dials back to the client that dialed in to validate
 * its CommonName and send the bootstrap parameters (validity, roles, SANs).
 * In response to this the client will send an X509 REQ with the parameters
 * received from the authority.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK \
    MDR_DCV(0x00000002, 0x0005, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialback;
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK_RESP \
    MDR_DCV(0x00000002, 0x0006, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialback_resp;

/*
 * In response to this the authority's DIALBACK, the client will send an
 * X509 REQ with the parameters received from the authority.
 * After receiving the REQ from the client, the authority replies with
 * a signed certificate which the client can install.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_REQ \
    MDR_DCV(0x00000002, 0x0007, 0x0000)
extern const struct mdr_spec *msg_bootstrap_req;
#define MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_RESP \
    MDR_DCV(0x00000002, 0x0008, 0x0000)
extern const struct mdr_spec *msg_bootstrap_req_resp;
#define MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_RESP_FAILED \
    MDR_DCV(0x00000002, 0x0008, 0x0001)
extern const struct mdr_spec *msg_bootstrap_req_resp_failed;

/*
 * Messages between certalator and its coorinator to share a challenge from
 * our authority internally.
 */
#define MDR_DCV_CERTALATOR_COORD_SAVE_CERT_CHALLENGE \
    MDR_DCV(0x00000002, 0x0009, 0x0000)
#define MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE \
    MDR_DCV(0x00000002, 0x000A, 0x0000)
#define MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP \
    MDR_DCV(0x00000002, 0x000B, 0x0000)
#define MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP_NOTFOUND \
    MDR_DCV(0x00000002, 0x000B, 0x0001)
extern const struct mdr_spec *msg_coord_save_cert_challenge;
extern const struct mdr_spec *msg_coord_get_cert_challenge;
extern const struct mdr_spec *msg_coord_get_cert_challenge_resp;
extern const struct mdr_spec *msg_coord_get_cert_challenge_resp_notfound;

/* Built-ins */
extern const struct mdr_spec *msg_pack_beresp;
extern const struct mdr_spec *msg_pack_beresp_wmsg;

void load_mdr_defs();

#endif
