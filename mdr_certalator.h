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
 * The authority issues a challenge by connecting
 * back to the agent who initiated a bootstrap.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK \
    MDR_DCV(0x00000002, 0x0003, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialback;

/*
 * In response to this the authority's DIALBACK, the client will send an
 * X509 REQ with the parameters received from the authority.
 * After receiving the REQ from the client, the authority replies with
 * a signed certificate which the client can install.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_REQ \
    MDR_DCV(0x00000002, 0x0004, 0x0000)
extern const struct mdr_spec *msg_bootstrap_req;
#define MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_FAILED \
    MDR_DCV(0x00000002, 0x0005, 0x0000)
extern const struct mdr_spec *msg_bootstrap_req_failed;
#define MDR_DCV_CERTALATOR_BOOTSTRAP_SEND_CERT \
    MDR_DCV(0x00000002, 0x0006, 0x0000)
extern const struct mdr_spec *msg_bootstrap_send_cert;

/* Built-ins */
extern const struct mdr_spec *msg_pack_beresp;

void load_mdr_defs();

#endif
