#ifndef MDR_CERTALATOR_H
#define MDR_CERTALATOR_H

#include "mdr.h"
#include "mdrd.h"

/*
 * Certalator operation success
 */
#define MDR_DCV_CERTALATOR_OK \
    MDR_DCV(0x00000002, 0x0001, 0x0000)
extern const struct mdr_spec *msg_ok;

/*
 * Certalator errors with operation information
 */
#define MDR_DCV_CERTALATOR_ERROR \
    MDR_DCV(0x00000002, 0x0002, 0x0000)
extern const struct mdr_spec *msg_error;

/*
 * Creates a bootstrap entry for a client in the database.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP \
    MDR_DCV(0x00000002, 0x0003, 0x0000)
extern const struct mdr_spec *msg_bootstrap_setup;

/*
 * A client (agent) contacts its authority to initiate the bootstrap
 * process, providing a bootstrap one-time-key.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN \
    MDR_DCV(0x00000002, 0x0004, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialin;

/*
 * The authority issues a challenge by connecting
 * back to the agent who initiated a bootstrap.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK \
    MDR_DCV(0x00000002, 0x0005, 0x0000)
extern const struct mdr_spec *msg_bootstrap_dialback;

/*
 * In response to this the authority's DIALBACK, the client will send an
 * X509 REQ with the parameters received from the authority.
 * After receiving the REQ from the client, the authority replies with
 * a signed certificate which the client can install.
 */
#define MDR_DCV_CERTALATOR_BOOTSTRAP_ANSWER \
    MDR_DCV(0x00000002, 0x0006, 0x0000)
extern const struct mdr_spec *msg_bootstrap_answer;
#define MDR_DCV_CERTALATOR_SEND_CERT \
    MDR_DCV(0x00000002, 0x0007, 0x0000)
extern const struct mdr_spec *msg_send_cert;

#define MDR_DCV_CERTALATOR_CERT_RENEWAL_INQUIRY \
    MDR_DCV(0x00000002, 0x0008, 0x0000)
extern const struct mdr_spec *msg_cert_renewal_inquiry;
#define MDR_DCV_CERTALATOR_CERT_RENEWAL_REQUIRED \
    MDR_DCV(0x00000002, 0x0009, 0x0000)
extern const struct mdr_spec *msg_cert_renewal_required;
#define MDR_DCV_CERTALATOR_CERT_RENEW_DIALBACK \
    MDR_DCV(0x00000002, 0x000A, 0x0000)
extern const struct mdr_spec *msg_cert_renew_dialback;
#define MDR_DCV_CERTALATOR_CERT_RENEW_ANSWER \
    MDR_DCV(0x00000002, 0x000B, 0x0000)
extern const struct mdr_spec *msg_cert_renew_answer;

/* Built-ins */
extern const struct mdr_spec *msg_pack_beout;

void load_mdr_defs();
int  beout_ok(struct mdrd_besession *, const char *, uint32_t);
int  beout_error(struct mdrd_besession *, const char *, uint32_t,
         uint32_t, const char *);

#endif
